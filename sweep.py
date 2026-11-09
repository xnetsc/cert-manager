#!/usr/bin/env python3
"""Cert manager sweep: read the domain registry from OSS, issue or
renew each domain's certificate with acme.sh (free ACME CAs, DNS-01),
and store cert + key back in the same bucket, one folder per domain.

Everything persistent lives in the bucket:
  domains.txt            registry, one domain per line (# = comment)
  <domain>/fullchain.pem, privkey.pem, cert.pem, chain.pem
  state/acme-home.tar.gz the acme.sh home (account keys + cert state)

Credentials come from the environment (Ali_Key/Ali_Secret for the
Aliyun DNS API; OSS_ACCESS_KEY_ID/OSS_ACCESS_KEY_SECRET/OSS_TOKEN)
or, when CERTS_RAM_ROLE is set, from the FC metadata endpoint.
"""

import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import urllib.error
import urllib.parse
import base64
import hmac
import datetime
import re

REGISTRY_KEY = os.environ.get("CERTS_REGISTRY_KEY", "domains.txt")
STATE_KEY = "state/acme-home.tar.gz"
RENEW_BEFORE_DAYS = 30
DNS_SLEEP = int(os.environ.get("CERTS_DNS_SLEEP", "20"))
DEFAULT_SERVER = os.environ.get("CERTS_CA", "letsencrypt")


# ---------------------------------------------------------------- OSS
class OssError(Exception):
    pass


class Oss:
    """Minimal OSS client (V1 signatures, stdlib only). Works with a
    plain AK or STS credentials (security token header)."""

    def __init__(self, bucket, endpoint, key_id, key_secret, token=""):
        self.bucket = bucket
        self.endpoint = endpoint.rstrip("/")
        self.key_id = key_id
        self.key_secret = key_secret
        self.token = token

    def _request(self, method, key, data=None, content_type=""):
        url = f"{self.endpoint}/{key}"
        date = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT")
        headers = {"Date": date}
        if self.token:
            headers["x-oss-security-token"] = self.token
        if content_type:
            headers["Content-Type"] = content_type
        canon_res = f"/{self.bucket}/{key}"
        sts = f"{method}\n\n{content_type}\n{date}\n"
        if self.token:
            sts += f"x-oss-security-token:{self.token}\n"
        sts += canon_res
        sig = base64.b64encode(hmac.new(
            self.key_secret.encode(), sts.encode(),
            hashlib.sha1).digest()).decode()
        headers["Authorization"] = f"OSS {self.key_id}:{sig}"
        req = urllib.request.Request(url, data=data, method=method,
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404 and method == "GET":
                return 404, b""
            raise OssError(f"OSS {method} {key}: HTTP {e.code} "
                           f"{e.read()[:200]!r}")

    def get(self, key):
        status, body = self._request("GET", key)
        return None if status == 404 else body

    def put(self, key, data, content_type="application/octet-stream"):
        self._request("PUT", key, data=data, content_type=content_type)


def metadata_credentials(role):
    url = ("http://100.100.100.200/latest/meta-data/ram/"
           f"security-credentials/{role}")
    with urllib.request.urlopen(url, timeout=5) as resp:
        import json
        d = json.loads(resp.read())
    return d["AccessKeyId"], d["AccessKeySecret"], d["SecurityToken"]


def get_credentials():
    """(key_id, key_secret, token) for this run: STS credentials of
    the function's RAM role when CERTS_RAM_ROLE is set, else the
    static env keys (local development)."""
    role = os.environ.get("CERTS_RAM_ROLE", "")
    if role:
        return metadata_credentials(role)
    return (os.environ["OSS_ACCESS_KEY_ID"],
            os.environ["OSS_ACCESS_KEY_SECRET"],
            os.environ.get("OSS_TOKEN", ""))


def build_oss():
    kid, ksec, token = get_credentials()
    bucket = os.environ["CERTS_BUCKET"]
    endpoint = os.environ["CERTS_OSS_ENDPOINT"]
    return Oss(bucket, endpoint, kid, ksec, token)


# ------------------------------------------------- DNS hosting check
class ZoneCheckUnavailable(Exception):
    pass


def _ali_percent(s):
    out = urllib.parse.quote(str(s), safe="")
    return out.replace("+", "%20").replace("*", "%2A").replace("%7E", "~")


def _alidns_describe(zone, creds):
    """One DescribeDomainRecords call. Returns the parsed JSON on an
    API-level answer; raises ZoneCheckUnavailable on transport or
    auth-level failures (where 'not hosted' cannot be concluded)."""
    import json
    import uuid
    kid, ksec, token = creds
    params = {
        "AccessKeyId": kid, "Action": "DescribeDomainRecords",
        "DomainName": zone, "Format": "json", "PageSize": "1",
        "SignatureMethod": "HMAC-SHA1",
        "SignatureNonce": uuid.uuid4().hex,
        "SignatureVersion": "1.0",
        "Timestamp": datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Version": "2015-01-09",
    }
    if token:
        params["SecurityToken"] = token
    canonical = "&".join(
        f"{_ali_percent(k)}={_ali_percent(params[k])}"
        for k in sorted(params))
    sts = "GET&%2F&" + _ali_percent(canonical)
    sig = base64.b64encode(hmac.new(
        (ksec + "&").encode(), sts.encode(), hashlib.sha1).digest()
    ).decode()
    url = ("https://alidns.aliyuncs.com/?" + canonical +
           "&Signature=" + _ali_percent(sig))
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            raise ZoneCheckUnavailable(f"HTTP {e.code}")
    except Exception as e:
        raise ZoneCheckUnavailable(str(e))


def find_aliyun_zone(domain, creds):
    """The Aliyun-DNS zone that would serve this domain, or None when
    the zone is not hosted in this account. Walks up from the full
    name (sans '*.'), asking the DNS API about each candidate."""
    name = domain[2:] if domain.startswith("*.") else domain
    labels = name.split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand.count(".") < 1:
            break
        d = _alidns_describe(cand, creds)
        if "DomainRecords" in d:
            return cand
        code = d.get("Code", "")
        if "Forbidden" in code or "InvalidAccessKeyId" in code \
                or "Signature" in code:
            raise ZoneCheckUnavailable(f"DNS API auth error: {code}")
        # Any other API answer means: not this zone; walk up.
    return None


def default_zone_checker():
    creds = get_credentials()
    return lambda domain: find_aliyun_zone(domain, creds)


# ------------------------------------------------------------ registry
def parse_registry(text):
    domains = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.append(line.split()[0])
    return domains


def folder_for(domain):
    # '*' is legal in OSS keys but hostile everywhere else.
    return domain.replace("*", "_")


# -------------------------------------------------------------- acme.sh
def acme_home_state(oss, workdir):
    blob = oss.get(STATE_KEY)
    home = os.path.join(workdir, "acme-home")
    os.makedirs(home, exist_ok=True)
    if blob:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            tar.extractall(home)
    if not os.path.exists(os.path.join(home, "acme.sh")):
        # First run (or a wiped state): seed the home from the tree
        # baked into the image.
        import shutil
        src = os.environ.get("ACME_SRC", "/opt/acme.sh")
        shutil.copytree(src, home, dirs_exist_ok=True)
    return home


def save_acme_home_state(oss, home):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(home, arcname=".")
    oss.put(STATE_KEY, buf.getvalue())


def cert_days_left(pem_path):
    out = subprocess.run(
        ["openssl", "x509", "-noout", "-enddate", "-in", pem_path],
        capture_output=True, text=True)
    if out.returncode != 0:
        return None
    m = re.search(r"notAfter=(.*)", out.stdout)
    if not m:
        return None
    dt = datetime.datetime.strptime(
        m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
    return (dt - datetime.datetime.utcnow()).days


def sha256(b):
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------ triggers
def oss_event_keys(payload):
    """Object keys from an FC OSS-trigger event (parsed JSON), or
    None when the payload is not an OSS event."""
    try:
        events = payload["events"]
        keys = []
        for e in events:
            key = e["oss"]["object"]["key"]
            from urllib.parse import unquote_plus
            keys.append(unquote_plus(key))
        return keys
    except (TypeError, KeyError, AttributeError):
        return None


def should_run(payload):
    """Decide whether an invocation runs the sweep. Timer triggers
    and manual invokes always run. OSS events run ONLY when the
    registry file itself changed - the sweep's own writes to the
    bucket (certs, state) must never retrigger it."""
    if not payload:
        return True
    keys = oss_event_keys(payload)
    if keys is None:
        return True
    return REGISTRY_KEY in keys


def manage_domain(oss, home, domain, runner=subprocess.run):
    """Issue/renew one domain; upload to its folder when changed.
    Returns a one-line status string."""
    folder = folder_for(domain)
    acme = os.path.join(home, "acme.sh")
    env = dict(os.environ)
    env["HOME"] = home
    hook = os.environ.get("CERTS_DNS_HOOK", "dns_fcrole")
    cmd = [acme, "--home", home, "--issue", "--dns", hook,
           "-d", domain, "--server", DEFAULT_SERVER,
           "--dnssleep", str(DNS_SLEEP), "--keylength", "ec-256"]
    r = runner(cmd, capture_output=True, text=True, env=env)
    # acme.sh exits 0 on issue/renew, 2 when not due yet (with the
    # default config a fresh --issue on an existing fresh cert is a
    # no-op success); either way, judge by the cert on disk.
    # acme.sh keeps certs in <home>/<domain>[_ecc]/ with the domain
    # spelled as given ('*' included for wildcards).
    import glob
    cert_dir = None
    for cand in (os.path.join(home, domain),
                 os.path.join(home, domain + "_ecc"),
                 os.path.join(home, folder),
                 os.path.join(home, folder + "_ecc")):
        if os.path.isdir(cand):
            cert_dir = cand
            break
    full = os.path.join(cert_dir, "fullchain.cer") if cert_dir else ""
    if not cert_dir or not os.path.exists(full):
        tail = (r.stdout + r.stderr).strip().splitlines()[-3:]
        return f"FAIL {domain}: no cert produced: {' | '.join(tail)}"
    days = cert_days_left(full)
    keys = glob.glob(os.path.join(cert_dir, "*.key"))
    leaf = [p for p in glob.glob(os.path.join(cert_dir, "*.cer"))
            if os.path.basename(p) not in ("ca.cer", "fullchain.cer")]
    files = {"fullchain.pem": full,
             "privkey.pem": keys[0] if keys else "",
             "cert.pem": leaf[0] if leaf else "",
             "chain.pem": os.path.join(cert_dir, "ca.cer")}
    changed = []
    for name, path in files.items():
        if not os.path.exists(path):
            continue
        data = open(path, "rb").read()
        remote = oss.get(f"{folder}/{name}")
        if remote is None or sha256(remote) != sha256(data):
            oss.put(f"{folder}/{name}", data)
            changed.append(name)
    state = "updated " + ",".join(changed) if changed else "unchanged"
    return f"OK {domain}: {state} (expires in {days}d)"


def sweep(oss, runner=subprocess.run, log=print, zone_checker=None):
    raw = oss.get(REGISTRY_KEY)
    if raw is None:
        log(f"registry {REGISTRY_KEY} not found; nothing to do")
        return 0
    domains = parse_registry(raw.decode("utf-8"))
    log(f"registry: {len(domains)} domain(s)")
    if zone_checker is None:
        zone_checker = default_zone_checker()
    failures = 0
    with tempfile.TemporaryDirectory() as workdir:
        home = acme_home_state(oss, workdir)
        for domain in domains:
            # Special handling (user, 2026-11-09): the DNS-01 hook can
            # only serve zones hosted on Aliyun DNS in this account.
            # Check first; a foreign zone is skipped with the reason,
            # not failed opaquely inside acme.sh.
            try:
                zone = zone_checker(domain)
            except ZoneCheckUnavailable as e:
                log(f"WARN {domain}: DNS hosting check unavailable "
                    f"({e}); proceeding")
                zone = "?"
            if zone is None:
                log(f"SKIP {domain}: DNS is not hosted on Aliyun; "
                    f"the DNS-01 hook cannot set TXT records for it")
                continue
            try:
                line = manage_domain(oss, home, domain, runner=runner)
                log(line)
                if line.startswith("FAIL"):
                    failures += 1
            except Exception as e:  # one bad domain must not stop rest
                failures += 1
                log(f"FAIL {domain}: {e}")
        save_acme_home_state(oss, home)
    return failures


def main():
    oss = build_oss()
    sys.exit(1 if sweep(oss) else 0)


if __name__ == "__main__":
    main()
