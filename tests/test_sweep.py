#!/usr/bin/env python3
"""Sweep tests: in-memory OSS double + a fake acme.sh runner that
materializes a real (self-signed) cert in the acme.sh layout, so the
whole registry/state/upload flow is exercised without network."""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sweep as S

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name}")


class FakeOss:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def put(self, key, data, content_type=""):
        self.store[key] = bytes(data)


_cert_cache = {}


def make_cert(domain):
    if domain in _cert_cache:
        return _cert_cache[domain]
    d = tempfile.mkdtemp()
    key = os.path.join(d, "k.pem")
    cer = os.path.join(d, "c.pem")
    subj = f"/CN={domain.replace('*', 'x')}"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", key, "-out", cer, "-days", "90",
                    "-nodes", "-subj", subj],
                   capture_output=True, check=True)
    _cert_cache[domain] = (open(cer, "rb").read(), open(key, "rb").read())
    return _cert_cache[domain]


def fake_runner_factory(fail_domains=()):
    def runner(cmd, capture_output, text, env):
        # cmd: [acme.sh, --home, HOME, --issue, --dns, dns_ali, -d, DOM, ...]
        home = cmd[2]
        domain = cmd[cmd.index("-d") + 1]
        if domain in fail_domains:
            return subprocess.CompletedProcess(cmd, 1, "", "dns error")
        cer, key = make_cert(domain)
        cdir = os.path.join(home, domain + "_ecc")
        os.makedirs(cdir, exist_ok=True)
        with open(os.path.join(cdir, "fullchain.cer"), "wb") as f:
            f.write(cer)
        with open(os.path.join(cdir, domain + ".cer"), "wb") as f:
            f.write(cer)
        with open(os.path.join(cdir, "ca.cer"), "wb") as f:
            f.write(cer)
        with open(os.path.join(cdir, domain + ".key"), "wb") as f:
            f.write(key)
        return subprocess.CompletedProcess(cmd, 0, "issued", "")
    return runner


def seed_home(oss):
    # Pretend a previous run baked acme.sh into the state: the sweep
    # seeds from ACME_SRC when absent; point it at a stub dir.
    src = tempfile.mkdtemp()
    with open(os.path.join(src, "acme.sh"), "w") as f:
        f.write("#!/bin/sh\n")
    os.environ["ACME_SRC"] = src


def main():
    seed_home(None)

    # Registry parsing
    check("registry: comments/blanks skipped",
          S.parse_registry("# hi\n\nexample.com\n  *.a.com  \n") ==
          ["example.com", "*.a.com"])
    check("folder: wildcard sanitized",
          S.folder_for("*.example.com") == "_.example.com")

    # Trigger classification
    check("trigger: timer/manual runs", S.should_run(None) and
          S.should_run({}))
    oss_ev = {"events": [{"oss": {"object": {"key": "domains.txt"}}}]}
    check("trigger: registry change runs", S.should_run(oss_ev))
    oss_ev2 = {"events": [{"oss": {"object": {
        "key": "example.com/fullchain.pem"}}}]}
    check("trigger: cert write ignored", not S.should_run(oss_ev2))
    oss_ev3 = {"events": [{"oss": {"object": {
        "key": "state/acme-home.tar.gz"}}}]}
    check("trigger: state write ignored", not S.should_run(oss_ev3))
    pend_del = {"events": [{"eventName": "ObjectRemoved:DeleteObject",
                            "oss": {"object": {
                                "key": "pending/foreign.example.org.txt"}}}]}
    check("trigger: pending instruction deletion runs",
          S.should_run(pend_del))
    pend_put = {"events": [{"eventName": "ObjectCreated:PutObject",
                            "oss": {"object": {
                                "key": "pending/foreign.example.org.txt"}}}]}
    check("trigger: pending instruction creation ignored",
          not S.should_run(pend_put))

    # Full sweep: two domains, one failing
    oss = FakeOss()
    oss.put(S.REGISTRY_KEY,
            b"# certs\nexample.com\n*.example.org\nbad.example.net\n")
    logs = []
    failures = S.sweep(oss, runner=fake_runner_factory(
        fail_domains=("bad.example.net",)), log=logs.append,
        zone_checker=lambda d: "zone")
    check("sweep: one failure isolated", failures == 1)
    check("sweep: cert uploaded",
          "example.com/fullchain.pem" in oss.store and
          "example.com/privkey.pem" in oss.store)
    check("sweep: wildcard under sanitized folder",
          "_.example.org/fullchain.pem" in oss.store)
    check("sweep: state saved", S.STATE_KEY in oss.store)
    check("sweep: failed domain has no folder",
          not any(k.startswith("bad.example.net/") for k in oss.store))

    # Second sweep with the same certs: no re-upload (unchanged)
    class CountingOss(FakeOss):
        def __init__(self, other):
            self.store = other.store
            self.puts = []

        def put(self, key, data, content_type=""):
            self.puts.append(key)
            super().put(key, data)

    oss2 = CountingOss(oss)
    logs2 = []
    S.sweep(oss2, runner=fake_runner_factory(
        fail_domains=("bad.example.net",)), log=logs2.append,
        zone_checker=lambda d: "zone")
    cert_puts = [k for k in oss2.puts if not k.startswith("state/")]
    check("sweep: fresh cert not re-uploaded", cert_puts == [])
    check("sweep: status says unchanged",
          any("unchanged" in line for line in logs2))

    # Missing registry: quiet no-op
    oss3 = FakeOss()
    check("sweep: missing registry is a no-op", S.sweep(oss3) == 0)

    # DNS hosting pre-check + manual flow for foreign zones, over
    # three sweeps sharing one bucket (state must carry the phase):
    # 1) foreign zone -> instruction file with the TXT, no cert yet
    # 2) file still there -> WAIT, no completion attempt
    # 3) file deleted + TXT set -> resume completes, cert uploaded
    manual_ready = set()

    def manual_runner(cmd, capture_output, text, env):
        home = cmd[2]
        domain = cmd[cmd.index("-d") + 1]
        if "--renew" in cmd:
            if domain in manual_ready:
                cer, key = make_cert(domain)
                cdir = os.path.join(home, domain + "_ecc")
                os.makedirs(cdir, exist_ok=True)
                for name, data in (("fullchain.cer", cer),
                                   (domain + ".cer", cer),
                                   ("ca.cer", cer),
                                   (domain + ".key", key)):
                    with open(os.path.join(cdir, name), "wb") as fh:
                        fh.write(data)
                return subprocess.CompletedProcess(cmd, 0, "renewed", "")
            return subprocess.CompletedProcess(cmd, 1, "", "txt not found")
        # --issue in manual mode (bare --dns): stop with the TXT.
        out = (f"Domain: '_acme-challenge.{domain}'\n"
               f"TXT value: 'txt-{domain}'\n")
        return subprocess.CompletedProcess(cmd, 3, out, "")

    oss4 = FakeOss()
    oss4.put(S.REGISTRY_KEY, b"foreign.example.org\n")
    logs4 = []
    failures4 = S.sweep(oss4, runner=manual_runner, log=logs4.append,
                         zone_checker=lambda d: None)
    instr_key = "pending/foreign.example.org.txt"
    check("manual: phase 1 not a failure", failures4 == 0)
    check("manual: instruction file written with the TXT",
          instr_key in oss4.store and
          b"txt-foreign.example.org" in oss4.store[instr_key])
    check("manual: MANUAL line logged",
          any(line.startswith("MANUAL foreign.example.org")
              for line in logs4))
    check("manual: no cert yet",
          "foreign.example.org/fullchain.pem" not in oss4.store)

    logs5 = []
    S.sweep(oss4, runner=manual_runner, log=logs5.append,
            zone_checker=lambda d: None)
    check("manual: still waiting while instruction file exists",
          any(line.startswith("WAIT foreign.example.org")
              for line in logs5))

    # The user sets the TXT and deletes the instruction file.
    del oss4.store[instr_key]
    manual_ready.add("foreign.example.org")
    logs6 = []
    S.sweep(oss4, runner=manual_runner, log=logs6.append,
            zone_checker=lambda d: None)
    check("manual: resume after deletion issues the cert",
          "foreign.example.org/fullchain.pem" in oss4.store and
          any(line.startswith("OK foreign.example.org")
              for line in logs6))

    # Zone walking: subdomain resolves to its parent zone; a missing
    # zone walks up and gives up cleanly.
    answers = {
        "sub.example.com": {"Code": "InvalidDomainName.NoExist"},
        "example.com": {"DomainRecords": {"Record": []}},
        "nowhere.zz": {"Code": "InvalidDomainName.NoExist"},
    }
    orig = S._alidns_describe
    S._alidns_describe = lambda zone, creds: answers.get(
        zone, {"Code": "InvalidDomainName.NoExist"})
    try:
        check("zone: walks up to the hosted parent",
              S.find_aliyun_zone("sub.example.com", ("k", "s", "")) ==
              "example.com")
        check("zone: wildcard checks its base zone",
              S.find_aliyun_zone("*.example.com", ("k", "s", "")) ==
              "example.com")
        check("zone: foreign zone returns None",
              S.find_aliyun_zone("nowhere.zz", ("k", "s", "")) is None)
    finally:
        S._alidns_describe = orig

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
