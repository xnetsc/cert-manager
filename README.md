# cert-manager — free-cert automation on Function Compute

A small FC function that keeps free ACME certificates (Let's Encrypt
by default; ZeroSSL / Google Public CA selectable) renewed for a list
of domains and stores them in a **private** OSS bucket. It never
deploys certificates anywhere — the owner downloads them from the
bucket and deploys them himself.

## How it works

Everything lives in one private bucket:

| Object | Meaning |
|---|---|
| `domains.txt` | Registry: one domain per line (`*.example.com` for a wildcard, `#` comments). Edit it to enroll/remove a certificate. |
| `<domain>/fullchain.pem` | Full-chain certificate |
| `<domain>/privkey.pem` | Private key |
| `<domain>/cert.pem`, `chain.pem` | Leaf / intermediate |
| `state/acme-home.tar.gz` | acme.sh home (account keys, cert state), maintained by the function |

Wildcard domains use `_` in place of `*` for the folder name
(`_.example.com/`).

The function runs the same sweep on every invocation:

1. Read `domains.txt`.
2. Restore the acme.sh home from `state/`.
3. For each domain: first check that its DNS zone is hosted on
   Aliyun DNS in this account (the DNS-01 hook can only write TXT
   records there).
   - **Hosted**: issue or renew automatically via acme.sh; upload
     cert files whose content changed.
   - **Not hosted**: a two-phase manual flow. The sweep runs acme.sh
     in manual DNS mode, which stops with the TXT record to publish,
     and writes it to `pending/<domain>.txt` in the bucket. The
     owner sets that TXT at the external DNS provider, then
     **deletes the instruction file** — the deletion wakes the
     function, which resumes the order, verifies the TXT and
     completes issuance. If the TXT is wrong or missing, a fresh
     instruction file is written. The phase survives across runs in
     the persisted acme.sh state.
4. Save the acme.sh home back to `state/`.

Two triggers invoke it:

- **Timer trigger** — daily; catches ordinary expiries.
- **OSS triggers** — two of them. One fires when `domains.txt`
  itself changes (suffix filter, re-checked in code). The other
  fires when an object under `pending/` is **deleted** — the
  manual-flow "TXT is set" signal. The function's own writes
  (certs, state, new instruction files) match neither rule, so
  they never retrigger it.

## Cloud setup

1. **Bucket**: create a dedicated OSS bucket.
   - ACL: **private**. Enable **Block Public Access**. No exceptions:
     the bucket holds private keys.
   - The only access is the function's RAM role below.
2. **RAM role** for the function, with a custom policy scoped to:
   - `alidns:*` actions needed to add/remove TXT records (or
     `AliyunDNSFullAccess` if scoping is impractical),
   - `oss:GetObject` / `oss:PutObject` on this bucket only.
   No static AccessKeys are stored anywhere; the function reads its
   role credentials from the metadata endpoint
   (`CERTS_RAM_ROLE=<role name>`).
3. **Function**: custom container from this repo's image.
   - Port 9001, timeout 600s, **instance concurrency 1** (sweeps must
     not race each other over the shared state).
   - Environment: `CERTS_BUCKET`, `CERTS_OSS_ENDPOINT` (the bucket's
     endpoint), `CERTS_RAM_ROLE`; optional `CERTS_CA`
     (`letsencrypt` default, `zerossl`, `google`), `CERTS_DNS_SLEEP`.
4. **Triggers**: a daily timer trigger; an OSS trigger on the
   bucket for `ObjectCreated`/`ObjectUpdated` events **filtered to
   the `domains.txt` object**; and a second OSS trigger for
   `ObjectRemoved:DeleteObject` events **filtered to the `pending/`
   prefix**.

## Local development

```
python3 tests/test_sweep.py    # in-memory OSS + fake acme.sh
docker build -t cert-manager . # image: python:3.12-alpine + acme.sh
```

## Notes

- Free CAs only, by design. Let's Encrypt rate limits apply
  (50 certificates per registered domain per week — far above this
  tool's intended scale).
- Renewal happens when acme.sh judges the cert due (default: 30 days
  before expiry); unchanged cert files are not re-uploaded.
- A failing domain is logged and counted but never blocks the rest.
