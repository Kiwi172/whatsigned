# whatsigned

[![tests](https://github.com/Kiwi172/whatsigned/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiwi172/whatsigned/actions/workflows/ci.yml)

**Watch the TLS certificates your hosts actually serve — and notice when
they change.**

crt.sh watches certificate *transparency logs*: what was issued, with
delays and gaps. Nobody watches the live endpoint. But the certificate a
host is serving *right now* is the one your browser sees, and when it
changes it carries news: a new issuer, a new key, an expiry that moved,
and — most interestingly — **new or removed SAN names**. A cert that
grew an `api2.example.com` SAN is telling you about a host before any
scanner finds its DNS. A cert that stopped being trusted is telling you
something broke.

`whatsigned` probes a list of hosts, remembers each certificate in a
local JSON history, and diffs run against run:

```
   run 1                              run 2 (two weeks later)
   ┌──────────────────────┐           ┌──────────────────────────────┐
   │ app.example.com      │           │ app.example.com              │
   │   sha256:9d7e… LE R13│  history  │   CHANGED since last run:    │
   │   san: 12 names      │ ────────▶ │   certificate REPLACED       │
   │   BASELINE recorded  │           │   issuer: R13 -> E4          │
   └──────────────────────┘           │   SAN added: api2.example.com│
                                      │   expires in 71 days         │
                                      └──────────────────────────────┘
```

Everything happens on your machine. The history is a plain JSON file you
own. No services, no accounts, no dependencies — one file, Python
standard library only.

---

## Install

Any machine with Python 3.9 or newer:

```bash
curl -sO https://raw.githubusercontent.com/Kiwi172/whatsigned/main/whatsigned.py
chmod +x whatsigned.py
```

Or:

```bash
pipx install git+https://github.com/Kiwi172/whatsigned
```

## Use

Point it at hosts, or at the recon list you already have:

```bash
whatsigned example.com api.example.com
whatsigned --file in-scope-hosts.txt          # one host per line
whatsigned --file hosts.txt --warn-days 21    # your expiry policy
```

First run records a baseline; every later run answers the only question
that matters:

```
$ whatsigned bounty.cryptobox.com
bounty.cryptobox.com
  sha256:9d7e66d3ebf6…  YR2 / Let's Encrypt / US
  TLSv1.3  expires Dec 15 01:21:45 2026 GMT (60 days)  trusted
  san: 1 names  unchanged
```

A replacement looks like this (proven by the test suite against local
TLS servers with openssl-generated certs):

```
app.example.com
  CHANGED since last run:
    certificate REPLACED (fingerprint changed)
    issuer: R11 / Let's Encrypt -> E5 / Let's Encrypt
    expires: Sep 30 ... -> Dec 30 ...
    SAN added: api2.example.com   <- new name, worth a look
    SAN removed: old.example.com
```

Other flags:

```bash
whatsigned --history              # print the stored timeline (JSON)
whatsigned --json                 # machine-readable results
whatsigned app.example.com --resolve 10.0.0.7   # pin to an IP (staging box)
whatsigned internal.corp --cafile internal-ca.pem
```

Expired and self-signed certificates are **recorded, not fatal**: the
verifier retries unverified and marks the host `NOT TRUSTED: <reason>`.
That is exactly the case a plain "connect and check" script dies on.

## What it detects

| change | how |
|---|---|
| certificate replaced | SHA-256 of the DER differs from the last observation |
| issuer changed | issuer chain string differs (e.g. LE R11 → E5, or a switch to an internal CA) |
| SAN set changed | added/removed DNS names, listed individually |
| expiry moved / approaching | `notAfter` delta, `--warn-days` threshold |
| trust broke | a previously verified cert now fails verification |
| protocol downgraded | TLS version differs |

Identical repeats update `last_seen` instead of growing the history; the
file stays small (last 50 distinct observations per host).

## Non-goals

- **Not a CT-log client.** For "who has ever issued certs for this
  domain", use crt.sh. whatsigned watches what is served *now* — which
  also covers internal CAs and self-signed certs that never appear in
  any log.
- **Not a scanner.** It probes exactly the hosts you list. Cron it
  daily if you want continuous watching.
- **Leaf certificate only.** It does not walk the full chain.

## Tests

```bash
python3 -m pytest tests/      # or: python3 tests/test_whatsigned.py
```

The tests generate certificates with `openssl` (SAN sets, short
validity), serve them from local TLS servers, and prove the full
lifecycle: baseline → unchanged → replaced with exact SAN deltas,
untrusted recorded not fatal, expiry warnings.

## License

MIT
