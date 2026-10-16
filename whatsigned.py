#!/usr/bin/env python3
"""whatsigned -- watch the TLS certificates your hosts actually serve.

crt.sh watches certificate *transparency logs* -- what was issued, with
deliberate delays and gaps. whatsigned watches the live endpoint: the
certificate a host is serving right now, remembered in a local history.
Run it on a list of hosts and re-run it whenever: it tells you when a
certificate was *replaced* (new issuer, new key, new validity window),
which SAN names appeared or disappeared (a new SAN is a new host, often
before any scanner finds the DNS), and which certificates are about to
expire. Expired and self-signed certificates are recorded, not fatal --
they are exactly what you wanted to know.

Stdlib-only. History is a plain JSON file you own. No services.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"
MAX_OBS = 50


# ---------------------------------------------------------------------------
# probing
# ---------------------------------------------------------------------------

def probe(host, port, timeout, cafile=None, addr=None):
    """Return an observation dict for the cert served at host:port.

    addr overrides the connect address (SNI/verification still use host)
    -- used by the tests to serve fake certs from localhost.
    """
    target = addr or host

    def connect(verify):
        ctx = ssl.create_default_context()
        if cafile:
            ctx.load_verify_locations(cafile)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((target, port), timeout)
        try:
            sock = ctx.wrap_socket(raw, server_hostname=host)
            der = sock.getpeercert(binary_form=True)
            cert = sock.getpeercert()
            version = sock.version()
            cipher = sock.cipher()
            return der, cert, version, cipher, None
        finally:
            try:
                raw.close()
            except OSError:
                pass

    verify_error = None
    try:
        der, cert, version, cipher, _ = connect(verify=True)
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message if hasattr(e, "verify_message") \
            else str(e)
        der, cert, version, cipher, _ = connect(verify=False)
    if der is None or cert is None:
        raise RuntimeError("no certificate")

    issuer = _flat(cert.get("issuer", ()))
    subject = _flat(cert.get("subject", ()))
    sans = sorted({v for k, v in cert.get("subjectAltName", ()) if k == "DNS"})
    return {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fingerprint": "sha256:" + hashlib.sha256(der).hexdigest(),
        "issuer": issuer,
        "subject": subject,
        "not_before": cert.get("notBefore", ""),
        "not_after": cert.get("notAfter", ""),
        "san_dns": sans,
        "tls": version,
        "cipher": cipher[0] if cipher else "",
        "verified": verify_error is None,
        "verify_error": verify_error or "",
    }


def _flat(tup):
    parts = []
    for rdn in tup:
        for attr, val in rdn:
            if val:
                parts.append(val)
    return " / ".join(reversed(parts)) if parts else "?"


def days_left(not_after):
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except (ValueError, TypeError):
        try:
            dt = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
        except (ValueError, TypeError):
            return None
    return (dt.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days


# ---------------------------------------------------------------------------
# state + diffing
# ---------------------------------------------------------------------------

def load_state(path):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"tool": "whatsigned", "version": VERSION, "hosts": {}}


def diff(prev, cur):
    """Changes between two observations; empty list means unchanged."""
    out = []
    if prev["fingerprint"] != cur["fingerprint"]:
        out.append(("replaced", "certificate REPLACED (fingerprint changed)"))
        if prev.get("issuer") != cur.get("issuer"):
            out.append(("issuer", f"issuer: {prev.get('issuer')} -> {cur.get('issuer')}"))
        if prev.get("not_after") != cur.get("not_after"):
            out.append(("validity", f"expires: {prev.get('not_after')} -> {cur.get('not_after')}"))
        a, b = set(prev.get("san_dns", [])), set(cur.get("san_dns", []))
        for s in sorted(b - a):
            out.append(("san+", f"SAN added: {s}   <- new name, worth a look"))
        for s in sorted(a - b):
            out.append(("san-", f"SAN removed: {s}"))
    if bool(prev.get("verified")) and not bool(cur.get("verified")):
        out.append(("verify", f"no longer trusted: {cur.get('verify_error')}"))
    if prev.get("tls") != cur.get("tls"):
        out.append(("tls", f"protocol: {prev.get('tls')} -> {cur.get('tls')}"))
    return out


def record(state, host, obs):
    entry = state["hosts"].setdefault(host, {"observations": []})
    obslist = entry["observations"]
    if obslist and obslist[-1]["fingerprint"] == obs["fingerprint"] \
            and obslist[-1]["san_dns"] == obs["san_dns"]:
        obslist[-1]["last_seen"] = obs["ts"]
        return "unchanged"
    obslist.append(obs)
    entry["observations"] = obslist[-MAX_OBS:]
    return "changed" if len(obslist) > 1 else "baseline"


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(
        prog="whatsigned",
        description="Watch the TLS certificates hosts actually serve: "
                    "replacements, issuer/SAN changes, expiry. Local "
                    "history, stdlib-only, no services.")
    ap.add_argument("hosts", nargs="*", metavar="HOST",
                    help="hostnames to probe (or use --file)")
    ap.add_argument("--file", metavar="PATH",
                    help="read one host per line (recon lists work)")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--state", metavar="PATH", default="whatsigned.json",
                    help="history file (default: whatsigned.json)")
    ap.add_argument("--warn-days", type=int, default=14,
                    help="warn when a cert expires within N days (default 14)")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--cafile", metavar="PATH",
                    help="extra CA bundle to trust (internal CAs)")
    ap.add_argument("--resolve", metavar="ADDR",
                    help="connect to ADDR while verifying/probing HOST "
                         "(pinning, or testing a staging box)")
    ap.add_argument("--history", action="store_true",
                    help="print the stored timeline instead of probing")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--version", action="version", version=f"whatsigned {VERSION}")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    state_path = Path(args.state)
    state = load_state(state_path)

    hosts = list(args.hosts)
    if args.file:
        hosts += [l.strip() for l in Path(args.file).read_text().splitlines()
                  if l.strip() and not l.startswith("#")]
    hosts = [re.sub(r"^https?://", "", h).split("/")[0].split(":")[0]
             for h in hosts]
    if args.history:
        print(json.dumps(state["hosts"], indent=1))
        return 0
    if not hosts:
        print("whatsigned: no hosts given", file=sys.stderr)
        return 2

    results = []
    for host in hosts:
        try:
            obs = probe(host, args.port, args.timeout, args.cafile,
                        addr=args.resolve)
        except (OSError, ssl.SSLError, RuntimeError) as e:
            print(f"{host}: {c('33', 'UNREACHABLE')} ({e})")
            results.append({"host": host, "status": "unreachable",
                            "error": str(e)})
            continue

        status = record(state, host, obs)
        prevs = state["hosts"][host]["observations"]
        prev = prevs[-2] if len(prevs) > 1 and status == "changed" else None
        d = diff(prev, obs) if prev else []
        dl = days_left(obs["not_after"])

        print(host)
        fp = obs["fingerprint"][:19] + "…"
        issuer = obs["issuer"][:60]
        exp = f"expires {obs['not_after']}"
        if dl is not None:
            exp += f" ({dl} days)"
        trust = c("32", "trusted") if obs["verified"] else \
            c("31", "NOT TRUSTED: " + obs["verify_error"][:50])
        print(f"  {fp}  {issuer}")
        print(f"  {obs['tls']}  {exp}  {trust}")
        san_note = f"  san: {len(obs['san_dns'])} names"
        if status == "baseline":
            print(san_note + "  " + c("36", "BASELINE") + " recorded")
        elif status == "unchanged":
            print(san_note + "  " + c("32", "unchanged"))
        else:
            print(f"  " + c("31", "CHANGED since last run:"))
            for kind, line in d:
                print(c("90", f"    {line}"))
        if dl is not None and dl < 0:
            print("  " + c("31", "EXPIRED"))
        elif dl is not None and dl <= args.warn_days:
            print("  " + c("33", f"WARNING: expires in {dl} days"))
        print()
        results.append({"host": host, "status": status, "observation": obs,
                        "diff": [line for _, line in d],
                        "days_left": dl})

    state_path.write_text(json.dumps(state, indent=1))
    if args.as_json:
        print(json.dumps({"tool": "whatsigned", "version": VERSION,
                          "results": results}, indent=2))
    changed = sum(1 for r in results if r["status"] == "changed")
    print(f"{len(hosts)} host(s) probed · {changed} certificate change(s) "
          f"detected · history: {state_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
