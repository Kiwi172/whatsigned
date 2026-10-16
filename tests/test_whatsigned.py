"""Tests for whatsigned. Run with: python3 -m pytest tests/ (or python3 tests/test_whatsigned.py)

Local TLS servers serve openssl-generated self-signed certs, so
replacement / SAN-delta / trust-failure behaviour is proven without
touching the internet.
"""
from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

TOOL = str(Path(__file__).resolve().parent.parent / "whatsigned.py")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import whatsigned as wsign  # noqa: E402


def require_openssl():
    if shutil.which("openssl") is None:
        print("SKIP: openssl not installed")
        sys.exit(0)


def make_cert(tmp: Path, name: str, sans: str, days=30):
    pem, key = tmp / f"{name}.pem", tmp / f"{name}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(key), "-out", str(pem), "-days", str(days),
         "-nodes", "-subj", f"/CN=a.test/O=Test {name}",
         "-addext", f"subjectAltName={sans}"],
        check=True, capture_output=True)
    return pem, key


def serve_tls(pem, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(pem), str(key))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                raw, _ = srv.accept()
            except OSError:
                return
            try:
                tls = ctx.wrap_socket(raw, server_side=True)
                tls.close()
            except OSError:
                try:
                    raw.close()
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()
    return port, srv


def run(*argv):
    return subprocess.run([sys.executable, TOOL, *argv],
                          capture_output=True, text=True)


# ---------------------------------------------------------------------------

def test_probe_reads_live_cert(tmp_path):
    require_openssl()
    pem, key = make_cert(tmp_path, "A", "DNS:a.test,DNS:foo.test")
    port, srv = serve_tls(pem, key)
    obs = wsign.probe("a.test", port, 5, cafile=str(pem), addr="127.0.0.1")
    assert obs["verified"] and obs["tls"].startswith("TLS")
    assert obs["fingerprint"].startswith("sha256:")
    assert obs["san_dns"] == ["a.test", "foo.test"]
    assert "Test A" in obs["issuer"]
    srv.close()


def test_baseline_then_unchanged(tmp_path):
    require_openssl()
    pem, key = make_cert(tmp_path, "A", "DNS:a.test")
    port, srv = serve_tls(pem, key)
    state = tmp_path / "s.json"
    common = ["a.test", "--port", str(port), "--cafile", str(pem),
              "--resolve", "127.0.0.1", "--state", str(state)]
    r1 = run(*common)
    assert "BASELINE" in r1.stdout
    r2 = run(*common)
    assert "unchanged" in r2.stdout
    d = json.loads(state.read_text())
    assert len(d["hosts"]["a.test"]["observations"]) == 1
    srv.close()


def test_replacement_detected_with_san_delta(tmp_path):
    require_openssl()
    pemA, keyA = make_cert(tmp_path, "A", "DNS:a.test,DNS:foo.test")
    pemB, keyB = make_cert(tmp_path, "B", "DNS:a.test,DNS:bar.test")
    portA, srvA = serve_tls(pemA, keyA)
    state = tmp_path / "s.json"
    run("a.test", "--port", str(portA), "--cafile", str(pemA),
        "--resolve", "127.0.0.1", "--state", str(state))
    portB, srvB = serve_tls(pemB, keyB)
    r = run("a.test", "--port", str(portB), "--cafile", str(pemB),
            "--resolve", "127.0.0.1", "--state", str(state))
    assert "CHANGED" in r.stdout
    assert "certificate REPLACED" in r.stdout
    assert "SAN added: bar.test" in r.stdout
    assert "SAN removed: foo.test" in r.stdout
    assert "issuer:" in r.stdout and "Test A" in r.stdout and "Test B" in r.stdout
    srvA.close(); srvB.close()


def test_untrusted_cert_recorded_not_fatal(tmp_path):
    require_openssl()
    pem, key = make_cert(tmp_path, "A", "DNS:a.test")
    port, srv = serve_tls(pem, key)
    r = run("a.test", "--port", str(port), "--resolve", "127.0.0.1",
        "--state", str(tmp_path / "s.json"))
    assert "NOT TRUSTED" in r.stdout          # self-signed, no cafile
    assert "BASELINE" in r.stdout             # but still recorded
    d = json.loads((tmp_path / "s.json").read_text())
    assert d["hosts"]["a.test"]["observations"][0]["verified"] is False
    srv.close()


def test_expiry_warning(tmp_path):
    require_openssl()
    pem, key = make_cert(tmp_path, "A", "DNS:a.test", days=3)
    port, srv = serve_tls(pem, key)
    r = run("a.test", "--port", str(port), "--cafile", str(pem),
            "--resolve", "127.0.0.1", "--state", str(tmp_path / "s.json"),
            "--warn-days", "14")
    assert "WARNING: expires in" in r.stdout
    srv.close()


def test_days_left_parsing():
    from datetime import datetime, timezone, timedelta
    future = (datetime.now(timezone.utc) + timedelta(days=10)).strftime(
        "%b %d %H:%M:%S %Y GMT")
    assert 8 <= wsign.days_left(future) <= 10
    assert wsign.days_left("garbage") is None


def test_host_normalization_and_unreachable(tmp_path):
    r = run("https://127.0.0.1:1/x", "--state", str(tmp_path / "s.json"),
            "--timeout", "1")
    assert "UNREACHABLE" in r.stdout
    assert r.returncode == 0


def test_history_flag(tmp_path):
    require_openssl()
    pem, key = make_cert(tmp_path, "A", "DNS:a.test")
    port, srv = serve_tls(pem, key)
    state = tmp_path / "s.json"
    run("a.test", "--port", str(port), "--cafile", str(pem),
        "--resolve", "127.0.0.1", "--state", str(state))
    r = run("--history", "--state", str(state))
    d = json.loads(r.stdout)
    assert "a.test" in d and d["a.test"]["observations"]
    srv.close()


if __name__ == "__main__":
    import inspect
    import tempfile
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                if inspect.signature(fn).parameters:
                    with tempfile.TemporaryDirectory() as d:
                        fn(Path(d))
                else:
                    fn()
                print(f"  ok  {name}")
            except SystemExit:
                pass
            except Exception as e:
                failed += 1
                print(f"FAIL  {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
