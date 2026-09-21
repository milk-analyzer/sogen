"""Behavioural check for the vmpunpack build: does a guest socket reach the HOST?

The release workflow greps analyzer.exe for marker strings, which proves that SOGEN_ALLOW_NETWORK is read
and says nothing about which way the condition points. This runs a benign guest - Microsoft's finger.exe,
a plain TCP client - against a listener on the host's loopback and requires:

    SOGEN_ALLOW_NETWORK=1      the listener is reached   (the control: without it "not reached" proves nothing)
    unset, "0", "true"         the listener is not reached

    python .github/vmpunpack-nettest.py --analyzer build/release/artifacts --root path/to/emulation/root
"""
import argparse, os, shutil, socket, subprocess, sys, threading

PORT = 79                                   # finger/tcp, which is what finger.exe looks up and connects to
SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")


def run_guest(analyzer_dir, root, extra_env):
    """Run finger.exe under the emulator. Returns (listener reached, bytes it received, engine stdout)."""
    got = {"accepted": False, "data": b""}
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT)); srv.listen(1); srv.settimeout(120)

    def serve():
        try:
            conn, _ = srv.accept()
            got["accepted"] = True
            conn.settimeout(10)
            try: got["data"] = conn.recv(64)
            except OSError: pass
            conn.close()
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True); t.start()
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("SOGEN_", "EMULATOR_"))}
    env.update(extra_env)
    cmd = [os.path.join(analyzer_dir, "analyzer.exe"), "--backend", "unicorn", "--no-inst-precision",
           "-e", root, "-r", os.path.join(root, "registry"), "-c", r"C:\nettest\finger.exe", "canary@127.0.0.1"]
    try:
        p = subprocess.run(cmd, cwd=analyzer_dir, env=env, capture_output=True, text=True, encoding="latin1",
                           timeout=110, stdin=subprocess.DEVNULL)
        out = p.stdout or ""
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else (e.stdout or b"").decode("latin1", "replace")
    t.join(3); srv.close(); t.join(3)
    return got["accepted"], got["data"], out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--analyzer", required=True, help="directory holding analyzer.exe and its backends")
    ap.add_argument("--root", required=True, help="emulation root (the directory holding filesys/ and registry/)")
    args = ap.parse_args()
    analyzer_dir, root = os.path.abspath(args.analyzer), os.path.abspath(args.root)

    finger = os.path.join(SYSTEM32, "finger.exe")
    services = os.path.join(SYSTEM32, "drivers", "etc", "services")
    for p in (os.path.join(analyzer_dir, "analyzer.exe"), os.path.join(root, "registry"), finger, services):
        if not os.path.exists(p): sys.exit(f"[!] missing {p}")

    # finger.exe looks its port up in etc\services, which the emulation root does not carry. Everything
    # staged into the root is removed again.
    guest_dir = os.path.join(root, "filesys", "c", "nettest")
    etc = os.path.join(root, "filesys", "c", "windows", "system32", "drivers", "etc")
    staged_services = os.path.join(etc, "services")
    made_etc, made_services = not os.path.isdir(etc), not os.path.isfile(staged_services)
    failures = []
    try:
        os.makedirs(guest_dir, exist_ok=True); os.makedirs(etc, exist_ok=True)
        shutil.copy(finger, os.path.join(guest_dir, "finger.exe"))
        if made_services: shutil.copy(services, staged_services)

        cases = [("SOGEN_ALLOW_NETWORK=1 (control)", {"SOGEN_ALLOW_NETWORK": "1"}, True),
                 ("default", {}, False),
                 ("default, as vmpunpack runs it", {"SOGEN_UNPACK": "1"}, False),
                 ("SOGEN_ALLOW_NETWORK=0", {"SOGEN_ALLOW_NETWORK": "0"}, False),
                 ("SOGEN_ALLOW_NETWORK=true", {"SOGEN_ALLOW_NETWORK": "true"}, False)]
        for name, env, want in cases:
            reached, data, out = run_guest(analyzer_dir, root, env)
            ok = reached == want and (not want or data == b"canary")
            print(f"  {'ok  ' if ok else 'FAIL'}  {name:34} host listener reached={reached} data={data!r}")
            if not ok: failures.append(name)
            said = [l for l in out.splitlines() if l.startswith("[UNPACK] host network:")]
            if env.get("SOGEN_UNPACK") and said[:1] != ["[UNPACK] host network: blocked"]:
                print(f"  FAIL  {name:34} startup line was {said[:1]}"); failures.append(name + " (startup line)")
            if env.get("SOGEN_ALLOW_NETWORK") == "1" and not (said and said[0].startswith("[UNPACK] host network: LIVE")):
                print(f"  FAIL  {name:34} startup line was {said[:1]}"); failures.append(name + " (startup line)")
    finally:
        shutil.rmtree(guest_dir, ignore_errors=True)
        if made_services:
            try: os.remove(staged_services)
            except OSError: pass
        if made_etc:
            try: os.rmdir(etc)
            except OSError: pass
        for f in ("unpacked.bin", "unpacked.meta"):          # the SOGEN_UNPACK case dumps finger.exe
            try: os.remove(os.path.join(r"C:\dumps", f))
            except OSError: pass

    if failures:
        sys.exit("[!] the build does not contain the guest's network as documented: " + "; ".join(failures))
    print("[+] guest sockets stay off the host unless SOGEN_ALLOW_NETWORK=1")


if __name__ == "__main__":
    main()
