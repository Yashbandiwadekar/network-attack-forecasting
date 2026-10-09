"""Run the whole system as one service, on one port.

Builds the dashboard if needed, then serves it and the API from a single uvicorn process. That
is the deployable shape: the browser and the API share an origin, so CORS never applies and the
frontend needs no build-time knowledge of the host's address.

    python -m scripts.serve                 # localhost only
    python -m scripts.serve --lan           # bind 0.0.0.0 and print the LAN URL to open
    python -m scripts.serve --lan --port 80 # a port a phone will reach without a suffix
    python -m scripts.serve --config v1     # serve the v1 (leaky-split) model; default is v2

The model defaults to configs/real_data_v2_converged.yaml (day-disjoint, the README headline).
--config (or $PHOENIX_CONFIG) takes v1, v2, or a path to a configs/*.yaml file. Startup aborts with
a clear message if that model's checkpoint or scaler is missing.

For the split development setup (Vite on :5173 with hot reload), run uvicorn and `npm run dev`
separately instead; frontend/.env.development points the dev server at the API.
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST = PROJECT_ROOT / "frontend" / "dist"


def lan_ip() -> str | None:
    """The address this machine is reachable at from the rest of the network.

    Opening a UDP socket to a public address makes the OS pick the interface it would actually
    route through; nothing is sent. This beats gethostbyname(), which commonly returns 127.0.0.1.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def build_frontend(force: bool) -> bool:
    if DIST.joinpath("index.html").is_file() and not force:
        print(f"[=] Using existing build at {DIST.relative_to(PROJECT_ROOT)} (--rebuild to refresh)")
        return True

    npm = shutil.which("npm") or shutil.which("npm.cmd")
    if not npm:
        print("[!] npm not found, so the dashboard cannot be built.")
        print("    The API will still serve on its own; install Node, or run "
              "`npm run build --prefix frontend` elsewhere and copy frontend/dist across.")
        return False

    print("[*] Building the dashboard...")
    result = subprocess.run([npm, "run", "build", "--prefix", "frontend"], cwd=PROJECT_ROOT)
    if result.returncode != 0:
        print("[!] Frontend build failed. The API will start, but it will have no dashboard to serve.")
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lan", action="store_true", help="bind 0.0.0.0 so other machines can reach it")
    parser.add_argument("--host", default=None, help="explicit bind address (overrides --lan)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--config", default=None,
                        help="model to serve: v1, v2 (default) or a configs/*.yaml path; "
                             "also settable via $PHOENIX_CONFIG")
    parser.add_argument("--rebuild", action="store_true", help="rebuild the dashboard even if a build exists")
    args = parser.parse_args()

    if args.config:
        os.environ["PHOENIX_CONFIG"] = args.config

    have_frontend = build_frontend(args.rebuild)
    host = args.host or ("0.0.0.0" if args.lan else "127.0.0.1")

    print()
    print("  PHOENIX IDPS")
    print(f"  {'dashboard + API' if have_frontend else 'API only (no dashboard build)'} on port {args.port}")
    print()
    print(f"    local   http://127.0.0.1:{args.port}")
    # Imported here so the banner prints before torch and the checkpoint load.
    try:
        from app.server import STATE, check_model_artifacts
        config_path = STATE.config_path  # resolved (and validated to exist) when app.server is imported
        check_model_artifacts(config_path)
    except RuntimeError as exc:  # ModelUnavailableError
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(2)
    print(f"    model   {config_path}")
    if host == "0.0.0.0":
        ip = lan_ip()
        if ip:
            print(f"    network http://{ip}:{args.port}   <- open this on other devices")
        else:
            print("    network bound to 0.0.0.0, but this machine's LAN address could not be determined")
        print()
        print("  Reachable from the network. If another device cannot connect, the host firewall")
        print(f"  is the usual cause -- allow inbound TCP {args.port}.")
    print()

    import uvicorn

    os.environ.setdefault("PHOENIX_HOST", host)
    uvicorn.run("app.server:app", host=host, port=args.port, log_level="info")


if __name__ == "__main__":
    sys.exit(main())
