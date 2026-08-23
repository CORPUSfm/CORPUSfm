"""CLI: corpusfm setup-embeddings — stand up a local embedder and wire CORPUSfm at it.

Post-install helper the admin runs on the box to make semantic search work with zero
outbound network: it optionally kicks off the vendor's own Ollama install, pulls a small
embedding model, points CORPUSfm's config at the loopback endpoint, and verifies it with a
live /embeddings round-trip.

Boundary (packet 1013 — do not cross): CORPUSfm stays a *consumer* of an OpenAI-compatible
/embeddings endpoint. This helper never bundles or pins Ollama, never checks for or manages
Ollama updates, and is agnostic afterward — the config just points at a base URL, so swapping
to LM Studio or a hosted endpoint later is a plain config change. The vendor install runs only
with explicit consent (--install-ollama / --yes / interactive y-N); without consent, or on a
platform whose install path is unknown, the exact manual commands are printed and the helper
exits 0 (never a silent privileged install, never a hard fail).

Run as the service user in server context (CORPUSFM_MODE=server / ~/.corpusfm/install.yaml
present) so the config write lands in FM SETTING, not a dev YAML the running server ignores.

Examples:
    corpusfm setup-embeddings                         # detect, prompt before any install, test
    corpusfm setup-embeddings --install-ollama --yes  # non-interactive: install + pull + wire + test
    corpusfm setup-embeddings --install-ollama --low-priority   # ...and let it yield to FMS under load
    corpusfm setup-embeddings --model mxbai-embed-large
    corpusfm setup-embeddings --no-test               # wire config without the live round-trip
    corpusfm setup-embeddings --uninstall             # undo config + priority drop-in (+ Ollama if we installed it)
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys

DEFAULT_MODEL = "nomic-embed-text"
DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "setup-embeddings",
        help="Stand up a local embedder (Ollama) and wire CORPUSfm at it",
        description=(
            "Post-install helper: optionally install Ollama (with consent), pull a small "
            "embedding model, point CORPUSfm at the loopback endpoint, and verify it live. "
            "Run as the service user in server mode so config lands in FM SETTING."
        ),
    )
    p.add_argument("--model", default=DEFAULT_MODEL,
                   help=f"embedding model to pull/use (default: {DEFAULT_MODEL})")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL,
                   help=f"OpenAI-compatible endpoint (default: {DEFAULT_BASE_URL})")
    p.add_argument("--install-ollama", action="store_true",
                   help="consent to run the vendor's Ollama installer if Ollama is absent")
    p.add_argument("--yes", "-y", action="store_true",
                   help="non-interactive: assume yes to install/pull consent prompts")
    p.add_argument("--no-test", action="store_true",
                   help="wire config without the live /embeddings verification round-trip")
    p.add_argument("--low-priority", action="store_true",
                   help="lower Ollama's CPU priority (Linux/systemd CPUWeight) so a big index yields to "
                        "co-located FileMaker Server; on other platforms, print the manual steps")
    p.add_argument("--uninstall", action="store_true",
                   help="undo CORPUSfm's embedder setup: clear config + remove the priority drop-in, and "
                        "remove Ollama itself if CORPUSfm installed it (see --keep-ollama)")
    p.add_argument("--keep-ollama", action="store_true",
                   help="with --uninstall: remove only CORPUSfm's footprint (config + drop-in), leave Ollama")
    p.set_defaults(func=run)


# ── platform / ollama detection (pure, testable) ─────────────────────────────

def detect_platform() -> dict:
    """Normalize the host into {system: linux|windows|macos|other, arch}."""
    sysname = platform.system().lower()
    system = {"linux": "linux", "windows": "windows", "darwin": "macos"}.get(sysname, "other")
    return {"system": system, "arch": platform.machine().lower()}


def ollama_present() -> bool:
    """True if the `ollama` executable is on PATH."""
    return shutil.which("ollama") is not None


def _ollama_root(base_url: str) -> str:
    """The Ollama native API root (strip the OpenAI-compat /v1 suffix)."""
    root = (base_url or "").rstrip("/")
    if root.endswith("/v1"):
        root = root[:-3]
    return root or "http://127.0.0.1:11434"


def ollama_serving(base_url: str, timeout: int = 4) -> bool:
    """True if the Ollama server answers on its native /api/tags (i.e. is running)."""
    import requests
    try:
        resp = requests.get(f"{_ollama_root(base_url)}/api/tags", timeout=timeout)
        return resp.status_code == 200
    except Exception:
        return False


def wait_serving(base_url: str, attempts: int = 15, delay: float = 2.0) -> bool:
    """Poll until Ollama is serving, up to attempts*delay seconds. A fresh install starts the
    systemd service asynchronously, so `ollama pull` fired immediately after install hits a
    'could not connect' race — this closes it. Returns True as soon as it is up."""
    import time
    for _ in range(attempts):
        if ollama_serving(base_url):
            return True
        time.sleep(delay)
    return ollama_serving(base_url)


def install_instructions(system: str) -> str:
    """The exact manual commands to install Ollama on this platform (printed when we
    won't/can't install: consent withheld, or an unknown platform)."""
    if system == "linux":
        return "  curl -fsSL https://ollama.com/install.sh | sh"
    if system == "windows":
        return ("  winget install Ollama.Ollama\n"
                "  (or download and run OllamaSetup.exe from https://ollama.com/download)")
    if system == "macos":
        return ("  brew install ollama    # then: brew services start ollama\n"
                "  (or download the app from https://ollama.com/download)")
    return ("  See https://ollama.com/download for your platform, then re-run "
            "`corpusfm setup-embeddings`.")


def _install_command(system: str) -> list[str] | None:
    """The vendor install invocation for a supported platform, else None (unknown path)."""
    if system == "linux":
        # The vendor's official installer; run via a shell (it is a piped curl|sh).
        return ["sh", "-c", "curl -fsSL https://ollama.com/install.sh | sh"]
    if system == "windows":
        # winget is not guaranteed on Server SKUs; caller falls back to manual instructions if this
        # is unavailable (handled by the FileNotFoundError / non-zero exit path in run()).
        return ["winget", "install", "--id", "Ollama.Ollama", "-e",
                "--accept-source-agreements", "--accept-package-agreements"]
    if system == "macos":
        return ["brew", "install", "ollama"]
    return None


# ── consent ──────────────────────────────────────────────────────────────────

def want_install(args) -> bool:
    """Explicit consent to run the vendor installer: --install-ollama, or --yes, or an
    interactive y/N confirmation. No consent -> we never install."""
    if getattr(args, "install_ollama", False) or getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        return False
    print("Ollama is not installed. This will run Ollama's OWN installer, which you maintain")
    print("from here (CORPUSfm does not update or manage it).")
    try:
        reply = input("Install Ollama now? [y/N] ").strip().lower()
    except EOFError:
        return False
    return reply in ("y", "yes")


# ── CPU priority (let the embedder yield to co-located FMS; packet 1013 follow-up) ─
#
# A large index makes a CPU-only embedder saturate the box, competing with FileMaker Server. Indexing is
# on-demand, so a hard cap (which throttles even when the box is idle) is wrong — instead we LOWER the
# service's CPU priority so it runs full speed when the box is free and backs off under contention. On
# Linux the vendor installs Ollama as a systemd service, so a CPUWeight drop-in does this persistently.
# Windows (IFEO, needs admin) and macOS (launchd) are documented manual steps — see docs/ollama. This
# stays consent-driven (packet 1013): applied ONLY with --low-priority or an interactive y/N (default No).

_OLLAMA_UNIT = "ollama.service"
_CPU_DROPIN_DIR = "/etc/systemd/system/ollama.service.d"
_CPU_DROPIN_PATH = _CPU_DROPIN_DIR + "/corpusfm-cpu.conf"
_CPU_WEIGHT = 20  # cgroup v2 default is 100; 20 favors FMS under contention, full speed when idle


def low_priority_dropin() -> str:
    return ("# Written by `corpusfm setup-embeddings --low-priority` to make the local embedder yield to\n"
            "# co-located FileMaker Server under CPU contention (full speed when the box is idle). Delete\n"
            f"# this file, then `systemctl daemon-reload && systemctl restart {_OLLAMA_UNIT}` to restore.\n"
            "[Service]\n"
            f"CPUWeight={_CPU_WEIGHT}\n")


def low_priority_instructions(system: str) -> str:
    """The manual steps to lower Ollama's CPU priority on this platform (printed when we won't/can't apply
    it). CORPUSfm only automates Linux; Windows/macOS point at the manual commands + docs/ollama."""
    if system == "linux":
        return (f"  sudo mkdir -p {_CPU_DROPIN_DIR}\n"
                f"  printf '[Service]\\nCPUWeight={_CPU_WEIGHT}\\n' | sudo tee {_CPU_DROPIN_PATH}\n"
                f"  sudo systemctl daemon-reload && sudo systemctl restart {_OLLAMA_UNIT}")
    if system == "windows":
        return ("  Lower ollama.exe's CPU priority persistently via an Image File Execution Options\n"
                "  registry value (needs admin) — set CpuPriorityClass=5 (Below Normal) under\n"
                "  HKLM\\...\\Image File Execution Options\\ollama.exe\\PerfOptions. See docs/ollama.")
    if system == "macos":
        return ("  Run Ollama under launchd with Nice / ProcessType=Background, or nice/renice the\n"
                "  ollama process. See docs/ollama.")
    return ("  Lower the `ollama` process's CPU priority with your OS's tools. See docs/ollama.")


def want_low_priority(args, system: str) -> bool:
    """Consent to lower Ollama's CPU priority so it yields to FMS: --low-priority, or an interactive y/N
    (Linux only, where we can apply it automatically; DEFAULT No). No consent -> we never touch the
    service."""
    if getattr(args, "low_priority", False):
        return True
    if system != "linux" or not sys.stdin.isatty():
        return False
    print("\nIs this a CPU-only, co-located box? A large index makes the local embedder saturate CPU and")
    print("compete with FileMaker Server. CORPUSfm can lower Ollama's CPU priority so it yields to FMS")
    print("under load (full speed when the box is idle) — recommended on a co-located box.")
    try:
        reply = input("Lower Ollama's CPU priority so it yields to FileMaker Server? [y/N] ").strip().lower()
    except EOFError:
        return False
    return reply in ("y", "yes")


def apply_low_priority(system: str) -> bool:
    """Lower the ollama systemd service's CPU priority via a CPUWeight drop-in (Linux only). Returns True
    on success. On any failure (not Linux/systemd, no sudo, restart error) it prints the manual commands
    and returns False — never a hard fail (mirrors the vendor-install fallback)."""
    if system != "linux" or shutil.which("systemctl") is None:
        print("Automatic priority-lowering is Linux/systemd only. To do it yourself:")
        print(low_priority_instructions(system))
        return False
    try:
        subprocess.run(["sudo", "mkdir", "-p", _CPU_DROPIN_DIR], check=True)
        subprocess.run(["sudo", "tee", _CPU_DROPIN_PATH], input=low_priority_dropin().encode(),
                       stdout=subprocess.DEVNULL, check=True)
        subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
        subprocess.run(["sudo", "systemctl", "restart", _OLLAMA_UNIT], check=True)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        print(f"Could not lower Ollama's priority automatically ({exc}). To do it yourself:")
        print(low_priority_instructions(system))
        return False
    print(f"Lowered Ollama's CPU priority (CPUWeight={_CPU_WEIGHT}) via {_CPU_DROPIN_PATH}.")
    print(f"To restore: delete that file, then `sudo systemctl daemon-reload && sudo systemctl "
          f"restart {_OLLAMA_UNIT}`.")
    return True


# ── uninstall (mirror of the installer; packet 1013 follow-up) ─────────────────
#
# The safety mechanism is a "did WE install Ollama" marker written on a successful vendor install, so
# --uninstall never removes an Ollama the admin runs for other things. Config-clearing + drop-in removal
# always run (our footprint); Ollama removal runs only when installed_by_us() and not --keep-ollama, and
# only Linux is automated (Windows/macOS print winget/brew guidance, like install).

def _marker_path():
    """This installation's state directory, not `~` (packet 1246-03-01).

    The marker decides whether `--uninstall` may remove Ollama. Keyed to a home directory it was
    keyed to whoever ran the command: install as one user, uninstall as another, and the marker is
    missing — so an Ollama CORPUSfm *did* install would be left behind, which is the safer error but
    still the wrong answer. It belongs to the installation.
    """
    from corpusfm.lifecycle import app_paths
    return app_paths.state_dir() / "ollama_installed_by_corpusfm"


def mark_installed() -> None:
    """Record that CORPUSfm ran the vendor install, so --uninstall may later remove it. Best-effort."""
    p = _marker_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("Ollama was installed by `corpusfm setup-embeddings`.\n")
    except OSError:
        pass


def installed_by_us() -> bool:
    return _marker_path().exists()


def _clear_marker() -> None:
    try:
        _marker_path().unlink(missing_ok=True)
    except OSError:
        pass


def unwire_config() -> None:
    """Clear the embedding endpoint/model + verified flag (mirror of wire_config) so CORPUSfm stops
    pointing at an endpoint we're about to remove."""
    from corpusfm.app.app_config import load_app_config, save_app_config
    cfg = load_app_config()
    cfg.ai_embedding_base_url = ""
    cfg.ai_embedding_model = ""
    cfg.ai_embedding_verified = False
    save_app_config(cfg)


def uninstall_instructions(system: str) -> str:
    """The manual commands to remove Ollama on this platform (printed when we won't/can't automate it)."""
    if system == "linux":
        return ("  sudo systemctl stop ollama && sudo systemctl disable ollama\n"
                "  sudo rm -f /etc/systemd/system/ollama.service\n"
                f"  sudo rm -rf {_CPU_DROPIN_DIR}\n"
                "  sudo systemctl daemon-reload\n"
                "  sudo rm -f \"$(command -v ollama)\"\n"
                "  sudo rm -rf /usr/share/ollama\n"
                "  sudo userdel ollama 2>/dev/null; sudo groupdel ollama 2>/dev/null")
    if system == "windows":
        return ("  winget uninstall Ollama.Ollama\n"
                "  (or Settings -> Apps -> Ollama -> Uninstall). Then delete %USERPROFILE%\\.ollama.")
    if system == "macos":
        return ("  brew services stop ollama && brew uninstall ollama\n"
                "  (or quit the app and move it to Trash). Then delete ~/.ollama.")
    return "  Remove Ollama with your platform's package manager, then delete its models directory."


def remove_low_priority_dropin(system: str) -> None:
    """Remove the CPUWeight drop-in we may have written + reload systemd (Linux only). Silent no-op when
    absent or not applicable."""
    if system != "linux" or shutil.which("systemctl") is None or not os.path.exists(_CPU_DROPIN_PATH):
        return
    try:
        subprocess.run(["sudo", "rm", "-f", _CPU_DROPIN_PATH], check=True)
        subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
        print(f"Removed the CPU-priority drop-in {_CPU_DROPIN_PATH}.")
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        print(f"Could not remove {_CPU_DROPIN_PATH} automatically ({exc}); remove it by hand.")


def remove_ollama(system: str) -> bool:
    """Run the vendor-removal steps for a CORPUSfm-installed Ollama (Linux only). Returns True on success.
    Prints manual guidance and returns False where we don't automate it (Windows/macOS/unknown) or on any
    error — never a hard fail (mirrors the vendor-install fallback)."""
    if system != "linux" or shutil.which("systemctl") is None:
        print("Automatic removal is Linux/systemd only. To remove Ollama yourself:")
        print(uninstall_instructions(system))
        return False
    binary = shutil.which("ollama")
    steps = [
        ["sudo", "systemctl", "stop", _OLLAMA_UNIT],
        ["sudo", "systemctl", "disable", _OLLAMA_UNIT],
        ["sudo", "rm", "-f", "/etc/systemd/system/ollama.service"],
        ["sudo", "rm", "-rf", _CPU_DROPIN_DIR],
        ["sudo", "systemctl", "daemon-reload"],
    ]
    if binary:
        steps.append(["sudo", "rm", "-f", binary])
    steps.append(["sudo", "rm", "-rf", "/usr/share/ollama"])
    try:
        for cmd in steps:
            subprocess.run(cmd, check=True)
        # user/group removal is best-effort — may be absent or still referenced.
        subprocess.run(["sudo", "userdel", "ollama"], check=False)
        subprocess.run(["sudo", "groupdel", "ollama"], check=False)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        print(f"Removal hit an error ({exc}). Finish by hand:")
        print(uninstall_instructions(system))
        return False
    print("Removed Ollama (service, binary, models, and the ollama user).")
    return True


def _confirm_uninstall(args) -> bool:
    """Loud confirm before a destructive Ollama removal: --yes, or an interactive y/N (default No)."""
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        return False
    try:
        return input("Remove Ollama now? [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def run_uninstall(args) -> int:
    info = detect_platform()
    system = info["system"]
    print(f"Platform: {system} ({info['arch']})")
    keep = getattr(args, "keep_ollama", False)

    # 1) Unwire CORPUSfm's embedder config so it stops pointing at the endpoint.
    try:
        unwire_config()
        print("Cleared the embedder config (base URL / model / verified).")
    except Exception as exc:
        print(f"WARNING: could not clear embedder config: {exc}", file=sys.stderr)
        print("Clear it by hand in Settings -> Integrations -> Semantic search.", file=sys.stderr)

    # 2) Remove our CPU-priority drop-in (our footprint), regardless of whether Ollama goes.
    remove_low_priority_dropin(system)

    # 3) Remove Ollama itself — only if WE installed it and --keep-ollama was not given.
    if keep:
        print("Left Ollama in place (--keep-ollama); removed only CORPUSfm's config + priority drop-in.")
    elif not installed_by_us():
        print("\nOllama was not installed by CORPUSfm (no install marker) — leaving it in place.")
        print("If you want to remove it yourself:")
        print(uninstall_instructions(system))
    else:
        print("\nThis will REMOVE the Ollama that CORPUSfm installed:")
        print(uninstall_instructions(system))
        if not _confirm_uninstall(args):
            print("Aborted; Ollama left in place.")
            return 0
        if remove_ollama(system):
            _clear_marker()

    print("\nNote: the vector index is separate CORPUSfm data and is untouched.")
    print("Reset it from Settings -> Storage -> Reset semantic index if you no longer want it.")
    return 0


# ── config wiring (mirrors app/web/routes/api/settings.py test_embedding) ─────

def wire_config(base_url: str, model: str, verified: bool) -> None:
    """Persist the embedding endpoint/model + verified flag via the app config writer.

    Imports the app helpers inside the fn (CLI style, like cmd_users) so the module stays cheap
    to import. save_app_config auto-routes: FM SETTING in server mode, YAML in dev — and a FM
    write failure now PROPAGATES (packet 1009/S2), which is why this must run in server context."""
    from corpusfm.app.app_config import load_app_config, save_app_config
    cfg = load_app_config()
    cfg.ai_embedding_base_url = base_url
    cfg.ai_embedding_model = model
    cfg.ai_embedding_verified = verified
    save_app_config(cfg)


# ── orchestration ────────────────────────────────────────────────────────────

def _pull_model(model: str) -> int:
    print(f"Pulling embedding model '{model}' (ollama pull)...")
    try:
        return subprocess.call(["ollama", "pull", model])
    except FileNotFoundError:
        print("ERROR: `ollama` not found on PATH after install.", file=sys.stderr)
        return 1


def _run_installer(system: str) -> int:
    cmd = _install_command(system)
    if cmd is None:
        return 127
    print("Running Ollama's own installer (you maintain it from here):")
    print("  " + " ".join(cmd))
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        # e.g. winget absent on a Server SKU — signal "unknown path" so run() prints manual steps.
        return 127


def run(args) -> int:
    if getattr(args, "uninstall", False):
        return run_uninstall(args)

    model = args.model or DEFAULT_MODEL
    base_url = args.base_url or DEFAULT_BASE_URL
    info = detect_platform()
    system = info["system"]
    print(f"Platform: {system} ({info['arch']})")

    # 1) Ensure Ollama present.
    if not ollama_present():
        if not want_install(args):
            print("\nOllama is not installed and no install consent was given.")
            print("To install it yourself, run:")
            print(install_instructions(system))
            print("\nThen re-run: corpusfm setup-embeddings")
            return 0
        rc = _run_installer(system)
        if rc == 127 or not ollama_present():
            print("\nCould not run an automatic Ollama install on this platform.")
            print("Install it manually, then re-run this command:")
            print(install_instructions(system))
            return 0
        if rc != 0:
            print(f"ERROR: Ollama installer exited with code {rc}.", file=sys.stderr)
            return 1
        mark_installed()  # record OUR install so --uninstall may later remove it
        print("Ollama installed.")
    else:
        print("Ollama already present.")

    # 1.5) Optionally lower Ollama's CPU priority so a big index yields to co-located FMS (Linux/systemd;
    # consent-driven, default No). Applied before the serving wait so the service restart settles first.
    if want_low_priority(args, system):
        apply_low_priority(system)

    # 2) Ensure the server is actually serving BEFORE pulling. A fresh install starts the
    # service asynchronously, so an immediate `ollama pull` races 'could not connect'.
    if not ollama_serving(base_url):
        print("Waiting for the Ollama server to come up...")
        if not wait_serving(base_url):
            print(f"NOTE: Ollama is not serving at {base_url} yet.")
            print("      Start it (Linux: `systemctl start ollama`; Windows: the Ollama service;")
            print("      macOS: `brew services start ollama`), then re-run this command.")

    # 3) Pull the model (idempotent — ollama re-pull is a fast no-op if current).
    if _pull_model(model) != 0:
        print(f"ERROR: failed to pull model '{model}'.", file=sys.stderr)
        return 1

    # 4) Verify the endpoint with a live /embeddings round-trip (test = verify).
    verified = False
    if args.no_test:
        print("Skipping live verification (--no-test); ai_embedding_verified will stay False.")
    else:
        from corpusfm.server.ai.vector_index import test_embedding_endpoint
        print(f"Testing {base_url} with model '{model}'...")
        result = test_embedding_endpoint(base_url, model)
        if result.get("ok"):
            verified = True
            print(f"OK: embeddings working ({result.get('dims')} dimensions).")
        else:
            print(f"Endpoint not verified: {result.get('error')}", file=sys.stderr)
            print("Wiring config anyway (unverified); fix the endpoint and re-run to verify.")

    # 5) Wire config (server context required so it lands in FM SETTING).
    try:
        wire_config(base_url, model, verified)
    except Exception as exc:
        print(f"ERROR: could not save config: {exc}", file=sys.stderr)
        print("Are you running in server context (CORPUSFM_MODE=server) as the service user?",
              file=sys.stderr)
        return 1
    print(f"Config saved: base_url={base_url}, model={model}, verified={verified}")

    if verified:
        print("\nSemantic search is ready. Index a snapshot from Catalog -> Index/Reindex,")
        print("then search. Changing/re-pulling the model changes the vectors -> Reset + reindex.")
    return 0
