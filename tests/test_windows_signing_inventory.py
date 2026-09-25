"""The Windows signing inventory is complete and nothing is rewritten after signing (public closure).

These assert the RULES the signed release depends on, not the spelling of the implementation
(CLAUDE.md, *Assert what must be TRUE*). Each names the property it defends and, where a real
mistake is available, reproduces that mistake so the guard is known to be able to say WRONG.

Two properties carry the packet's closure and are worth stating plainly, because every other test
here exists to protect one of them:

  1. COMPLETENESS - 11 distributed occurrences over 10 distinct byte streams, and no PowerShell in
     the Windows package outside that list. Public decision D14 excludes the standalone bootstrap.
  2. NO POST-SIGNING REWRITE - the bytes inside the finished archives are the bytes that were
     signed, proved by opening the archives rather than by trusting the build order.

Statically checkable and in-process: no Azure, no network, no Windows. The real signing run is a
manually dispatched workflow that no routine sweep will ever execute, so the discriminating work has
to be doable here or it is not done at all.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGER = ROOT / "installer/package-installer.sh"


def _load_module():
    """`installer/` is a build tree, not a package, so the module is loaded by path.

    It is registered in `sys.modules` before execution because `@dataclass` resolves annotations
    through `sys.modules[cls.__module__]` and fails on a module that is not there yet.
    """
    spec = importlib.util.spec_from_file_location(
        "cfm_windows_signing", ROOT / "installer/windows_signing.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ws = _load_module()


# ── the candidate the packager stages, rebuilt here from the real repository files ──────────────
#
# The member lists are PARSED OUT OF THE PACKAGER rather than restated. A test that carried its own
# copy would keep passing after the packager stopped shipping a file, which is the exact class of
# silently-dead guard CLAUDE.md names.

def _runtime_members(name: str) -> list[str]:
    body = PACKAGER.read_text(encoding="utf-8")
    block = re.search(rf"(?ms)^{name}=\(\n(.*?)^\)$", body)
    assert block, f"{name} is no longer an array literal in the packager"
    return [line.strip() for line in block.group(1).splitlines() if line.strip()]


WINDOWS_RUNTIME_MEMBERS = _runtime_members("WINDOWS_RUNTIME_MEMBERS")
LINUX_RUNTIME_MEMBERS = _runtime_members("LINUX_RUNTIME_MEMBERS")

OUTER_SOURCES = {
    "linux": {
        "install.sh": "installer/linux/install.sh",
        "_cfm_lib.sh": "installer/linux/_cfm_lib.sh",
        "cfm-verify-installer-bundle.sh": "installer/linux/cfm-verify-installer-bundle.sh",
        "cfm-verify-bootstrap-handoff.sh": "installer/linux/cfm-verify-bootstrap-handoff.sh",
    },
    "windows": {
        "install.ps1": "installer/windows/install.ps1",
        "_cfm_lib.ps1": "installer/windows/_cfm_lib.ps1",
        "cfm-verify-installer-bundle.ps1": "installer/windows/cfm-verify-installer-bundle.ps1",
        "cfm-verify-bootstrap-handoff.ps1": "installer/windows/cfm-verify-bootstrap-handoff.ps1",
    },
}

VERSION = "0.999001"
SERIES = "series-99"
COMMIT = "0" * 40


# The asset payload is small here but STRUCTURALLY REAL: finalization cross-checks the manifest's
# recorded digest, member set and application commit against the candidate, so a stub of two
# unrelated files would make every end-to-end test below pass for the wrong reason.
ASSET_ENTRIES = {
    "db/CORPUSfm_DB.fmp12": b"database bytes\n",
    "db/CORPUSfm_DB.artifact": b"wrapped db seed\n",
    "addon/CORPUSfm_ADDON.fmaddon": b"addon package bytes\n",
    "addon/CORPUSfm_ADDON/info.json": b'{"name": "CORPUSfm"}\n',
}


def write_asset_payload(payload_dir: Path, commit: str,
                        entries: dict[str, bytes] | None = None) -> None:
    """Write `corpusfm-assets.zip` + a truthful schema-2 `assets.json` describing exactly it."""
    entries = ASSET_ENTRIES if entries is None else entries
    archive = payload_dir / "corpusfm-assets.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for name, blob in entries.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, blob)
    manifest = {
        "schema_version": 2,
        "provenance": {
            "source": "application",
            "application_commit": commit,
            "assets_root": "assets",
            "source_paths": {name: f"assets/{name}" for name in entries},
        },
        "source_digests": {f"assets/{name}": hashlib.sha256(blob).hexdigest()
                           for name, blob in entries.items()},
        "payload_digests": {name: hashlib.sha256(blob).hexdigest()
                            for name, blob in entries.items()},
        "payload_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "excluded_evidence_only": ["assets/db/CORPUSfm_DB.xml"],
    }
    (payload_dir / "assets.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_candidate(root: Path) -> Path:
    """A candidate shaped exactly as `--stage-signing-candidate` leaves one.

    Real repository bytes are used for every PowerShell member, so a renamed or deleted script fails
    here instead of at a live gate.
    """
    candidate = root / "candidate"
    (candidate / "payload").mkdir(parents=True)
    for name, blob in (
        ("corpusfm.bundle", b"bundle\n"),
        ("corpusfm-recovery-source.zip", b"recovery\n"),
    ):
        (candidate / "payload" / name).write_bytes(blob)
    write_asset_payload(candidate / "payload", COMMIT)

    for platform, sources in OUTER_SOURCES.items():
        outer = candidate / platform / "outer"
        outer.mkdir(parents=True)
        for name, source in sources.items():
            shutil.copyfile(ROOT / source, outer / name)
        (outer / "READ-ME-FIRST.txt").write_bytes(b"read me\n")

        members = WINDOWS_RUNTIME_MEMBERS if platform == "windows" else LINUX_RUNTIME_MEMBERS
        for member in members:
            destination = candidate / platform / "runtime" / member
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / member, destination)

    (candidate / "candidate.json").write_text(json.dumps({
        "schema_version": 1,
        "installer_series": SERIES,
        "installer_version": VERSION,
        "commit": COMMIT,
        "installer_source_commit": "1" * 40,
        "package_kind": "ordinary",
        "bridge_target_series": None,
        "platforms": {
            "linux": {"entry_point": "install.sh",
                      "zip": f"corpusfm-installer-linux-{VERSION}.zip",
                      "runtime_members": LINUX_RUNTIME_MEMBERS},
            "windows": {"entry_point": "install.ps1",
                        "zip": f"corpusfm-installer-windows-{VERSION}.zip",
                        "runtime_members": WINDOWS_RUNTIME_MEMBERS},
        },
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return candidate


def fake_sign(data: bytes, marker: str) -> bytes:
    """What Authenticode does to a PowerShell file: APPEND a comment block, change nothing else."""
    return data + (b"\r\n# SIG # Begin signature block\r\n"
                   b"# " + marker.encode("ascii") + b"\r\n"
                   b"# SIG # End signature block\r\n")


def sign_all(candidate: Path, out: Path, mutate=None) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    inventory = ws.read_inventory(candidate)
    for row in inventory["streams"]:
        body = (candidate / ws.SIGN_DIRNAME / row["file"]).read_bytes()
        signed = fake_sign(body, row["stream"])
        if mutate is not None:
            signed = mutate(row["stream"], body, signed)
            if signed is None:
                continue
        (out / row["file"]).write_bytes(signed)
    return out


@pytest.fixture()
def candidate(tmp_path):
    return build_candidate(tmp_path)


# ── property 1: the inventory is complete ───────────────────────────────────────────────────────

def test_the_closure_is_eleven_occurrences_over_ten_distinct_streams():
    """The public closure (parent 1380 section 3.2 and D14), asserted against the table.

    Four outer members plus seven runtime members. Widening the table without revising the closure
    is the mistake this catches - and the module refuses at `stage` for the same reason.
    """
    assert len(ws.OCCURRENCES) == 11
    assert len({o.ordinal for o in ws.OCCURRENCES}) == 11
    assert len({o.path for o in ws.OCCURRENCES}) == 11
    assert len({o.stream for o in ws.OCCURRENCES}) == 10
    assert sorted(o.location for o in ws.OCCURRENCES).count("outer") == 4
    assert sorted(o.location for o in ws.OCCURRENCES).count("runtime") == 7


def test_the_library_is_the_one_stream_that_occupies_two_positions():
    """`_cfm_lib.ps1` ships twice. It is signed ONCE, or one library carries two signatures."""
    doubled = [stream for stream in {o.stream for o in ws.OCCURRENCES}
               if len([o for o in ws.OCCURRENCES if o.stream == stream]) > 1]
    assert doubled == ["cfm-lib"]
    positions = sorted(o.path for o in ws.OCCURRENCES if o.stream == "cfm-lib")
    assert positions == ["windows/outer/_cfm_lib.ps1",
                         "windows/runtime/installer/windows/_cfm_lib.ps1"]


def test_every_inventory_member_names_a_file_the_repository_actually_ships():
    """The inventory addresses candidate paths; the packager fills them from these sources.

    A rename anywhere in the Windows installer family must fail here, not at a signing run.
    """
    sources = {
        "windows/outer/install.ps1": "installer/windows/install.ps1",
        "windows/outer/_cfm_lib.ps1": "installer/windows/_cfm_lib.ps1",
        "windows/outer/cfm-verify-installer-bundle.ps1":
            "installer/windows/cfm-verify-installer-bundle.ps1",
        "windows/outer/cfm-verify-bootstrap-handoff.ps1":
            "installer/windows/cfm-verify-bootstrap-handoff.ps1",
    }
    for occurrence in ws.OCCURRENCES:
        if occurrence.location == "runtime":
            source = occurrence.path[len("windows/runtime/"):]
            assert source in WINDOWS_RUNTIME_MEMBERS, occurrence.path
        else:
            source = sources[occurrence.path]
        assert (ROOT / source).is_file(), source


def test_the_windows_runtime_ships_no_powershell_the_inventory_does_not_cover():
    """The nested runtime is where an added helper would hide: it is never opened by a human."""
    covered = {o.path[len("windows/runtime/"):] for o in ws.OCCURRENCES
               if o.location == "runtime"}
    assert {m for m in WINDOWS_RUNTIME_MEMBERS if m.endswith(".ps1")} == covered


def test_no_standalone_occurrence_and_no_credential_bearing_member():
    """D14: the public release has no standalone bootstrap surface, so none is signed; the package
    runtime bootstrap - the source of the installed launcher - stays in the closure.

    And the public package is acquired anonymously: no signed member may carry a credential seam,
    because a seam would have to be filled before signing and would then ship.
    """
    assert {o.location for o in ws.OCCURRENCES} == {"outer", "runtime"}
    assert not any(o.path.startswith("standalone/") for o in ws.OCCURRENCES)
    assert "windows/runtime/installer/bootstrap/windows/bootstrap.ps1" in {
        o.path for o in ws.OCCURRENCES}
    assert not hasattr(ws.OCCURRENCES[0], "carries_embedded_pat")
    body = (ROOT / "installer/windows/install.ps1").read_text(encoding="ascii")
    boot = (ROOT / "installer/bootstrap/windows/bootstrap.ps1").read_text(encoding="ascii")
    for text in (body, boot):
        assert not re.findall(r"(?mi)^\$EmbeddedPat\s*=", text)


def test_a_stray_standalone_bootstrap_is_never_signed_or_carried(candidate):
    """With no standalone tree in the closure, a stray standalone bootstrap must not be signed or
    silently carried: it is outside every tree the build packages, so staging never lists it."""
    stray = candidate / "standalone" / "bootstrap.ps1"
    stray.parent.mkdir()
    stray.write_bytes((ROOT / "installer/bootstrap/windows/bootstrap.ps1").read_bytes())
    inventory = ws.stage(candidate)
    paths = {o["path"] for row in inventory["streams"] for o in row["occurrences"]}
    assert not any(path.startswith("standalone/") for path in paths)
    assert not any(name.startswith("standalone/") for name in inventory["non_signable_sha256"])


def test_staging_publishes_exactly_one_file_per_distinct_stream(candidate):
    inventory = ws.stage(candidate)
    assert inventory["occurrence_count"] == 11
    assert inventory["distinct_stream_count"] == 10
    assert len(sorted((candidate / "sign").glob("*.ps1"))) == 10
    assert ws.read_inventory(candidate) == inventory


def test_staging_refuses_powershell_it_was_not_told_about(candidate):
    """THE COMPLETENESS GUARD. A new Windows helper added to the package must stop the build.

    Reproduced as the real mistake: a script is added to the nested runtime tree and to no list.
    Without this, it ships unsigned and, under AllSigned, an installation dies on a file nobody knew
    was executable.
    """
    stray = candidate / "windows/runtime/installer/windows/cfm-new-helper.ps1"
    stray.write_bytes(b"Write-Host 'hello'\r\n")
    with pytest.raises(ws.Refusal, match="not in the signing inventory"):
        ws.stage(candidate)


def test_staging_refuses_when_the_two_library_copies_have_drifted(candidate):
    """Items 3 and 6 are one file copied twice. Signing one and placing it in both positions is
    only correct while they are identical; if they diverge, doing so would ship bytes nobody
    wrote."""
    (candidate / "windows/runtime/installer/windows/_cfm_lib.ps1").write_bytes(
        (candidate / "windows/outer/_cfm_lib.ps1").read_bytes() + b"# drift\r\n"
    )
    with pytest.raises(ws.Refusal, match="not byte-identical"):
        ws.stage(candidate)


@pytest.mark.parametrize("prefix,suffix,expected", [
    (b"\xef\xbb\xbf", b"", "BOM"),
    (b"", "# café\r\n".encode("utf-8"), "not ASCII"),
])
def test_staging_refuses_an_encoding_a_signature_would_freeze(candidate, prefix, suffix, expected):
    """1380-01 constraint 6. Encoding is checked BEFORE signing because the only fix afterwards
    would be the post-signing rewrite the packet forbids."""
    path = candidate / "windows/outer/cfm-verify-installer-bundle.ps1"
    path.write_bytes(prefix + path.read_bytes() + suffix)
    with pytest.raises(ws.Refusal, match=expected):
        ws.stage(candidate)


# ── property 2: what comes back really is a signature over these exact bytes ────────────────────

def test_adoption_places_one_signed_library_into_both_of_its_positions(candidate):
    ws.stage(candidate)
    inventory = ws.adopt(candidate, sign_all(candidate, candidate.parent / "signed"))
    assert inventory["signed"] is True
    outer = (candidate / "windows/outer/_cfm_lib.ps1").read_bytes()
    nested = (candidate / "windows/runtime/installer/windows/_cfm_lib.ps1").read_bytes()
    assert outer == nested
    assert ws.SIG_BEGIN in outer
    recorded = {row["stream"]: row["signed_sha256"] for row in inventory["streams"]}
    assert recorded["cfm-lib"] == hashlib.sha256(outer).hexdigest()
    assert all(row["signed_sha256"] for row in inventory["streams"])


def test_adoption_refuses_a_member_that_came_back_unsigned(candidate):
    """The failure that looks like success: the signing action skipped a file and exited zero."""
    ws.stage(candidate)
    signed = sign_all(candidate, candidate.parent / "signed",
                      mutate=lambda stream, body, s: body if stream == "runtime-uninstall" else s)
    with pytest.raises(ws.Refusal, match="came back unchanged"):
        ws.adopt(candidate, signed)


def test_adoption_refuses_a_missing_or_an_extra_member(candidate):
    ws.stage(candidate)
    short = sign_all(candidate, candidate.parent / "short",
                     mutate=lambda stream, body, s: None if stream == "outer-install" else s)
    with pytest.raises(ws.Refusal, match="missing"):
        ws.adopt(candidate, short)

    wide = sign_all(candidate, candidate.parent / "wide")
    (wide / "someone-elses.ps1").write_bytes(fake_sign(b"x\r\n", "x"))
    with pytest.raises(ws.Refusal, match="extra"):
        ws.adopt(candidate, wide)


def test_adoption_refuses_a_body_the_signer_rewrote(candidate):
    """Authenticode APPENDS. A signer that also normalized a line ending, re-rendered a placeholder
    or transcoded the file would hand back a script whose behaviour was never reviewed - and whose
    signature would nonetheless verify."""
    ws.stage(candidate)

    def rewrite(stream, body, signed):
        if stream != "runtime-corpusfm-update":
            return signed
        return fake_sign(body.replace(b"corpusfm-update:", b"corpusfm-UPDATE:", 1), stream)

    signed = sign_all(candidate, candidate.parent / "signed", mutate=rewrite)
    with pytest.raises(ws.Refusal, match="outside its signature block"):
        ws.adopt(candidate, signed)


def test_adoption_refuses_when_anything_outside_the_inventory_moved(candidate):
    """The signed members are not the only thing that must not change between approval and build.

    A bundle, an asset payload or a README swapped in after staging would ship inside a package
    whose PowerShell is honestly signed - which reads, to every downstream check, as correct.
    """
    ws.stage(candidate)
    signed = sign_all(candidate, candidate.parent / "signed")
    (candidate / "payload/corpusfm.bundle").write_bytes(b"a different application entirely\n")
    with pytest.raises(ws.Refusal, match="outside the signing inventory changed"):
        ws.adopt(candidate, signed)


def test_a_candidate_cannot_adopt_twice(candidate):
    """Two signing runs are two candidates. Re-adopting would sign a signature block."""
    ws.stage(candidate)
    signed = sign_all(candidate, candidate.parent / "signed")
    ws.adopt(candidate, signed)
    with pytest.raises(ws.Refusal, match="already adopted"):
        ws.adopt(candidate, signed)


# ── property 2, concluded: the finished archives ────────────────────────────────────────────────

def _assemble(candidate: Path, out: Path, tamper=None) -> Path:
    """The shape `package-installer.sh` produces: an outer ZIP carrying a nested runtime ZIP."""
    runtime = out / "installer-runtime.zip"
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(runtime, "w") as zf:
        for member in WINDOWS_RUNTIME_MEMBERS:
            data = (candidate / "windows/runtime" / member).read_bytes()
            if tamper is not None:
                data = tamper(member, data)
            zf.writestr(member, data)
    package = out / f"corpusfm-installer-windows-{VERSION}.zip"
    with zipfile.ZipFile(package, "w") as zf:
        for path in sorted((candidate / "windows/outer").iterdir()):
            data = path.read_bytes()
            if tamper is not None:
                data = tamper(path.name, data)
            zf.writestr(path.name, data)
        zf.writestr("installer-runtime.zip", runtime.read_bytes())
        zf.writestr("corpusfm.bundle", b"bundle\n")
    return package


def test_verification_accepts_the_package_that_was_actually_signed(candidate, tmp_path):
    ws.stage(candidate)
    ws.adopt(candidate, sign_all(candidate, candidate.parent / "signed"))
    package = _assemble(candidate, tmp_path / "release")
    result = ws.verify(candidate, package)
    assert result["signed"] is True
    assert len(result["occurrences"]) == 11


@pytest.mark.parametrize("victim", [
    "install.ps1",                                    # an outer member
    "installer/windows/corpusfm-update.ps1",          # a nested runtime member
])
def test_verification_catches_a_rewrite_after_signing(candidate, tmp_path, victim):
    """THE RULE THE PHASE SPLIT EXISTS FOR (1380-04 section 4).

    A build that signs correctly and then edits a member while assembling passes every check that
    looks at the build ORDER. Only opening the finished archive catches it.
    """
    ws.stage(candidate)
    ws.adopt(candidate, sign_all(candidate, candidate.parent / "signed"))

    def tamper(name, data):
        return data + b"\r\n# one more line\r\n" if name == victim else data

    package = _assemble(candidate, tmp_path / "release", tamper=tamper)
    with pytest.raises(ws.Refusal, match="not the signed"):
        ws.verify(candidate, package)


def test_verification_catches_powershell_smuggled_into_the_finished_package(candidate, tmp_path):
    """An added member is not a rewrite, so the digest checks above would all still pass."""
    ws.stage(candidate)
    ws.adopt(candidate, sign_all(candidate, candidate.parent / "signed"))
    package = _assemble(candidate, tmp_path / "release")
    with zipfile.ZipFile(package, "a") as zf:
        zf.writestr("extra-tool.ps1", "Write-Host 'unsigned'\r\n")
    with pytest.raises(ws.Refusal, match="unsigned PowerShell"):
        ws.verify(candidate, package)


def test_verification_catches_an_unsigned_runtime_bootstrap(candidate, tmp_path):
    """The runtime bootstrap is the installed launcher's source; an unsigned copy must not ship."""
    ws.stage(candidate)
    ws.adopt(candidate, sign_all(candidate, candidate.parent / "signed"))
    unsigned = (ROOT / "installer/bootstrap/windows/bootstrap.ps1").read_bytes()

    def tamper(name, data):
        return unsigned if name == "installer/bootstrap/windows/bootstrap.ps1" else data

    package = _assemble(candidate, tmp_path / "release", tamper=tamper)
    with pytest.raises(ws.Refusal, match="not the signed"):
        ws.verify(candidate, package)


def test_verification_refuses_an_inventory_that_never_recorded_a_digest(candidate, tmp_path):
    """A hand-edited inventory must not be able to make verification vacuous."""
    ws.stage(candidate)
    inventory = ws.read_inventory(candidate)
    inventory["signed"] = True          # claims signed, records no signed digest
    ws._write_inventory(candidate, inventory)
    package = _assemble(candidate, tmp_path / "release")
    with pytest.raises(ws.Refusal, match="no recorded digest"):
        ws.verify(candidate, package)
