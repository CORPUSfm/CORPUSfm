#!/usr/bin/env python3
"""Packet 1380-04 - the Windows signing inventory and the final-byte signing order.

THE ORDER THIS FILE EXISTS TO ENFORCE. `package-installer.sh` used to materialize, assemble and
archive in one pass, which leaves no seam at which an external signer can act. Signing an earlier
representation and then rewriting it is forbidden (1380-04 section 4), so the build is split:

    stage   -> every FINAL Windows byte stream exists on disk, and the 11-occurrence inventory
               is written beside them
    (sign)  -> an external workflow signs and RFC 3161 timestamps each of the 10 DISTINCT
               streams. Nothing in this module reaches Azure.
    adopt   -> the signed bytes replace every occurrence of their stream, and nothing else moves
    (build) -> only now does `package-installer.sh` rebuild the nested runtime ZIP and generate the
               payload digest file, manifest, outer ZIP, sidecar and release.json
    verify  -> the finished archives are opened and every occurrence is proved byte-equal to the
               bytes that were signed

ELEVEN OCCURRENCES, TEN DISTINCT STREAMS. The outer `_cfm_lib.ps1` and the nested runtime's copy
are one library copied twice, so the stream is signed ONCE and those signed bytes are placed in both
positions. Signing it twice would produce two different signature blocks for one library and make an
installed-copy byte-equality claim depend on which copy a reader happened to open.

WHAT IS DELIBERATELY EXCLUDED, and why each exclusion is safe rather than forgotten: tests,
`installer/bridge-exercise/` (never in an ordinary package), every Linux file (the Linux peer stays
unsigned), the Python helpers (not PowerShell, so no execution policy applies to them) and
`corpusfm-recovery-source.zip` (measured PowerShell-free, parent 1380 section 3.2). The completeness
check in `stage` is what keeps that list honest: any `.ps1` that appears under the Windows candidate
trees and is NOT an inventory member fails the build rather than riding into the package unsigned.

NO STANDALONE BOOTSTRAP (public decision D14). The public release publishes no bootstrap outside its
ZIPs, so the closure is exactly the four outer members plus the seven runtime members. The bootstrap
inside the runtime archive - the source of the installed launcher - stays in the closure and is signed.
The two runtime scripts that are shipped but never installed (`corpusfm-proxy.ps1`,
`corpusfm-recovery.ps1`) are signed as package members; that claims nothing about an installed copy.
No public member carries a credential.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

INVENTORY_NAME = "windows-signing-inventory.json"
SIGN_DIRNAME = "sign"

# Authenticode for a PowerShell script APPENDS a comment block. That is what makes the
# "the signer did not rewrite the body" check in `adopt` possible at all.
SIG_BEGIN = b"# SIG # Begin signature block"


@dataclass(frozen=True)
class Occurrence:
    """One position in the shipped Windows package that must hold signed PowerShell."""

    ordinal: int
    stream: str
    path: str          # candidate-relative
    location: str      # outer | runtime


# The public closure (parent 1380 section 3.2): the outer ZIP holds exactly `install.ps1`,
# `_cfm_lib.ps1`, `cfm-verify-installer-bundle.ps1` and `cfm-verify-bootstrap-handoff.ps1`, and the
# nested runtime holds seven PowerShell members. D14 excludes the standalone bootstrap, so the table
# below is 11 occurrences over 10 distinct streams.
OCCURRENCES: tuple[Occurrence, ...] = (
    Occurrence(1, "outer-install",
               "windows/outer/install.ps1", "outer"),
    Occurrence(2, "cfm-lib",
               "windows/outer/_cfm_lib.ps1", "outer"),
    Occurrence(3, "outer-verify-installer-bundle",
               "windows/outer/cfm-verify-installer-bundle.ps1", "outer"),
    Occurrence(4, "outer-verify-bootstrap-handoff",
               "windows/outer/cfm-verify-bootstrap-handoff.ps1", "outer"),
    Occurrence(5, "cfm-lib",
               "windows/runtime/installer/windows/_cfm_lib.ps1", "runtime"),
    Occurrence(6, "runtime-cfm-proxy-exec",
               "windows/runtime/installer/windows/cfm-proxy-exec.ps1", "runtime"),
    Occurrence(7, "runtime-corpusfm-proxy",
               "windows/runtime/installer/windows/corpusfm-proxy.ps1", "runtime"),
    Occurrence(8, "runtime-corpusfm-recovery",
               "windows/runtime/installer/windows/corpusfm-recovery.ps1", "runtime"),
    Occurrence(9, "runtime-corpusfm-update",
               "windows/runtime/installer/windows/corpusfm-update.ps1", "runtime"),
    Occurrence(10, "runtime-uninstall",
               "windows/runtime/installer/windows/uninstall.ps1", "runtime"),
    Occurrence(11, "runtime-bootstrap",
               "windows/runtime/installer/bootstrap/windows/bootstrap.ps1", "runtime"),
)

EXPECTED_OCCURRENCES = 11
EXPECTED_DISTINCT_STREAMS = 10

# Trees searched for stray PowerShell. The Linux trees are not searched: they hold no `.ps1` and the
# Linux peer is deliberately unsigned.
WINDOWS_TREES = ("windows",)

# Everything the candidate carries that is not a signing subject. Digested at `stage` and re-digested
# at `adopt`, so a signer that touched anything outside its catalog is caught at the build and not at
# a live gate.
NON_SIGNABLE_TREES = ("windows", "linux", "payload")

# Candidate files that sit at the ROOT rather than inside a tree, and are therefore invisible to the
# walk above. `candidate.json` is one of them, and it is not inert metadata: finalization reads its
# `executable_outer` / `executable_runtime` records to decide which shipped members get mode 0755.
# Left unsealed, editing that one file - and nothing else - made finalization ship `_cfm_lib.sh`
# executable and exit 0 (Codex review, packet 1380-04). It is written before `stage` runs, so its
# digest belongs in the same record as everything else the signer must not touch.
NON_SIGNABLE_ROOT_FILES = ("candidate.json",)


class Refusal(RuntimeError):
    """A stop condition. Never a warning: every caller of this module is building a release."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _refuse(message: str) -> None:
    raise Refusal(message)


def _require_file(path: Path, what: str) -> bytes:
    if not path.is_file():
        _refuse(f"{what} is missing at {path}")
    return path.read_bytes()


def _assert_ascii_without_bom(name: str, data: bytes) -> None:
    """1380-01 constraint 6, kept as a build assertion (parent 1380 section 3.2 measured it clean).

    A signature over a differently shaped file is a signature over a different experiment. Encoding
    is checked BEFORE signing because afterwards the only fix would be a post-signing rewrite.
    """
    if data[:3] == b"\xef\xbb\xbf":
        _refuse(f"{name} carries a UTF-8 BOM")
    for byte in data:
        if byte > 0x7F:
            _refuse(f"{name} is not ASCII")


def strip_signature_block(data: bytes) -> bytes:
    """The script body, with any appended Authenticode comment block removed."""
    index = data.find(SIG_BEGIN)
    return data if index < 0 else data[:index]


def _stream_file(candidate: Path, stream: str) -> Path:
    return candidate / SIGN_DIRNAME / f"{stream}.ps1"


def _non_signable_manifest(candidate: Path, signable: set[str]) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for name in NON_SIGNABLE_ROOT_FILES:
        path = candidate / name
        if path.is_file():
            manifest[name] = _sha256(path.read_bytes())
    for tree in NON_SIGNABLE_TREES:
        root = candidate / tree
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(candidate).as_posix()
            if relative in signable:
                continue
            manifest[relative] = _sha256(path.read_bytes())
    return manifest


def _table_self_check() -> None:
    """The table is the packet's closure. A future edit may widen it only deliberately."""
    if len(OCCURRENCES) != EXPECTED_OCCURRENCES:
        _refuse(f"the occurrence table holds {len(OCCURRENCES)}, not {EXPECTED_OCCURRENCES}")
    streams = {occurrence.stream for occurrence in OCCURRENCES}
    if len(streams) != EXPECTED_DISTINCT_STREAMS:
        _refuse(f"the occurrence table holds {len(streams)} distinct streams, "
                f"not {EXPECTED_DISTINCT_STREAMS}")
    if len({occurrence.ordinal for occurrence in OCCURRENCES}) != len(OCCURRENCES):
        _refuse("the occurrence table repeats an ordinal")
    if len({occurrence.path for occurrence in OCCURRENCES}) != len(OCCURRENCES):
        _refuse("the occurrence table repeats a path")


def stage(candidate: Path) -> dict:
    """Build the inventory from the FINAL materialized members and publish the signing set."""
    _table_self_check()
    signable = {occurrence.path for occurrence in OCCURRENCES}

    bodies: dict[str, bytes] = {}
    for occurrence in OCCURRENCES:
        data = _require_file(candidate / occurrence.path,
                             f"inventory member {occurrence.ordinal}")
        _assert_ascii_without_bom(occurrence.path, data)
        if occurrence.stream in bodies and bodies[occurrence.stream] != data:
            # Items 2 and 5 are one library copied twice. If they ever diverge, signing one stream
            # and placing it in both positions would ship a file nobody wrote.
            _refuse(f"occurrences of stream {occurrence.stream} are not byte-identical")
        bodies[occurrence.stream] = data

    # COMPLETENESS. The inventory is a closed list, so the only thing that keeps it complete is an
    # unlisted PowerShell file under the Windows candidate trees failing the build.
    for tree in WINDOWS_TREES:
        root = candidate / tree
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.ps1")):
            relative = path.relative_to(candidate).as_posix()
            if relative not in signable:
                _refuse(f"{relative} is PowerShell in the Windows package and is not in the "
                        "signing inventory")

    sign_dir = candidate / SIGN_DIRNAME
    sign_dir.mkdir(parents=True, exist_ok=True)
    for stream, data in bodies.items():
        _stream_file(candidate, stream).write_bytes(data)

    inventory = {
        "schema_version": 1,
        "signed": False,
        "occurrence_count": len(OCCURRENCES),
        "distinct_stream_count": len(bodies),
        "streams": [
            {
                "stream": stream,
                "file": f"{stream}.ps1",
                "unsigned_sha256": _sha256(bodies[stream]),
                "signed_sha256": None,
                "occurrences": [
                    {
                        "ordinal": occurrence.ordinal,
                        "path": occurrence.path,
                        "location": occurrence.location,
                    }
                    for occurrence in OCCURRENCES if occurrence.stream == stream
                ],
            }
            for stream in sorted(bodies)
        ],
        "non_signable_sha256": _non_signable_manifest(candidate, signable),
    }
    _write_inventory(candidate, inventory)
    return inventory


def _write_inventory(candidate: Path, inventory: dict) -> None:
    (candidate / INVENTORY_NAME).write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def read_inventory(candidate: Path) -> dict:
    inventory = json.loads(_require_file(candidate / INVENTORY_NAME, "the signing inventory"))
    if inventory.get("schema_version") != 1:
        _refuse("the signing inventory is not schema 1")
    if inventory.get("occurrence_count") != EXPECTED_OCCURRENCES:
        _refuse(f"the signing inventory records {inventory.get('occurrence_count')} occurrences, "
                f"not {EXPECTED_OCCURRENCES}")
    if inventory.get("distinct_stream_count") != EXPECTED_DISTINCT_STREAMS:
        _refuse(f"the signing inventory records "
                f"{inventory.get('distinct_stream_count')} distinct streams, "
                f"not {EXPECTED_DISTINCT_STREAMS}")
    return inventory


def adopt(candidate: Path, signed_dir: Path) -> dict:
    """Place the externally signed bytes into every occurrence of their stream."""
    inventory = read_inventory(candidate)
    if inventory.get("signed"):
        _refuse("this candidate has already adopted signed members")

    expected_files = {row["file"] for row in inventory["streams"]}
    actual_files = {path.name for path in sorted(signed_dir.glob("*.ps1"))}
    # EXACT, in both directions. A missing member is an occurrence that would ship unsigned; an
    # extra one means the signing job operated on a set this candidate never described.
    if expected_files != actual_files:
        missing = sorted(expected_files - actual_files)
        extra = sorted(actual_files - expected_files)
        _refuse(f"the signed set does not match the inventory (missing: {missing}; extra: {extra})")

    for row in inventory["streams"]:
        unsigned = _require_file(_stream_file(candidate, row["stream"]), "the staged stream")
        if _sha256(unsigned) != row["unsigned_sha256"]:
            _refuse(f"the staged stream {row['stream']} no longer matches its recorded digest")

        signed = _require_file(signed_dir / row["file"], f"signed stream {row['stream']}")
        if signed == unsigned:
            _refuse(f"{row['file']} came back unchanged; it carries no signature")
        if SIG_BEGIN not in signed:
            _refuse(f"{row['file']} carries no Authenticode signature block")
        # THE BODY MUST BE UNTOUCHED. Authenticode appends; it does not rewrite. A signer that
        # normalized encoding, rewrote a line ending or re-rendered a placeholder would produce a
        # package whose behaviour is not the behaviour that was reviewed.
        if strip_signature_block(signed).rstrip(b"\r\n") != unsigned.rstrip(b"\r\n"):
            _refuse(f"{row['file']} differs from the staged bytes outside its signature block")

        row["signed_sha256"] = _sha256(signed)
        for occurrence in row["occurrences"]:
            (candidate / occurrence["path"]).write_bytes(signed)

    # Nothing outside the inventory may have moved between staging and adoption.
    signable = {occurrence.path for occurrence in OCCURRENCES}
    now = _non_signable_manifest(candidate, signable)
    if now != inventory["non_signable_sha256"]:
        recorded = inventory["non_signable_sha256"]
        changed = sorted(set(now) ^ set(recorded)) or sorted(
            name for name, digest in now.items() if recorded.get(name) != digest
        )
        _refuse(f"candidate content outside the signing inventory changed: {changed}")

    inventory["signed"] = True
    _write_inventory(candidate, inventory)
    return inventory


def expected_digests(inventory: dict) -> dict[str, str]:
    """occurrence path -> the digest the finished package must carry at that position."""
    signed = bool(inventory.get("signed"))
    mapping: dict[str, str] = {}
    for row in inventory["streams"]:
        digest = row["signed_sha256"] if signed else row["unsigned_sha256"]
        if not digest:
            _refuse(f"stream {row['stream']} has no recorded digest to verify against")
        for occurrence in row["occurrences"]:
            mapping[occurrence["path"]] = digest
    return mapping


def package_member_name(path: str) -> str:
    """Where a candidate-relative occurrence lands inside the shipped archives."""
    if path.startswith("windows/outer/"):
        return path[len("windows/outer/"):]
    if path.startswith("windows/runtime/"):
        return path[len("windows/runtime/"):]
    _refuse(f"{path} is not a packaged occurrence")
    raise AssertionError("unreachable")


def assert_records_sealed(candidate: Path) -> dict[str, str]:
    """Prove the candidate's own root records are the ones `stage` digested.

    Finalization reads `candidate.json` to decide which shipped members get mode 0755, so that file
    is an AUTHORITY, not a note. `adopt` re-digests the non-signable set, but the unsigned
    development path never calls `adopt` - and both paths reach the executable records. This check
    therefore runs on every finalization, before those records are used, and it covers only the root
    files: the trees legitimately change under `adopt`, which is why that comparison stays there.
    """
    inventory = read_inventory(candidate)
    recorded = inventory.get("non_signable_sha256") or {}
    checked: dict[str, str] = {}
    for name in NON_SIGNABLE_ROOT_FILES:
        path = candidate / name
        if name not in recorded:
            _refuse(f"{name} carries no staged digest; this candidate predates the record seal")
        if not path.is_file():
            _refuse(f"{name} was digested at staging and is missing now")
        digest = _sha256(path.read_bytes())
        if digest != recorded[name]:
            _refuse(f"{name} changed after staging (recorded {recorded[name]}, found {digest})")
        checked[name] = digest
    return checked


def verify(candidate: Path, package: Path) -> dict:
    """Open the FINISHED archives and prove every occurrence is the byte stream that was signed.

    This is the point of the phase split. A build that signed correctly and then rewrote a member
    while assembling would pass every earlier check and fail here.
    """
    inventory = read_inventory(candidate)
    wanted = expected_digests(inventory)
    state = "signed" if inventory["signed"] else "staged"
    report: dict[str, dict] = {}

    with zipfile.ZipFile(package) as outer:
        outer_names = set(outer.namelist())
        if "installer-runtime.zip" not in outer_names:
            _refuse("the package carries no installer-runtime.zip")
        with zipfile.ZipFile(io.BytesIO(outer.read("installer-runtime.zip"))) as runtime:
            runtime_names = set(runtime.namelist())
            for occurrence in OCCURRENCES:
                member = package_member_name(occurrence.path)
                if occurrence.location == "outer":
                    if member not in outer_names:
                        _refuse(f"the outer ZIP carries no {member}")
                    data = outer.read(member)
                else:
                    if member not in runtime_names:
                        _refuse(f"installer-runtime.zip carries no {member}")
                    data = runtime.read(member)
                digest = _sha256(data)
                if digest != wanted[occurrence.path]:
                    _refuse(f"occurrence {occurrence.ordinal} ({member}) is {digest}, "
                            f"not the {state} {wanted[occurrence.path]}")
                report[occurrence.path] = {"member": member, "sha256": digest}

            # Every PowerShell member of either archive must be an inventory occurrence. A file
            # added to the package after staging would otherwise ship unsigned and unnoticed.
            for names, location in ((outer_names, "outer"), (runtime_names, "runtime")):
                allowed = {package_member_name(o.path) for o in OCCURRENCES
                           if o.location == location}
                for name in sorted(names):
                    if name.lower().endswith(".ps1") and name not in allowed:
                        where = "the outer ZIP" if location == "outer" else "installer-runtime.zip"
                        _refuse(f"{where} carries unsigned PowerShell {name}")

    return {"signed": inventory["signed"], "occurrences": report}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Windows signing inventory (public closure)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_stage = sub.add_parser("stage", help="write the inventory and the signing set")
    p_stage.add_argument("--candidate", required=True, type=Path)

    p_adopt = sub.add_parser("adopt", help="place signed bytes into every occurrence")
    p_adopt.add_argument("--candidate", required=True, type=Path)
    p_adopt.add_argument("--signed", required=True, type=Path)

    p_sealed = sub.add_parser("assert-records-sealed",
                              help="prove candidate.json is the one staging digested")
    p_sealed.add_argument("--candidate", required=True, type=Path)

    p_verify = sub.add_parser("verify", help="prove the finished archives carry the signed bytes")
    p_verify.add_argument("--candidate", required=True, type=Path)
    p_verify.add_argument("--package", required=True, type=Path)
    p_verify.add_argument("--report", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            inventory = stage(args.candidate)
            print(f"  + windows signing inventory: {inventory['occurrence_count']} occurrences, "
                  f"{inventory['distinct_stream_count']} distinct streams")
        elif args.command == "assert-records-sealed":
            checked = assert_records_sealed(args.candidate)
            print(f"  + candidate records sealed: {', '.join(sorted(checked))}")
        elif args.command == "adopt":
            inventory = adopt(args.candidate, args.signed)
            print(f"  + adopted {inventory['distinct_stream_count']} signed streams into "
                  f"{inventory['occurrence_count']} occurrences")
        else:
            result = verify(args.candidate, args.package)
            if args.report:
                args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                       encoding="utf-8")
            state = "signed" if result["signed"] else "unsigned"
            print(f"  + verified {len(result['occurrences'])} {state} occurrences in "
                  f"{args.package.name}")
    except Refusal as refusal:
        print(f"Refusing: {refusal}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
