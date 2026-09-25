#!/usr/bin/env python3
"""Derive the public download page's release-trust overlay from one verified signing run.

Packet 1380-03. The committed ``site/src/release-trust.ts`` stays ``null``; this produces the
overlay text and the exact trust bytes for a later, separately approved scratch build. It copies
and digests; it never signs, verifies a certificate, contacts anything, or writes into the
repository. Staging requires a FRESH output directory that does not exist yet — see ``stage``.

The caller supplies the digests the signing run itself published as job outputs. Those are the
binding: a file is believed only because it hashes to a value that came from outside this command.
A digest computed from a supplied file is never treated as an expectation about that file.

This helper PRESERVES a binding the operator already established by reviewing the independent
Windows verification for this exact run. It does not establish that the verification happened and
grants no permission to publish.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent

#: The public repository the download page links to. The release URL is the impending tag, which is
#: knowable before publication; the two trust URLs are deliberately SITE paths, because Gate 4 step 1
#: needs them anonymously reachable BEFORE the packages become visible.
PUBLIC_REPOSITORY_URL = "https://github.com/CORPUSfm/CORPUSfm"
SITE_TRUST_DIRECTORY = "trust"

#: `site/src/release-trust.ts` declares exactly these, in this order. The test parses that file and
#: asserts this tuple equals it, so a field added to the type without being derived here fails.
RELEASE_TRUST_FIELDS = (
    "version", "releaseUrl", "installerAsset", "signerThumbprint",
    "certificateAsset", "certificateUrl", "trustRecordAsset", "trustRecordUrl",
)

#: `sign-windows-release.yml` emits the publisher trust record with exactly these keys and NO
#: version. Asserting the whole set makes a producer change loud instead of a silent partial read.
TRUST_RECORD_KEYS = frozenset((
    "schema_version", "kind", "signer_subject", "signer_thumbprint", "signer_issuer",
    "signer_not_before", "signer_not_after", "code_signing_eku", "required_store",
    "run_id", "run_commit", "signature_report_sha256", "leaf_der_sha256",
))

SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA1_THUMBPRINT = re.compile(r"^[0-9A-Fa-f]{40}$")
RUN_ID = re.compile(r"^[0-9]+$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^0\.[0-9]+$")
SERIES = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MANIFEST_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


class Refusal(RuntimeError):
    """A binding, schema or naming precondition did not hold."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bytes(path: Path, what: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise Refusal(f"{what} is not a plain file: {path}")
    return path.read_bytes()


def read_json_bytes(data: bytes, what: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"{what} is not readable JSON: {exc}") from None
    if not isinstance(value, dict):
        raise Refusal(f"{what} is not a JSON object")
    return value


def expect_digest(value: str, option: str) -> str:
    if not SHA256.fullmatch(value):
        raise Refusal(f"{option} is not a lowercase SHA-256 hex digest")
    return value


def bind(data: bytes, expected: str, what: str) -> bytes:
    """Believe `data` only because it hashes to a digest supplied from outside this command."""
    measured = sha256_bytes(data)
    if measured != expected:
        raise Refusal(f"{what} hashes to {measured}, not the expected {expected}")
    return data


def sidecar_line(name: str, digest: str) -> str:
    return f"{digest}  {name}\n"


class Manifest:
    """`finalized-manifest.json`, believed only after it hashes to the finalize job's output.

    Every other file is then addressed BY ITS MANIFEST PATH. A file that is present on disk but
    absent from the manifest is not part of what was finalized, so reading it would be reading
    something nothing verified.
    """

    def __init__(self, data: bytes, expected_sha256: str, run_id: str, run_commit: str):
        bind(data, expected_sha256, "the finalized manifest")
        body = read_json_bytes(data, "the finalized manifest")
        if body.get("kind") != "finalized-review-manifest":
            raise Refusal(f"the finalized manifest kind is {body.get('kind')!r}")
        self.run_id = str(body.get("run_id", ""))
        self.run_commit = str(body.get("run_commit", ""))
        if self.run_id != run_id:
            raise Refusal(f"the finalized manifest names run {self.run_id!r}, not {run_id!r}")
        if self.run_commit != run_commit:
            raise Refusal(
                f"the finalized manifest names commit {self.run_commit!r}, not {run_commit!r}")
        self.version = str(body.get("installer_version", ""))
        self.series = str(body.get("installer_series", ""))
        if not VERSION.fullmatch(self.version):
            raise Refusal(f"the finalized manifest names an unsafe version: {self.version!r}")
        if not SERIES.fullmatch(self.series):
            raise Refusal(f"the finalized manifest names an unsafe series: {self.series!r}")
        self.signature_report_sha256 = str(body.get("signature_report_sha256", ""))
        windows_package = str(body.get("windows_package", ""))
        if not MANIFEST_PATH.fullmatch(windows_package) or "/" not in windows_package:
            raise Refusal(f"the finalized manifest names no Windows package path: {windows_package!r}")
        self.release_prefix = windows_package.rsplit("/", 1)[0] + "/"
        rows = body.get("files")
        if not isinstance(rows, list) or not rows:
            raise Refusal("the finalized manifest inventories no files")
        self.digests: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise Refusal("the finalized manifest carries a non-object file row")
            path, digest = str(row.get("path", "")), str(row.get("sha256", ""))
            if not MANIFEST_PATH.fullmatch(path) or ".." in path or "//" in path:
                raise Refusal(f"the finalized manifest carries an unsafe path: {path!r}")
            if not SHA256.fullmatch(digest):
                raise Refusal(f"the finalized manifest records no digest for {path}")
            if path in self.digests:
                raise Refusal(f"the finalized manifest lists {path} twice")
            self.digests[path] = digest

    def digest_of(self, manifest_path: str, what: str) -> str:
        digest = self.digests.get(manifest_path)
        if digest is None:
            raise Refusal(f"{what} is absent from the finalized manifest: {manifest_path}")
        return digest

    def release_member(self, name: str, what: str) -> str:
        return self.digest_of(self.release_prefix + name, what)


def load_signature_report(data: bytes, expected: str, run_id: str, run_commit: str) -> dict[str, Any]:
    bind(data, expected, "the signature report")
    report = read_json_bytes(data, "the signature report")
    if report.get("verdict") != "pass":
        raise Refusal(f"the signature report verdict is {report.get('verdict')!r}, not 'pass'")
    failures = report.get("failures")
    if not isinstance(failures, list) or failures:
        raise Refusal("the signature report records failures")
    if str(report.get("run_id", "")) != run_id:
        raise Refusal(f"the signature report names run {report.get('run_id')!r}, not {run_id!r}")
    if str(report.get("run_commit", "")) != run_commit:
        raise Refusal(
            f"the signature report names commit {report.get('run_commit')!r}, not {run_commit!r}")
    return report


def load_trust_record(data: bytes, expected: str, report_sha256: str,
                      run_id: str, run_commit: str) -> dict[str, Any]:
    bind(data, expected, "the publisher trust record")
    trust = read_json_bytes(data, "the publisher trust record")
    if set(trust) != set(TRUST_RECORD_KEYS):
        missing = sorted(TRUST_RECORD_KEYS - set(trust))
        extra = sorted(set(trust) - TRUST_RECORD_KEYS)
        raise Refusal(
            f"the publisher trust record key set changed (missing {missing}, unexpected {extra})")
    if trust.get("kind") != "publisher-trust-record":
        raise Refusal(f"the publisher trust record kind is {trust.get('kind')!r}")
    if str(trust.get("signature_report_sha256", "")) != report_sha256:
        raise Refusal("the publisher trust record describes another signature report")
    if str(trust.get("run_id", "")) != run_id:
        raise Refusal(f"the publisher trust record names run {trust.get('run_id')!r}, not {run_id!r}")
    if str(trust.get("run_commit", "")) != run_commit:
        raise Refusal(
            f"the publisher trust record names commit {trust.get('run_commit')!r}, not {run_commit!r}")
    return trust


def load_release_manifest(data: bytes, expected: str, version: str, series: str) -> dict[str, Any]:
    bind(data, expected, "release.json against the finalized manifest")
    body = read_json_bytes(data, "release.json")
    if str(body.get("installer_version", "")) != version:
        raise Refusal(
            f"release.json names version {body.get('installer_version')!r}, "
            f"not the finalized manifest's {version!r}")
    if str(body.get("installer_series", "")) != series:
        raise Refusal(
            f"release.json names series {body.get('installer_series')!r}, "
            f"not the finalized manifest's {series!r}")
    platforms = body.get("platforms")
    if not isinstance(platforms, dict) or not isinstance(platforms.get("windows"), dict):
        raise Refusal("release.json inventories no Windows platform")
    filename = str(platforms["windows"].get("file", ""))
    if filename != f"corpusfm-installer-windows-{version}.zip":
        raise Refusal(f"release.json names an unexpected Windows asset: {filename!r}")
    return body


def thumbprint_of(trust: dict[str, Any]) -> str:
    """The record's own value, used verbatim, exactly as `finalize` derives the leaf filename.

    Uppercase is required rather than normalized to: the producer emits an uppercase .NET
    thumbprint, so a lowercase value means the producer changed and should fail loudly here
    instead of deriving a filename that is not the one on disk.
    """
    value = str(trust.get("signer_thumbprint", ""))
    if not SHA1_THUMBPRINT.fullmatch(value):
        raise Refusal(f"the publisher trust record carries no SHA-1 leaf thumbprint: {value!r}")
    if value != value.upper():
        raise Refusal(f"the leaf thumbprint is not the producer's uppercase form: {value!r}")
    return value


#: These two carry a path RELATIVE TO THE SITE ROOT, not an absolute URL, and are rendered against
#: Vite's BASE_URL in the generated module. Everything else is emitted as a plain string literal.
SITE_RELATIVE_FIELDS = ("certificateUrl", "trustRecordUrl")


def render_module(values: dict[str, str]) -> str:
    if tuple(values) != RELEASE_TRUST_FIELDS:
        raise Refusal("the derived field set is not the declared ReleaseTrust field set")
    declaration = "\n".join(f"  {name}: string;" for name in RELEASE_TRUST_FIELDS)
    literal = "\n".join(
        (f"  {name}: `${{siteBase}}{values[name]}`,"
         if name in SITE_RELATIVE_FIELDS
         else f"  {name}: {json.dumps(values[name])},")
        for name in RELEASE_TRUST_FIELDS
    )
    return (
        "// GENERATED by tools/release_trust_overlay.py from ONE verified signing run (packet\n"
        "// 1380-03). Do not hand-edit and do not commit: the checked-in module stays null, and this\n"
        "// overlay is applied only to a scratch build of the frozen candidate.\n"
        "//\n"
        "// The two trust URLs are SITE paths, not release-asset URLs, because the trust record and\n"
        "// the certificate must be anonymously reachable BEFORE the packages become visible.\n"
        "export type ReleaseTrust = {\n"
        f"{declaration}\n"
        "};\n"
        "\n"
        "const siteBase = import.meta.env.BASE_URL;\n"
        "\n"
        "export const releaseTrust: ReleaseTrust | null = {\n"
        f"{literal}\n"
        "};\n"
    )


class Overlay:
    def __init__(self, module_text: str, values: dict[str, str], assets: dict[str, bytes],
                 run_id: str, run_commit: str, version: str):
        self.module_text = module_text
        self.values = values
        self.assets = assets
        self.run_id = run_id
        self.run_commit = run_commit
        self.version = version

    def record(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "release-trust-overlay",
            "installer_version": self.version,
            "run_id": self.run_id,
            "run_commit": self.run_commit,
            "release_trust": dict(self.values),
            "site_relative_fields": list(SITE_RELATIVE_FIELDS),
            "site_trust_directory": SITE_TRUST_DIRECTORY,
            "staged": {name: sha256_bytes(data) for name, data in sorted(self.assets.items())},
        }


def derive(release_dir: Path, signature_report: Path, finalized_manifest: Path, *,
           expect_trust_record_sha256: str, expect_signature_report_sha256: str,
           expect_finalized_manifest_sha256: str, expect_run_id: str,
           expect_run_commit: str) -> Overlay:
    if not RUN_ID.fullmatch(expect_run_id):
        raise Refusal("--expect-run-id is not a run number")
    if not COMMIT.fullmatch(expect_run_commit):
        raise Refusal("--expect-run-commit is not a lowercase 40-hex commit")
    trust_digest = expect_digest(expect_trust_record_sha256, "--expect-trust-record-sha256")
    report_digest = expect_digest(expect_signature_report_sha256, "--expect-signature-report-sha256")
    manifest_digest = expect_digest(
        expect_finalized_manifest_sha256, "--expect-finalized-manifest-sha256")
    if not release_dir.is_dir() or release_dir.is_symlink():
        raise Refusal(f"the release directory is not a plain directory: {release_dir}")

    manifest = Manifest(
        read_bytes(finalized_manifest, "the finalized manifest"),
        manifest_digest, expect_run_id, expect_run_commit)
    if manifest.signature_report_sha256 != report_digest:
        raise Refusal("the finalized manifest describes another signature report")

    report_bytes = read_bytes(signature_report, "the signature report")
    bind(report_bytes, manifest.digest_of("signature-report.json", "the signature report"),
         "the signature report against the finalized manifest")
    load_signature_report(report_bytes, report_digest, expect_run_id, expect_run_commit)

    version, series = manifest.version, manifest.series
    trust_asset = f"corpusfm-installer-windows-{version}.trust.json"
    trust_bytes = read_bytes(release_dir / trust_asset, "the publisher trust record")
    bind(trust_bytes, manifest.release_member(trust_asset, "the publisher trust record"),
         "the publisher trust record against the finalized manifest")
    trust = load_trust_record(trust_bytes, trust_digest, report_digest,
                              expect_run_id, expect_run_commit)

    release_bytes = read_bytes(release_dir / "release.json", "release.json")
    release = load_release_manifest(
        release_bytes, manifest.release_member("release.json", "release.json"), version, series)

    thumbprint = thumbprint_of(trust)
    certificate_asset = f"corpusfm-signing-leaf-{thumbprint}.cer"
    leaf_bytes = read_bytes(release_dir / certificate_asset, "the signing leaf")
    bind(leaf_bytes, manifest.release_member(certificate_asset, "the signing leaf"),
         "the signing leaf against the finalized manifest")
    leaf_declared = str(trust.get("leaf_der_sha256", ""))
    if not SHA256.fullmatch(leaf_declared):
        raise Refusal(f"the publisher trust record carries no SHA-256 leaf digest: {leaf_declared!r}")
    bind(leaf_bytes, leaf_declared, "the signing leaf against the trust record")

    assets: dict[str, bytes] = {trust_asset: trust_bytes, certificate_asset: leaf_bytes}
    for name, data in dict(assets).items():
        sidecar_name = name + ".sha256"
        sidecar_bytes = read_bytes(release_dir / sidecar_name, sidecar_name)
        bind(sidecar_bytes, manifest.release_member(sidecar_name, sidecar_name),
             f"{sidecar_name} against the finalized manifest")
        expected_line = sidecar_line(name, sha256_bytes(data))
        if sidecar_bytes.decode("ascii", "replace") != expected_line:
            raise Refusal(f"{sidecar_name} does not describe {name}")
        assets[sidecar_name] = sidecar_bytes

    values = {
        "version": version,
        "releaseUrl": f"{PUBLIC_REPOSITORY_URL}/releases/tag/v{version}",
        "installerAsset": str(release["platforms"]["windows"]["file"]),
        "signerThumbprint": thumbprint,
        "certificateAsset": certificate_asset,
        "certificateUrl": f"{SITE_TRUST_DIRECTORY}/{certificate_asset}",
        "trustRecordAsset": trust_asset,
        "trustRecordUrl": f"{SITE_TRUST_DIRECTORY}/{trust_asset}",
    }
    return Overlay(render_module(values), values, assets, expect_run_id, expect_run_commit, version)


def assert_outside_repository(output_dir: Path) -> Path:
    """Decide the repository question with no I/O, so a test can exercise it without risking a write.

    Folded into `stage` this was only checkable by calling `stage` on a repository path — which
    writes into the repository the moment the rule regresses. A test must not be able to do that.
    """
    resolved = output_dir.expanduser().resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise Refusal(f"--output-dir may not be inside the repository: {resolved}")
    return resolved


def stage(overlay: Overlay, output_dir: Path) -> list[Path]:
    """Write the overlay and byte-for-byte copies into a FRESH directory this call creates.

    `--output-dir` must not exist. That is the whole rule, and it is what makes the destination
    safe: checking the output root and then writing under it is not enough, because a pre-existing
    `trust/` SYMLINK inside the output directory redirects the write somewhere else entirely — a
    repository, say — while the root itself passed. Refusing an existing path removes the case
    instead of trying to out-check it: every directory written here was created by this call, so
    nothing on the way to a file is a link someone else placed.
    """
    resolved = assert_outside_repository(output_dir)
    if output_dir.expanduser().is_symlink() or resolved.exists() or resolved.is_symlink():
        raise Refusal(
            f"--output-dir must be a fresh directory that does not exist yet: {resolved}")
    targets = {
        resolved / "release-trust.ts": overlay.module_text.encode("utf-8"),
        resolved / "overlay-record.json":
            (json.dumps(overlay.record(), indent=2, sort_keys=True) + "\n").encode("utf-8"),
    }
    for name, data in overlay.assets.items():
        if name != Path(name).name or name in {"", ".", ".."}:
            raise Refusal(f"a staged asset name is not a plain filename: {name!r}")
        targets[resolved / SITE_TRUST_DIRECTORY / name] = data
    resolved.mkdir(parents=True)
    (resolved / SITE_TRUST_DIRECTORY).mkdir()
    for path, data in targets.items():
        path.write_bytes(data)
        if path.read_bytes() != data:
            raise Refusal(f"{path.name} is not the bytes it was written from")
    return sorted(targets)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True)
    parser.add_argument("--signature-report", required=True)
    parser.add_argument("--finalized-manifest", required=True)
    parser.add_argument("--expect-trust-record-sha256", required=True)
    parser.add_argument("--expect-signature-report-sha256", required=True)
    parser.add_argument("--expect-finalized-manifest-sha256", required=True)
    parser.add_argument("--expect-run-id", required=True)
    parser.add_argument("--expect-run-commit", required=True)
    parser.add_argument("--output-dir", default="",
                        help="a FRESH directory, created by this command, to stage the overlay and "
                             "byte copies into; it must not already exist. Prints a plan when omitted")
    args = parser.parse_args()
    try:
        overlay = derive(
            Path(args.release_dir).expanduser(), Path(args.signature_report).expanduser(),
            Path(args.finalized_manifest).expanduser(),
            expect_trust_record_sha256=args.expect_trust_record_sha256,
            expect_signature_report_sha256=args.expect_signature_report_sha256,
            expect_finalized_manifest_sha256=args.expect_finalized_manifest_sha256,
            expect_run_id=args.expect_run_id, expect_run_commit=args.expect_run_commit)
    except (Refusal, OSError) as exc:
        print(f"REFUSED: {exc}")
        return 2
    print(overlay.module_text, end="")
    if not args.output_dir:
        print(f"\nPLAN only. Would stage under {SITE_TRUST_DIRECTORY}/:")
        for name, data in sorted(overlay.assets.items()):
            print(f"  {name}  {sha256_bytes(data)}")
        print("Pass --output-dir to write them. This command publishes and deploys nothing.")
        return 0
    try:
        written = stage(overlay, Path(args.output_dir).expanduser())
    except (Refusal, OSError) as exc:
        print(f"REFUSED: {exc}")
        return 2
    print(f"\nStaged {len(written)} files:")
    for path in written:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
