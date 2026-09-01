"""Packet 1374: a published update cannot renegotiate its installed locations."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LINUX = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")
WINDOWS = (ROOT / "installer/windows/install.ps1").read_text(encoding="utf-8")


def _location_block() -> str:
    start = LINUX.index("printf '  Installation locations (resolved before acquisition):")
    end = LINUX.index("# A bad local clock can make TLS", start)
    return LINUX[start:end]


def test_a_published_update_treats_locations_as_authority_not_a_question():
    block = _location_block()
    published = block.index('if [[ "$PREEXISTING_STATE" == published ]]; then',
                            block.index("FMS recognition:"))
    fixed = block.index("Published installation locations are authoritative", published)
    interactive = block.index("elif ! $SILENT && ! $ASSUME_YES", fixed)
    question = block.index("Use these locations?", interactive)
    assert published < fixed < interactive < question


def test_the_fresh_interactive_route_keeps_its_question_and_safe_decline():
    block = _location_block()
    assert "Use these locations? [y/N]" in block
    assert "Declined before acquisition; nothing has been changed." in block
    assert "read -r _location_answer" in block


def test_silent_and_assume_yes_remain_noninteractive():
    block = _location_block()
    assert "elif ! $SILENT && ! $ASSUME_YES; then" in block


def test_published_and_live_fms_mismatches_still_refuse_before_the_block():
    before = LINUX[: LINUX.index("printf '  Installation locations (resolved before acquisition):")]
    assert "Published CORPUSfm root is" in before
    assert "Published FileMaker Server root is" in before
    assert "Published apply-compartment folder is" in before
    assert "Active fmsadmin resolves under" in before
    assert before.count("Nothing has been acquired or changed.") >= 4


def test_windows_has_no_separate_location_confirmation_to_regress_into():
    assert "Use these locations?" not in WINDOWS
    assert "Cfm-Confirm -Prompt 'Proceed?'" in WINDOWS
    assert "Fixed OS state locations" in WINDOWS
