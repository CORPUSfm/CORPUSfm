"""Coverage gating driven by the FMUpgradeTool capability ledger.

generate_patch classifies every proposed action as patchable / not_patchable.
Several of those verdicts are LEDGER findings — proven on a live FMUpgradeTool
apply, not guesses:

  - a field ReplaceAction that CHANGES the field type produces an UNHOSTABLE
    file (ledger: field-replace-sametype-ok-typechange-unhostable);
  - a layout cannot be Replaced or Deleted — the export carries no layout UUID
    to target (ledger: layout-add-only-no-uuid-to-target);
  - accounts and built-in privilege sets cannot be deleted (ledger:
    account-delete-unsupported, builtin-privset-delete-unsupported);
  - a script added into a PRE-EXISTING folder lands at the catalog root
    (ledger: preexisting-folder-insert-lands-at-root) — still patchable, but a
    caveat worth surfacing.

This module turns those ledger entries into coverage verdicts so the
deterministic generator and the ledger stay in lockstep. Every entry id cited
here is guarded by tests/test_coverage_gate.py to exist in the ledger, so a
ledger rename can never silently strand a gate.
"""

from __future__ import annotations

# Sections whose objects the patch format cannot Replace or Delete — the export
# carries no targetable UUID. Ledger: layout-add-only-no-uuid-to-target.
_ADD_ONLY_SECTIONS = frozenset({"LayoutCatalog"})

# FM built-in privilege sets — cannot be deleted via patch.
BUILTIN_PRIVSETS = frozenset({
    "[Full Access]",
    "[Data Entry Only]",
    "[Read-Only Access]",
    "[No Access]",
})

# gate key -> (ledger entry id, reason template). The ledger entry id is the
# provenance; the reason is the short human verdict shown in the coverage report.
# Reason wording for account/privset is preserved verbatim for backward compat
# (existing coverage consumers match on "not supported" and the privset name).
_GATES: dict[str, tuple[str, str]] = {
    "layout_add_only": (
        "layout-add-only-no-uuid-to-target",
        "Layouts are add-only — the export carries no layout UUID to target a {action}; "
        "add a new layout instead",
    ),
    "field_typechange": (
        "field-replace-sametype-ok-typechange-unhostable",
        "A field Replace that changes the field type leaves the file unhostable; "
        "add a new field instead of changing this one's type",
    ),
    "account_delete": (
        "account-delete-unsupported",
        "Account deletion is not supported by the Upgrade Tool",
    ),
    "builtin_privset_delete": (
        "builtin-privset-delete-unsupported",
        "Built-in privilege set '{name}' cannot be deleted",
    ),
    "preexisting_folder": (
        "preexisting-folder-insert-lands-at-root",
        "Added inside a pre-existing folder — FMUpgradeTool appends it at the catalog "
        "root; move it into the folder by hand (or via an fmClip)",
    ),
}


def ledger_entry_ids() -> set[str]:
    """The set of ledger entry ids this gate depends on (guarded by a test)."""
    return {eid for eid, _ in _GATES.values()}


def gate_action(
    section: str,
    action: str,
    *,
    item_name: str = "",
    field_type_change: bool = False,
) -> tuple[bool, str]:
    """Return (allowed, reason) for a proposed patch action, per the ledger.

    allowed=False → coverage must mark it not_patchable with `reason` and the
    element must not be emitted. allowed=True with an empty reason means proceed
    normally. `action` is "Add" | "Delete" | "Replace" | "Rename".
    """
    is_replace = action in ("Replace", "Rename")

    if (is_replace or action == "Delete") and section in _ADD_ONLY_SECTIONS:
        return False, _GATES["layout_add_only"][1].format(action=action.lower())

    if is_replace and section == "FieldsForTables" and field_type_change:
        return False, _GATES["field_typechange"][1]

    if action == "Delete" and section == "AccountsCatalog":
        return False, _GATES["account_delete"][1]

    if (action == "Delete" and section == "PrivilegeSetsCatalog"
            and item_name in BUILTIN_PRIVSETS):
        return False, _GATES["builtin_privset_delete"][1].format(name=item_name)

    return True, ""


def preexisting_folder_caveat() -> str:
    """Reason text for a script added into a folder that already exists in the target."""
    return _GATES["preexisting_folder"][1]
