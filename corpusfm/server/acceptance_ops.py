"""Script paste-acceptance batches — the backend orchestration (packet 1121).

Sits between the pure `core.acceptance` logic and the MCP tools. Given a StorageBackend it:
  - CREATES a batch: preflight EVERY requested script through the ordinary emitter + permission authority
    (`emit_script_clip` / `scan_step_assessments` — never a second emitter), then store each case as an
    isolated ordinary fmClip with a deterministic FileMaker-safe unique name and structured acceptance metadata;
  - EVALUATES a returned SaveAsXML: correlate each case by EXACT generated script name, compare the returned
    ordered (step id, shape signature) sequence to the stored expected sequence via the SAME live signature
    authority, and record a conservative acceptance OBSERVATION.

Acceptance metadata rides as one additive JOR key (`AcceptanceCase`) on the generated fmClip, mutated only
through `update_record` — no new ArtifactType, no description-parsed manifest, no user-tag state machine. The
clip XML is immutable after creation; only the metadata record changes.
"""
from __future__ import annotations

import uuid as _uuid

from corpusfm.artifact.types import ArtifactType
from corpusfm.core import acceptance
from corpusfm.core import evidence as ev
from corpusfm.core import safe_xml as ET
from corpusfm.core.clip_emit import emit_script_clip, scan_source_incomplete, scan_step_assessments, ClipEmitContext
from corpusfm.core.crossfile import build_external_data_source_index


# ── the additive per-record acceptance metadata (one JOR key, both backends) ─────

def read_case(backend, uuid: str) -> "dict | None":
    """The acceptance-case record on an fmClip artifact, or None (cheap — no blob)."""
    try:
        jor = backend.load_record_jor(uuid)
    except Exception:
        return None
    ac = jor.get("AcceptanceCase")
    return ac if isinstance(ac, dict) else None


def write_case(backend, uuid: str, case: dict) -> None:
    """Persist the acceptance-case record additively (leaves clip XML + name/description/tags untouched)."""
    backend.update_record(uuid, {"acceptance_case": case})


def iter_batch_cases(backend, batch_id: str) -> "list[tuple[str, dict]]":
    """Every (uuid, case) in a batch, in case-id order — found from the CHEAP `acceptance_batch` meta scalar
    (no blob), then the full case read from the JOR. Structured metadata is the ONLY batch authority; no
    description/memory string is ever searched."""
    hits = []
    for meta in backend.iter_artifact_metas():
        if getattr(meta, "acceptance_batch", "") != batch_id:
            continue
        case = read_case(backend, meta.uuid)
        if case is not None:
            hits.append((meta.uuid, case))
    hits.sort(key=lambda uc: uc[1].get("case_id", 0))
    return hits


# ── generation (the ordinary emitter + permission authority, reused) ─────────────

def _script_item(art, query):
    return ev.find_artifact_item(art, query, section="ScriptCatalog")


def _steps_source(item) -> "str | None":
    src = next((s for s in (item.xml_sources or []) if s.catalog == "StepsForScripts"), None)
    return src.xml if src is not None else None


def _generate(art, item, ctx, *, strict: bool) -> dict:
    """Generate ONE script's whole-script clip + its case-level generation state through the ordinary path.
    Returns {ok, reason, clip_xml, gen_state, step_count, expected_shapes, unsupported}."""
    step_xml = _steps_source(item)
    if step_xml is None:
        return {"ok": False, "reason": f"script '{item.name}' has no StepsForScripts source (no steps stored)"}
    clip_xml, unsupported = emit_script_clip(
        step_xml, script_name=item.name, script_id=item.attributes.get("id", ""),
        include_in_menu=item.attributes.get("includeInMenu", "False"),
        flavor="xmsc", strict=strict, context=ctx)
    if unsupported:
        return {"ok": False, "reason": f"{len(unsupported)} step(s) refuse", "unsupported": unsupported}
    # Static validation (block balance) — an unbalanced clip is a generation FAILURE, never stored.
    from corpusfm.core.clip_validate import validate_clip, TargetIndex
    res = validate_clip(clip_xml, TargetIndex.from_artifact(art))
    if not res.blocks_balanced:
        return {"ok": False, "reason": "emitted clip failed static validation (script blocks unbalanced)"}
    # Case generation state — the SAME weakest-claim precedence as export_object_clip (source-incomplete →
    # experimental → verified); never a second permission check.
    assessed = scan_step_assessments(step_xml, strict=strict, context=ctx, flavor="xmsc")  # matches emit flavor
    si = [] if strict else scan_source_incomplete(step_xml)
    experimental = [a for a in assessed if a["evidence"] == "experimental" and not a["blocked"]]
    if si:
        gen_state = "generated_static_valid"
    elif experimental:
        gen_state = "generated_experimental"
    else:
        gen_state = "generated_verified"
    try:
        expected = acceptance.step_shapes(step_xml)
    except Exception:
        return {"ok": False, "reason": "could not derive the expected step-shape sequence from the source"}
    return {"ok": True, "clip_xml": clip_xml, "gen_state": gen_state,
            "step_count": len(expected), "expected_shapes": expected}


def _rename_script(clip_xml: str, old_name: str, new_name: str) -> str:
    """Rename ONLY the top-level `<Script name>` object of an emitted whole-script clip to `new_name`; steps
    and every other element are byte-untouched. The renamed script is the one matching the source name."""
    root = ET.fromstring(clip_xml)
    for sc in root.findall("Script"):
        if sc.get("name") == old_name:
            sc.set("name", new_name)
            break
    return ET.tostring(root, encoding="unicode")


# ── the SOLE store-a-case authority (packet 1131 — shared by the artifact-script path AND the compiler) ──

def _store_case(backend, *, batch_id, label, case_id, case_name, clip_xml, source_artifact_uuid,
                source_script_item_id, source_script_name, gen_state, expected_shapes, step_count,
                description, memory) -> "tuple[dict | None, dict | None]":
    """store_deliverable → new_case → write_case for ONE prepared case. Returns (stored_entry, None) on
    success or (None, failed_entry) on a storage failure — never raises. The single funnel both the
    artifact-script batch path and the compiler acceptance bridge (packet 1131) go through, so there is one
    naming / expected-shape / storage / record authority, never a second acceptance model."""
    try:
        meta = backend.store_deliverable(
            clip_xml.encode("utf-8"), artifact_type="fmClip", origin="MCP", name=case_name,
            description=description[:200], memory=memory)
        case = acceptance.new_case(
            batch_id=batch_id, batch_label=label, case_id=case_id, case_name=case_name,
            source_artifact_uuid=source_artifact_uuid, source_script_item_id=source_script_item_id,
            source_script_name=source_script_name, generation_state=gen_state,
            expected_shapes=expected_shapes, step_count=step_count)
        write_case(backend, meta.uuid, case)
        return ({"case_id": case_id, "case_name": case_name, "artifact_uuid": meta.uuid,
                 "source_script": source_script_name, "generation_state": gen_state,
                 "step_count": step_count}, None)
    except Exception as exc:
        return (None, {"case_id": case_id, "case_name": case_name, "source_script": source_script_name,
                       "error": str(exc)})


# ── create ──────────────────────────────────────────────────────────────────────

def create_batch(backend, art, art_uuid: str, requested: "list[str]", *, label: str, strict: bool) -> dict:
    """Preflight the WHOLE batch, then store one isolated fmClip per case. Returns a structured manifest.
    Stores NOTHING unless every case preflights; a mid-storage failure is reported honestly (no false atomicity
    claim, no rollback the backend cannot guarantee)."""
    if not acceptance.valid_label(label):
        return {"ok": False, "error": "invalid_label",
                "detail": "batch label must be 1-60 chars of letters/digits/space/_/- (it is echoed; no "
                          "private content)"}
    if not requested:
        return {"ok": False, "error": "empty_batch", "detail": "no scripts requested"}

    # 1. Resolve every requested script unambiguously, preserving caller order.
    resolved, seen_ids = [], {}
    for q in requested:
        item = _script_item(art, q)
        if item is None or item.is_folder:
            return {"ok": False, "error": "unresolved_script",
                    "detail": f"{q!r} did not resolve to a single ScriptCatalog script"}
        iid = item.item_id
        if iid in seen_ids:
            return {"ok": False, "error": "duplicate_script",
                    "detail": f"{q!r} and {seen_ids[iid]!r} resolve to the SAME script — a batch case must be "
                              "distinct"}
        seen_ids[iid] = q
        resolved.append(item)

    token = acceptance.batch_token(art_uuid, label, [it.name for it in resolved])
    batch_id = token
    # Catalog uniqueness — a token collision means this exact batch already exists.
    for meta in backend.iter_artifact_metas():
        if getattr(meta, "acceptance_batch", "") == batch_id:
            return {"ok": False, "error": "batch_exists",
                    "detail": f"an acceptance batch {batch_id} already exists for this source+label+scripts; "
                              "change the label to make a new one"}

    ctx = ClipEmitContext(external_data_sources=build_external_data_source_index(art))

    # 2-3. Preflight the ENTIRE batch before storing anything.
    prepared = []
    for i, item in enumerate(resolved, start=1):
        gen = _generate(art, item, ctx, strict=strict)
        if not gen["ok"]:
            return {"ok": False, "error": "case_refused", "batch_id": batch_id,
                    "detail": f"case {i} (source script {item.name!r}) cannot be generated: {gen['reason']}",
                    "refused_case": {"case_id": i, "source_script": item.name, "reason": gen["reason"]}}
        case_name = acceptance.case_script_name(token, i)
        clip_xml = _rename_script(gen["clip_xml"], item.name, case_name)
        prepared.append((i, item, case_name, clip_xml, gen))

    # 4-6. Store each case as a separate ordinary fmClip + attach structured metadata (via the shared authority).
    stored, failed = [], []
    for (i, item, case_name, clip_xml, gen) in prepared:
        ok_entry, fail_entry = _store_case(
            backend, batch_id=batch_id, label=label, case_id=i, case_name=case_name, clip_xml=clip_xml,
            source_artifact_uuid=art_uuid, source_script_item_id=item.item_id, source_script_name=item.name,
            gen_state=gen["gen_state"], expected_shapes=gen["expected_shapes"], step_count=gen["step_count"],
            description=f"acceptance case {i} of batch {label!r} — source script {item.name}",
            memory=f"acceptance batch {batch_id} case {i}; source {art_uuid}::{item.name}")
        if fail_entry is not None:
            failed.append(fail_entry)
            break   # stop on first storage failure; report honestly (no rollback we can't guarantee)
        stored.append(ok_entry)

    return {"ok": not failed, "batch_id": batch_id, "label": label, "strict": strict,
            "requested": len(resolved), "stored": stored, "failed": failed,
            "partial": bool(failed) and bool(stored)}


def register_compiler_case(backend, *, clip_xml: str, ddr_steps_blob: str, script_name: str, label: str,
                           gen_state: str) -> dict:
    """Register ONE compiler-produced clip (packet 1131 Stage 2/3) as an acceptance case — WITHOUT a source
    artifact. The compiled clip + its lowered DDR step sequence already exist, so this reuses the SAME
    naming / expected-shape / storage / `evaluate_acceptance_return` authorities via `_store_case` (no source
    resolution, no second emitter, no second acceptance model). The expected shape is derived from the lowered
    DDR blob with the identical `acceptance.step_shapes` a returned SaveAsXML will be measured by. Batch id is
    keyed on (synthetic source "", label, [case name]) so a compiler batch is catalog-unique like any other.
    `evaluate_acceptance_return` needs no change — it keys on the batch scalar + case name + expected shape."""
    if not acceptance.valid_label(label):
        return {"ok": False, "error": "invalid_label",
                "detail": "batch label must be 1-60 chars of letters/digits/space/_/- (it is echoed)"}
    if gen_state not in acceptance.GENERATION_STATES:
        return {"ok": False, "error": "bad_generation_state",
                "detail": f"generation_state must be one of {sorted(acceptance.GENERATION_STATES)}"}
    try:
        expected = acceptance.step_shapes(ddr_steps_blob)
    except Exception:
        return {"ok": False, "error": "bad_ddr_blob",
                "detail": "could not derive the expected step-shape sequence from the lowered DDR"}

    token = acceptance.batch_token("", label, [script_name])
    for meta in backend.iter_artifact_metas():
        if getattr(meta, "acceptance_batch", "") == token:
            return {"ok": False, "error": "batch_exists",
                    "detail": f"an acceptance batch {token} already exists for this label+script; change the "
                              "label to make a new one"}
    case_name = acceptance.case_script_name(token, 1)
    renamed = _rename_script(clip_xml, script_name, case_name)
    ok_entry, fail_entry = _store_case(
        backend, batch_id=token, label=label, case_id=1, case_name=case_name, clip_xml=renamed,
        source_artifact_uuid="", source_script_item_id="", source_script_name=script_name,
        gen_state=gen_state, expected_shapes=expected, step_count=len(expected),
        description=f"compiler acceptance case — {script_name!r} (batch {label!r})",
        memory=f"compiler acceptance batch {token} case 1; compiled script {script_name}")
    if fail_entry is not None:
        return {"ok": False, "error": "storage_failed", "batch_id": token, "detail": fail_entry["error"]}
    return {"ok": True, "batch_id": token, "label": label, "stored": [ok_entry]}


# ── evaluate ──────────────────────────────────────────────────────────────────────

def _returned_shapes(returned_art, case_name: str) -> "tuple[str, list | None]":
    """Find the EXACT-named script in the returned SaveAsXML and its ordered step shapes.
    Returns (status, shapes) where status ∈ {found, absent, unreadable}. No substring/case-fold/ordinal
    fallback — the generated name is exact."""
    item = next((it for it in returned_art.items.values()
                 if it.section == "ScriptCatalog" and not it.is_folder and it.name == case_name), None)
    if item is None:
        return ("absent", None)
    step_xml = _steps_source(item)
    if step_xml is None:
        return ("unreadable", None)
    try:
        return ("found", acceptance.step_shapes(step_xml))
    except Exception:
        return ("unreadable", None)


def evaluate_return(backend, batch_id: str, returned_art, returned_uuid: str, *,
                    rejected_ids: "set[int]" = frozenset(), override: bool = False) -> dict:
    """Correlate a returned SaveAsXML to a batch's cases and record conservative observations. Idempotent
    against the same returned artifact; a DIFFERENT returned artifact requires override and keeps a bounded
    prior-observation history."""
    cases = iter_batch_cases(backend, batch_id)
    if not cases:
        return {"ok": False, "error": "batch_not_found", "detail": f"no acceptance cases for batch {batch_id!r}"}
    # Require a genuine SaveAsXML return; a non-SaveAsXML never yields a false match.
    if getattr(getattr(returned_art, "type", None), "value", None) != ArtifactType.SAVE_AS_XML.value:
        return {"ok": False, "error": "evaluation_incomplete",
                "detail": "the returned artifact is not a SaveAsXML — cannot correlate; no case was matched",
                "batch_id": batch_id}

    results, needs_override = [], []
    for uuid, case in cases:
        cid = case.get("case_id")
        prior = case.get("acceptance_state")
        prior_ret = case.get("returned_artifact_uuid")
        # idempotence / override: a different return against an already-evaluated case needs override.
        if prior and prior != acceptance.AWAITING_PASTE and prior_ret and prior_ret != returned_uuid and not override:
            needs_override.append(cid)
            results.append({"case_id": cid, "case_name": case.get("case_name"), "state": prior,
                            "skipped": "needs_override"})
            continue

        if cid in rejected_ids:
            state, diff = acceptance.PASTE_REJECTED, []
        else:
            status, shapes = _returned_shapes(returned_art, case.get("case_name"))
            if status == "unreadable":
                state, diff = acceptance.EVALUATION_INCOMPLETE, []
            elif status == "absent":
                state, diff = acceptance.NOT_FOUND_IN_RETURN, []
            else:
                state, diff = acceptance.compare_shapes(case.get("expected_shapes") or [], shapes)

        updated = acceptance.apply_observation(case, state=state, returned_artifact_uuid=returned_uuid, diff=diff)
        # idempotence: if nothing changed (same state + same return), do not churn history/rewrite.
        if not (updated["acceptance_state"] == prior and (prior_ret or "") == returned_uuid):
            write_case(backend, uuid, updated)
        results.append({"case_id": cid, "case_name": case.get("case_name"), "state": state,
                        "diff_count": len(diff)})

    counts: dict = {}
    for r in results:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    return {"ok": True, "batch_id": batch_id, "returned_artifact_uuid": returned_uuid,
            "counts": counts, "cases": results, "needs_override": needs_override,
            "disclaimer": "returned_shape_match proves the named script survived paste AND its per-step DDR "
                          "SHAPE matches — NOT behavioral equivalence, formula-result correctness, or complete "
                          "content fidelity. not_found_in_return is not proof of rejection; only an explicit "
                          "user report is."}
