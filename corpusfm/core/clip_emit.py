"""DDR `StepsForScripts` `<Step>` → clipboard `FMObjectList` `<Step>` emitter — packet 1037C.

The DDR (SaveAsXML) step dialect and the clipboard (FMObjectList / XMSC) step dialect share only
`id` / `name` / `enable` per step; parameters, calculations, and references are shaped completely
differently, and each step type re-expresses its option flags in its own flat clip grammar.

**Permission model (packet 1091, fmClip epoch).** `step_generation_assessment` is the single authority.
A step EMITS when it is a byte-captured verified shape (`generated_verified`), a registered
source-incomplete shape (`generated_static_valid`; packet 1089), or a shape a code-adjacent CAPABILITY
RULE fully accounts for though its exact pair is uncaptured (`generated_experimental`). Everything else
REFUSES with its exact id — an unaccounted option shape names a `capability_unaccounted_shape` hazard, not
a missing captured pair. Structural clip validity (well-formed, block balance, reference resolution)
**cannot** prove a step type's option flags survived conversion, so an unaccounted shape is never emitted
best-effort. `_VERIFIED_SIGS` / `VERIFIED_STEP_IDS` is EVIDENCE (the byte-captured set that reproduces
ground truth, kept in lockstep with the fixtures by `tests/test_clip_emit.py`), no longer the whole
permission gate. Capability migration is deliberately incremental — `_STEP_CAPABILITY_RULES` began at
ONE family (ids 9/10, the NoInteract `With dialog` grammar) and, through packet 1109, spans TWELVE families
(145 ids — see the registry comment above `_STEP_CAPABILITY_RULES`): the whole `_emit_noninteract` family,
the direct-Boolean base shapes, the base-bare + toggle families, the selector-enum + embedded-insert
families, the simple option-bearing base emitters, the bounded reference-bearing emitters (menu-set /
object-name / window / field / current-file references), and the calculation + direct-content primitives
(control flow / comment / variable / field / result calcs / text / selection / URL / web-viewer / JS /
duration / path). Every rule migrates BASE/simple/bounded grammar only; a richer configured form of the same
id (and external-file/layout/script references, Rich Replace Field Contents) still refuses, and every other
id's unseen shapes stay refused until their grammar is migrated. `strict=True` requests verified-only output
(experimental + source-incomplete refuse).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NamedTuple

from corpusfm.core import safe_xml as ET
from corpusfm.ingestion.clip import _strip_xml_decl


class ClipEmitError(Exception):
    pass


@dataclass(frozen=True)
class ClipEmitContext:
    """Explicit, immutable context for clip generation (packet 1118) — threaded optionally through the
    whole script path INSTEAD of module/ambient state. Today it carries only the external-data-source
    resolution authority (a `crossfile.ExternalDataSourceIndex`, duck-typed so clip_emit imports nothing
    from crossfile), so a context-aware external rule resolves a step's DataSourceReference against the
    SAME loaded artifact. Extensible only by a deliberate future packet. `context=None` everywhere
    preserves every existing assessment, emitted byte, and caller."""
    external_data_sources: object = None   # crossfile.ExternalDataSourceIndex | None

    def resolve_external(self, ref_id, ref_name):
        """Delegate to the external-data-source authority (None if no authority is present)."""
        idx = self.external_data_sources
        return idx.resolve(ref_id, ref_name) if idx is not None else None

    def resolve_external_path(self, ref_id, ref_name):
        """The ONE raw path for a uniquely-resolved single-path FileMaker entry, else None (packet 1119).
        Delegates to the authority's `single_external_path` — the only channel by which a raw path reaches
        the emitter as clip CONTENT; it never enters a reason/report/log. None when the authority is absent
        or the reference is not a unique single-path FileMaker entry."""
        idx = self.external_data_sources
        return idx.single_external_path(ref_id, ref_name) if idx is not None else None


# The five step families whose external-file form carries a DataSourceReference into a sibling file
# (packet 1118). Only these get a context-aware resolution; every other id is untouched.
_EXTERNAL_REF_STEP_IDS = frozenset({1, 33, 34, 138, 164})


# ── packet 1077 — the DECLARED target FileMaker version ────────────────────────
#
# Every clip this module emits is FM2026-form. That was already true before this constant existed; what
# was missing was saying so. An emitter with an *undeclared* target is the same defect the fence exists
# to prevent — a projection that doesn't state its own limits — so the target is now named, surfaced by
# `export_object_clip` (human + structured), and cataloged per version-sensitive id.
#
# This is NOT a version-keying knob. There is no target_version parameter and no FM2025 output path;
# adding one is packet 1077 option B, and it is only worth building if FM2025 clips are actually wanted.
# Until then the honest posture is: we emit FM2026, we say FM2026, and we do not pretend about FM2025.
#
# Two independent reasons the output is FM2026-shaped:
#   1. `<DisableStepCollapsed>` — an FM2026 clipboard addition the FM2025 clip omits entirely. Every
#      step we emit carries it, so EVERY clip is version-shaped, not just the 19 below.
#   2. The 19 version-sensitive ids in `clip_catalog.yaml`'s `version_sensitivity` — 10 FM2026-only
#      types plus 9 with real payload deltas (e.g. 212, where FM2025 expects the typo `SetLLMAccout`).
#
# Whether FM2025 tolerates an FM2026-form clip is UNTESTED — a paste test on an FM2025 box, not a guess.
CLIP_TARGET_VERSION = "FM2026"


# FileMaker's clipboard export canonicalizes a handful of built-in function-name casings differently
# from its DDR export (both parse identically — FM function names are case-insensitive). We mirror the
# clipboard spelling so an emitted calc is byte-identical to a real FM copy. This is an EXPLICIT,
# tested normalization, not a silent fudge: any *unobserved* casing drift would surface as a
# round-trip mismatch in test_clip_emit / the dev full-pair check, never a quiet divergence.
#
# Shared with field_emit (it imports `_canon_calc`): a field's auto-enter/validation calc goes through the
# same clipboard, so the same canonicalization applies. Two copies of this map would drift — and drift
# here is invisible, because a wrongly-cased function still PARSES.
#
# `GetAsTimeStamp` was added 2026-07-15 from a FIELD capture, and it exposed a latent hole on the SCRIPT
# side too: no committed script pair contains that function, so clip_emit would have emitted it wrong and
# nothing would have failed. All three names FileMaker's DDR writes with a capital S are now mapped
# (`CurrentTimeStamp`, `CurrentHostTimeStamp`, `GetAsTimeStamp` — a census of a 39 MB export).
#
# Note the direction, which is genuinely confusing: the clip lower-cases the `s` in FUNCTION names while
# the datatype map (field_emit._DATATYPE) does the OPPOSITE — `Timestamp` → `TimeStamp`. So one clip can
# hold `dataType="TimeStamp"` next to `GetAsTimestamp`, and both are correct. Never unify them into one
# rule; they are different vocabularies that merely share a word.
_FN_CANON = {"CurrentHostTimeStamp": "CurrentHostTimestamp",
             "CurrentTimeStamp": "CurrentTimestamp",
             "GetAsTimeStamp": "GetAsTimestamp"}
_FN_CANON_RE = re.compile(r"\b(" + "|".join(map(re.escape, _FN_CANON)) + r")\b") if _FN_CANON else None


def _canon_calc(text: str) -> str:
    if not text or _FN_CANON_RE is None:
        return text
    return _FN_CANON_RE.sub(lambda m: _FN_CANON[m.group(1)], text)


# ── DDR readers ────────────────────────────────────────────────────────────────

def _inner_text(el) -> str:
    """DDR calcs are double-nested: <Calculation datatype=…><Calculation><DDRREF/><Text>CALC</Text>…>.
    Return the innermost <Text> content ('' if absent), with FM function-name casing canonicalized to
    the clipboard spelling. `el` scopes the search (a Parameter / value / repetition subtree) so Set
    Variable's value vs repetition don't cross."""
    if el is None:
        return ""
    t = el.find(".//Text")
    return _canon_calc(t.text if (t is not None and t.text is not None) else "")


def _sig_token(p) -> str:
    """One `Parameter`'s fence token. The token must separate every BEHAVIOUR-BEARING variant that
    serialises differently in the clip, so a verified id in an unseen shape is refused (packet 1041
    §3). Existing (packet-1037C) param kinds keep their exact old token — a bare `Boolean:Collapsed`
    (display state, value handled generically), or the plain `@type` — so the 12 original verified
    sigs are unchanged; the newer mode/option kinds add the minimal nested discriminator."""
    ty = p.get("type") or "?"
    if ty == "Boolean":
        b = p.find("Boolean")
        bt = (b.get("type") if b is not None else None) or "_"
        if bt == "Collapsed":                       # display state — unchanged from 1037C
            return "Boolean:Collapsed"
        return f"Boolean:{bt}={b.get('value') if b is not None else '?'}"   # option bool: value-fenced
    if ty in ("List", "Records"):                   # mode selector + option booleans + reference kind
        l = p.find("List")
        nm = l.get("name") if l is not None else "?"
        opts = "".join(sorted(f"[{b.get('type')}={b.get('value')}]"
                              for b in (l.findall("Boolean") if l is not None else [])))
        # The reference CHILDREN are behaviour-bearing: an internal call carries <ScriptReference>; an
        # external-file target adds <DataSourceReference> (→ a <FileReference> the flat emitter can't
        # resolve — the path lives in the data-source catalog); an UNRESOLVED external target leaves the
        # List empty (still a <FileReference>+<Script id="0"/> in the clip). Only the resolved internal
        # shape is verified; the others must fence, not half-emit.
        refs = "".join(f"<{t}>" for t in ("DataSourceReference", "ScriptReference", "Calculation")
                       if l is not None and l.find(t) is not None)
        return f"{ty}:{nm}{opts}{refs}"
    if ty == "LayoutReferenceContainer":
        c = p.find(ty)
        return f"LRC:{c.get('value') if c is not None else '?'}"
    if ty == "Animation":
        a = p.find("Animation")
        return f"Animation:{a.get('name') if a is not None else '?'}"
    if ty == "Options":                             # option mode selector (e.g. Pause/Resume duration)
        o = p.find("Options")
        if o is None:
            return "Options:?"
        # packet 1082 — 131 Insert File hangs FIVE <Options type=…> siblings off ONE param
        # (Title/Filters/Storage/Display/Compress), and `p.find("Options")` returns only the FIRST, so
        # the token read `Options:Title` and every Storage/Display/Compress enum was invisible to the
        # fence. An emitter verified on 'Let user choose' would then have emitted UserChoice for
        # 'Insert only a reference' — silently wrong. Gated on >1 child, which no other verified id has
        # (62/67/143/144/243 all carry exactly one), so their tokens cannot move.
        siblings = p.findall("Options")
        if len(siblings) > 1:
            parts = []
            for s in siblings:
                kind = s.get("type")
                sel = s.find(kind) if kind else None      # <Storage name=… value=…> etc.
                val = sel.get("value") if sel is not None else None
                parts.append(f"{kind}={val}" if val is not None else f"{kind}")
            return f"Options:[{','.join(parts)}]"
        # packet 1081 — the PDF family (144/243) hangs its whole Document/Security/View config off this
        # ONE param, so `Options:{@type}` collapsed the base (empty <Options/>) and every configured
        # shape into a single token. Verifying a configured pair would then license the emitter to fire
        # on the base shape and invent a config from nothing — the same collision 1076 found in Print
        # Setup. Scoped to the PDF sub-blocks on purpose: 62/67/143 also use `Options` and their tokens
        # must not change (a generic subtree fingerprint is unsound — see 1069's Set Field 1→116).
        if any(o.find(t) is not None for t in ("Document", "Security", "View")):
            return f"Options:{o.get('type')}|{_pdf_options_fingerprint(o)}"
        return f"Options:{o.get('type')}"
    if ty in ("Portal", "action"):                  # a mode selector inside a <List name=…> — fence by mode
        l = p.find("List")
        return f"{ty}:{l.get('name') if l is not None else '?'}"
    if ty == "DataSourceReference":                 # current file (id 0) vs a NAMED external file
        d = p.find("DataSourceReference")            # (named → clip needs a UniversalPathList path that
        cur = d is not None and d.get("id") == "0"   #  lives in the data-source catalog, unresolvable here)
        return "DataSourceReference:current" if cur else "DataSourceReference:external"
    if ty == "Email":                               # Send Mail — fence the STRUCTURAL shape (send mode +
        return f"Email:{_email_fingerprint(p)}"     # encryption/auth/provider enums), values handled generically
    if ty == "Print":                               # fence by print-type (only mapped types are verified)
        # packet 1112 — the print type ALONE collapsed two more target-driving Print attributes the emitter
        # consumes: `toFile` (→ <PrintSettings PrintToFile>) and Pages `@All` (→ AllPages). Without them a
        # toFile="True" or AllPages="False" step borrowed the verified `Print:Current record` tuple yet
        # produced a different clip. Copies is CONTENT (a copied number, like calc text) and stays out. Print
        # is a 43-only param, so this token change is id-scoped by construction.
        pr = p.find("Print")
        if pr is None:
            return "Print:?"
        pages = pr.find("Pages")
        return (f"Print:{pr.get('name')}|toFile={pr.get('toFile')}"
                f"|all={pages.get('All') if pages is not None else '_'}")
    if ty == "PageSetup":
        # packet 1076 — EMPTY vs POPULATED is structural, not cosmetic: an empty <PageSetup> yields a
        # clip with NO <PageFormat>, a populated one yields a <PageFormat> carrying printer-computed
        # geometry we cannot reproduce (a class-2 gap). Collapsing both to a bare 'PageSetup' let the
        # verified empty shape silently ADMIT the populated one — which would have emitted a clip that
        # drops the entire page setup. This is the same failure the mode-selector tokens fixed in 1069.
        ps = p.find("PageSetup")
        return "PageSetup:set" if (ps is not None and len(ps)) else "PageSetup:empty"
    if ty in ("Text", "Select"):
        # packet 1082 — two of packet 1069's named FENCE-HOLES. The bare `ty` token could not tell an
        # EMPTY payload from a configured one, and the two serialise completely differently: 61's empty
        # <Text/> yields a clip with no text element at all, a filled one carries the content; 130's
        # empty <Start/><End/> yields a clip with no bounds, filled ones carry <StartPosition>/
        # <EndPosition>. So a base-verified emitter would have silently DROPPED the inserted text / the
        # selection bounds on every configured instance. Same empty-vs-set split as PageSetup (1076) and
        # the PDF Options subtree (1081) — the third time this shape of bug has shown up.
        # NB the payload hides in a different place per type, and guessing cost a round here: 61 carries
        # its text in an ATTRIBUTE (<Text value="this text"/>), while 130 has no <Select> node at all —
        # its bounds are <Start>/<End> siblings. A tidy generic check reported both as empty.
        if ty == "Text":
            node = p.find("Text")
            payload = node is not None and (node.get("value") or len(node) or (node.text or "").strip())
        else:
            payload = any(p.find(f"{b}/Calculation") is not None for b in ("Start", "End"))
        return f"{ty}:{'set' if payload else 'empty'}"
    if ty == "replace":
        # packet 1082 — 91 Replace Field Contents. The bare token collapsed the replace MODE, and the
        # three modes emit different clips (<With value="None"/CurrentContents/SerialNumbers/…>). The
        # List @name is NOT enough on its own: 'Current contents' appears at BOTH value 0 (the unset
        # base) and value 1 (the configured replace), and those two produce DIFFERENT clips — so the
        # value is part of the fence, not decoration.
        l = p.find("List")
        if l is None:
            return "replace:?"
        opts = "".join(sorted(f"[{b.get('type')}={b.get('value')}]" for b in l.findall("Boolean")))
        # packet 1120 — the serial mode's nested 'Entry option values' List drives UseEntryOptions AND the
        # presence of Initial/increment, and it is a <List> (not a <Boolean>), so the bare token above
        # collapsed EOV=True (UseEntryOptions=True, no InitialValue) with EOV=False+explicit (UseEntryOptions=
        # False, InitialValue/increment present) — two DIFFERENT clips. Its @value + explicit-value PRESENCE are
        # shape; the numbers are content. Only id 91 carries a `replace` param, so this is id-scoped by nature.
        eov = l.find("List[@name='Entry option values']")
        if eov is not None:
            iv = "+iv" if (eov.find("Initial") is not None or eov.find("increment") is not None) else ""
            opts += f"[Entry option values={eov.get('value')}{iv}]"
        return f"replace:{l.get('name')}={l.get('value')}{opts}"
    if ty == "SortSpecification":                   # fingerprint the sort shape (order + custom/VL)
        ss = p.find("SortSpecification")
        sorts = ss.findall(".//Sort") if ss is not None else []
        desc = ",".join((s.get("type") or "?") + (":VL" if s.find(".//ValueListReference") is not None else "")
                        for s in sorts)
        return f"SortSpec:{desc}"
    if ty == "FindRequest":                         # fingerprint the request set (action + criteria count)
        reqs = p.findall(".//FindRequest")
        desc = ",".join(f"{r.get('action')}:{len([c for c in r if c.tag in ('find', 'omit')])}" for r in reqs)
        return f"Find:{desc}"
    if ty in ("From", "SaveTo", "operation", "AccountType", "Monitor"):
        # packet 1069 — bespoke selector fence (the sound slice of 1068 item 2's subtree-token work).
        # Each of these param types wraps a lone <List name=…> MODE selector the emitter reads by name
        # (PDF save-mode File/Records/Current · Configure ML operation · Add Account account-type ·
        # Configure Region Monitor source). The old fallback ('ty') collapsed every mode to one token,
        # so a verified id in an UNSEEN mode was silently ADMITTED. Fingerprinting the selector fences
        # every mode but the round-trip-verified one. A generic subtree fingerprint is NOT viable here
        # (DDR encodes selectors and content identically as @name → it explodes on field/TO names) —
        # the fence is per-type by necessity; see docs/clip-emit-coverage.md. (Monitor has no emitter
        # yet → forward scaffold for a future id-185 emitter; harmless until then.)
        l = p.find("List")
        return f"{ty}:{l.get('name') if l is not None else '?'}"
    return ty


def _step_signature(step) -> tuple:
    """The DDR parameter SHAPE of a step — the sequence of per-`Parameter` fence tokens (`_sig_token`)
    under `ParameterValues` (absent → ()). This is the per-id fence key: a verified id is only emitted
    for a shape we actually round-trip-verified, so a known id carrying an unseen option/parameter/mode
    is REFUSED rather than silently emitted."""
    pv = step.find("ParameterValues")
    if pv is None:
        return ()
    params = pv.findall("Parameter")
    toks = [_sig_token(p) for p in params]
    # packet 1103 — id 26 (Omit Multiple)'s OPTIONAL count Calculation: a POPULATED calc serialises as
    # <Calculation>text</Calculation>, an EMPTY one as <Calculation/> — different clips — but the generic
    # `Calculation` token collapses both, so the verified populated shape would silently ADMIT an unobserved
    # empty-calc one (emitting a wrong empty <Calculation>). Split empty/set SCOPED TO id 26 (the only id
    # with an OPTIONAL count calc): the 13 other ids whose Calculation is REQUIRED keep the bare token so
    # their whole fence stays put. Same empty-vs-set fence-hole class as Text/Select/PageSetup/Options.
    if step.get("id") == "26":
        toks = [f"Calculation:{'set' if (params[i].findtext('.//Text') or '').strip() else 'empty'}"
                if t == "Calculation" else t
                for i, t in enumerate(toks)]
    # packet 1106 — the selector-enum family: its OPTIONAL Collapsed Boolean drives <DisableStepCollapsed
    # @state>, but the generic `Boolean:Collapsed` token is value-AGNOSTIC (display state, handled by
    # _collapsed_state). Id 45's committed shape carries Collapsed=False, so a Collapsed=True recombination
    # would collide with the verified tuple yet emit a DIFFERENT state. Split the value SCOPED to the 13
    # selector ids (the only ones where Collapsed rides alongside a selector) so True/False stay distinct;
    # ids 68/125 and the packet-1105 base-bare Collapsed keep the bare token, whole fences byte-identical.
    if step.get("id") in _SELECTOR_ID_STRS:
        toks = [f"Boolean:Collapsed={params[i].find('Boolean').get('value')}"
                if t == "Boolean:Collapsed" else t
                for i, t in enumerate(toks)]
    # packet 1108 — reference-family evidence-token REPAIR (topology fidelity, NOT new permission). Each of
    # these tokens collapsed a target-driving reference topology to one string, so an uncaptured topology could
    # inherit a verified verdict. Repaired with the SMALLEST id-scoped discriminator, re-derived from the same
    # committed pairs (no evidence growth). Scoped by id so the OTHER users of each shared token stay
    # byte-identical: WindowReference is also used by 119/122 (out of scope), FieldReference by 76/91/130/132,
    # CustomMenuSet only by 142. `Object`'s repetition presence adds a target <Repetition> (145/167 carry it,
    # 180 does not); `CustomMenuSet`'s Use-as-file-default drives <UseAsFileDefault @state>.
    _sid = step.get("id")
    if _sid == "142":
        toks = [f"CustomMenuSet:default={_menu_default_value(params[i])}" if t == "CustomMenuSet" else t
                for i, t in enumerate(toks)]
    if _sid in _OBJECT_NAME_SIG_IDS:
        toks = [("Object:rep" if params[i].find("repetition") is not None else "Object") if t == "Object" else t
                for i, t in enumerate(toks)]
    if _sid in _WINDOWREF_SIG_IDS:
        toks = [_windowref_sig_token(params[i]) if t == "WindowReference" else t
                for i, t in enumerate(toks)]
    if _sid in _FIELDREF_SIG_IDS:
        toks = [_fieldref_sig_token(params[i]) if t == "FieldReference" else t
                for i, t in enumerate(toks)]
    # packet 1109 — calculation/direct-content topology repair. Comment: a `value` ATTRIBUTE present → a target
    # <Text> child, absent → none (the broad `Comment` token collapsed both). Target (77/203): a FieldReference
    # branch vs a Variable branch, plus anchor/repetition presence, drive different target trees but collapsed
    # to one `Target` token. Both scoped by id so the OTHER users stay byte-identical (Comment only 89; Target
    # also 61/131/144/160 which keep the bare token — their branch/rep is fixed or dropped). Calc/name/path TEXT
    # stays content.
    if _sid == "89":
        toks = [f"Comment:{'set' if params[i].find('Comment').get('value') is not None else 'bare'}"
                if t == "Comment" else t for i, t in enumerate(toks)]
    if _sid in _TARGET_SIG_IDS:
        toks = [_target_sig_token(params[i]) if t == "Target" else t for i, t in enumerate(toks)]
    # packet 1129 — new target-driving distinctions. 61 Insert Text now admits a VARIABLE target (→ <Field>$var</Field>)
    # alongside the field target (→ <Field table id name/>); the bare `Target` token collapsed them. 141 Set Variable
    # now admits an EMPTY <value/> (→ NO <Value> element) alongside a populated one; `Variable` collapsed them. 130
    # Set Selection now admits a LONE bound (Start-only / End-only, → one <StartPosition>/<EndPosition>); `Select:set`
    # collapsed which bound(s) were set (an uncaptured lone-End would have borrowed the both-bound verdict). Each
    # scoped to its id and re-derived from the same committed pairs; $name/formula/field TEXT stays content.
    if _sid == "61":
        toks = [("Target:var" if params[i].find("Variable") is not None else "Target:field")
                if t == "Target" else t for i, t in enumerate(toks)]
    if _sid == "141":
        toks = [f"Variable:val={'set' if params[i].find('value/Calculation') is not None else 'empty'}"
                if t == "Variable" else t for i, t in enumerate(toks)]
    if _sid == "175":                          # packet 1129 — JS argument count drives <Parameters Count=N>
        toks = [f"Parameter:args={len(params[i].findall('Calculation'))}" if t == "Parameter" else t
                for i, t in enumerate(toks)]
    if _sid == "130":
        new = []
        for i, t in enumerate(toks):
            if t.startswith("Select:"):
                sel = params[i]
                bset = "".join(x for x, f in (("start", sel.find("Start/Calculation") is not None),
                                              ("end", sel.find("End/Calculation") is not None)) if f)
                new.append(f"Select:{bset or 'empty'}")
            else:
                new.append(t)
        toks = new
    # packet 1126 — Write/Read to Data File carry a non-Parameter <Encoding> sibling under <ParameterValues>
    # whose @type drives <DataSourceType value>. It is target-driving but not a <Parameter>, so append it to
    # the signature (id-scoped to 192/193) — an uncaptured encoding then emits experimental, not verified.
    if _sid in ("192", "193"):
        enc = pv.find("Encoding")
        if enc is not None:
            toks = toks + [f"Encoding:{enc.get('type')}"]
    # packet 1110 — layout/window topology repair. The generic `WindowReference` (119/122) and `Related` (74)
    # tokens collapsed target-driving topology (selection mode, per-bound presence, layout destination/payload,
    # Name-calc presence, new-window presence, style/option values) to one string, so an uncaptured topology
    # could inherit a verified verdict. Repaired with the smallest id-scoped discriminators, re-derived from the
    # SAME committed pairs. Scoped by id so the packet-1108 WindowReference ids (121/123/124) and the id 6/228
    # LRC/Animation tokens stay byte-identical. Layout/TO names, ids, calc/name TEXT, and bound values remain
    # content.
    if _sid == "119":
        toks = [_move_resize_sig_token(params[i]) if t == "WindowReference" else t for i, t in enumerate(toks)]
    if _sid == "122":
        toks = [_new_window_sig_token(params[i]) if t == "WindowReference" else t for i, t in enumerate(toks)]
    if _sid == "74":
        toks = [_goto_related_sig_token(params[i]) if t == "Related" else t for i, t in enumerate(toks)]
    # packet 1111 — record/query/state topology repair (id-scoped). The base tokens for FindRequest (28),
    # SortSpecification (39), Portal (99), and the sort Restore (39) collapse target-driving facts (per-
    # criterion/sort anchor presence, the SortSpec option attrs, the portal With-dialog value, the sort Restore
    # value) into one string, so an uncaptured topology could inherit a verified verdict. Re-derived from the
    # SAME committed pairs and scoped by id so the Restore token (shared by 42/43/143/144/243) and the "action"
    # Portal-branch users (146/187/201) stay byte-identical. Criterion text, field identity, and formulas remain
    # content.
    if _sid == "28":
        toks = [_perform_find_sig_token(params[i]) if t.startswith("Find:") else t for i, t in enumerate(toks)]
    if _sid == "39":
        new = []
        for i, t in enumerate(toks):
            if t.startswith("SortSpec:"):
                new.append(_sort_spec_sig_token(params[i]))
            elif t == "Restore":
                r = params[i].find("Restore")
                new.append(f"Restore={r.get('value') if r is not None else '?'}")
            else:
                new.append(t)
        toks = new
    if _sid == "99":
        toks = [_portal_sig_token(params[i]) if t.startswith("Portal:") else t for i, t in enumerate(toks)]
    # packet 1113 — Perform Script (1) / on Server (164): the optional Parameter block's present-empty vs
    # present-populated topology drives whether the clip carries a <Calculation>, but the generic `Parameter`
    # token collapsed both. A by-name EMPTY step would then borrow the by-name POPULATED verified tuple (id 164)
    # or id 1's refuse-worthy shape. Split empty/set SCOPED to 1/164 (the only ids with this Parameter block);
    # re-derived from the same three committed pairs each. Formula text stays content.
    if _sid in _PERFORM_SCRIPT_SIG_IDS:
        toks = [f"Parameter:{_perform_script_param_presence(params[i])}" if t == "Parameter" else t
                for i, t in enumerate(toks)]
    # packet 1114 — service/communication topology repair (id-scoped). id 66 (Speak): the bare `Voice`/`Wait`
    # tokens dropped the effect-driving VoiceId + WaitForCompletion values, so a Wait=False / other-voice shape
    # could borrow the verified tuple. id 63 (Send Mail): `_email_fingerprint` captured only mode + crypto enums,
    # collapsing dialog/Multiple/attachment/recipient/CollectAddresses/content presence — all target-driving —
    # so an uncaptured mail shape could borrow a verified tuple. Both re-derived from the same committed pairs.
    if _sid == "66":
        new = []
        for i, t in enumerate(toks):
            if t == "Voice":
                new.append(f"Voice:{params[i].find('Voice').get('value')}")
            elif t == "Wait":
                new.append(f"Wait:{params[i].find('Boolean').get('value')}")
            else:
                new.append(t)
        toks = new
    if _sid == "63":
        toks = [_send_mail_sig_token(params[i]) if t.startswith("Email:") else t for i, t in enumerate(toks)]
    # packet 1115 — file-I/O topology repair (id-scoped). id 37/132: the UPL's AutoOpen/CreateMail attrs drive
    # <AutoOpen>/<CreateEmail> states, collapsed by the bare `UniversalPathList` token. id 131: the Target's TO
    # anchor drives <Field table> (its repetition is DROPPED by _emit_field_ref, so anchor-only). id 160: the URL
    # autoEncode flag drives <DontEncodeURL @state>. FieldReference (132) + Target (160) join the shared sig-id
    # sets above. All re-derived from committed pairs; path/URL/field TEXT stays content.
    if _sid in _FILE_UPL_SIG_IDS:
        toks = [_file_upl_sig_token(params[i]) if t == "UniversalPathList" else t for i, t in enumerate(toks)]
    if _sid == "131":
        toks = [_insert_file_target_sig_token(params[i]) if t == "Target" else t for i, t in enumerate(toks)]
    if _sid in _URL_SIG_IDS:
        toks = [_url_sig_token(params[i]) if t == "URL" else t for i, t in enumerate(toks)]
    # packet 1116 — Show Custom Dialog (87) topology repair (id-scoped). Each button's Commit value + label
    # presence and each input slot's target kind/password/label drive different clips but collapse into the bare
    # `Button{i}`/`Field{i}` token, so an uncaptured arrangement could inherit a verified verdict. Re-derived from
    # the three committed dialog pairs. Title/Message keep the bare token (presence is already the discriminator;
    # calc TEXT is content). No other id carries these param types, so this is id-scoped by construction.
    if _sid == "87":
        toks = [_dialog_sig_token(params[i]) if t in _DIALOG_SIG_TYPES else t for i, t in enumerate(toks)]
    # packet 1117 — Export/Excel/JSONL configured topology (id-scoped). The bare `UniversalPathList`/`Export`/
    # `SaveAsJSONLDataCompleteField`/`SaveAsJSONLTable` tokens collapse target-driving facts (export file type +
    # charset/format + order-kind sequence + field count; the Excel save mode + useFieldNames + metadata order;
    # the JSONL field/table anchor topology), so an uncaptured configured shape could inherit a verified verdict.
    # Encoded id-scoped and re-derived from the four committed pairs. BASE shapes carry none of these params, so
    # their signatures are byte-identical. Path/calc/field TEXT stays content.
    if _sid == "36":
        toks = [(_export_upl_sig_token(params[i]) if t == "UniversalPathList"
                 else _export_order_sig_token(params[i]) if t == "Export" else t)
                for i, t in enumerate(toks)]
    if _sid == "143":
        toks = [_excel_upl_sig_token(params[i]) if t == "UniversalPathList" else t for i, t in enumerate(toks)]
    if _sid == "225":
        toks = [("JSONLPath" if t == "UniversalPathList"
                 else _jsonl_field_sig_token(params[i]) if t == "SaveAsJSONLDataCompleteField"
                 else "JSONLTable" if t == "SaveAsJSONLTable" else t)
                for i, t in enumerate(toks)]
    return tuple(toks)


def _export_upl_sig_token(param) -> str:       # id 36 configured UPL — fileType drives the Profile DataType
    upl = param.find("UniversalPathList")
    return f"ExportUPL:{upl.get('fileType') if upl is not None else '?'}"


def _export_order_sig_token(param) -> str:     # id 36 configured Export — charset/format + ordered order topology
    ex = param.find("Export")
    o = ex.find("Options") if ex is not None else None
    orders = []
    for od in (ex.findall("Order") if ex is not None else []):
        k = od.get("type")
        orders.append(f"Field:{len(od.findall('Field'))}" if k == "Field" else (k or "?"))
    return (f"Export:cs={o.get('name') if o is not None else '?'},"
            f"fmt={o.get('Formatting') if o is not None else '?'},order={';'.join(orders)}")


def _excel_upl_sig_token(param) -> str:        # id 143 configured UPL — fileType + save mode + ufn + metadata order
    upl = param.find("UniversalPathList")
    ex = upl.find("Excel") if upl is not None else None
    if ex is None:
        return "UniversalPathList"
    ufn = ex.find("Boolean[@type='Use field names as column names']")
    return (f"ExcelUPL:ft={upl.get('fileType')},mode={ex.get('name')}={ex.get('value')},"
            f"ufn={ufn.get('value') if ufn is not None else '?'},"
            f"meta={'|'.join(m.get('type') for m in ex.findall('Parameter'))}")


def _jsonl_field_sig_token(param) -> str:      # id 225 data-complete field — anchor-presence topology
    fr = param.find("FieldReference")
    return f"JSONLField:{'anchored' if (fr is not None and fr.find('TableOccurrenceReference') is not None) else 'bare'}"


def _collapsed_state(step) -> str:
    """The clip's <DisableStepCollapsed state=…> mirrors the DDR Boolean 'Collapsed' param (all
    observed ground truth is False; default False when the param is absent)."""
    b = step.find(".//Parameter[@type='Boolean']/Boolean[@type='Collapsed']")
    return "True" if (b is not None and b.get("value") == "True") else "False"


# ── clip builders ──────────────────────────────────────────────────────────────

def _step_el(ddr_step, *, restore: bool):
    s = ET.Element("Step", {"enable": ddr_step.get("enable", "True"),
                            "id": ddr_step.get("id"), "name": ddr_step.get("name")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(ddr_step)})
    if restore:
        ET.SubElement(s, "Restore", {"state": "False"})
    return s


def _emit_comment(step):                       # 89 — # (comment)
    s = _step_el(step, restore=True)
    c = step.find(".//Parameter[@type='Comment']/Comment")
    val = c.get("value") if c is not None else None
    if val is not None:                        # empty comment (DDR <Comment/>) → no <Text> child
        ET.SubElement(s, "Text").text = val
    return s


def _emit_calc(step, *, restore: bool):        # If (68), Exit Script (103), Exit Loop If (72), Else If (125)
    s = _step_el(step, restore=restore)
    p = step.find(".//Parameter[@type='Calculation']")
    if p is not None:                          # no calc param (e.g. Exit Script w/o result) → no <Calculation>
        ET.SubElement(s, "Calculation").text = _inner_text(p)
    return s


def _emit_set_variable(step):                  # 141 — Set Variable
    s = _step_el(step, restore=False)
    p = step.find(".//Parameter[@type='Variable']")
    if p is None:
        raise ClipEmitError("Set Variable: no Variable parameter")
    vnode = p.find("value")                    # packet 1129 — an empty <value/> OMITS <Value> entirely
    if vnode is not None and vnode.find("Calculation") is not None:
        v = ET.SubElement(s, "Value"); ET.SubElement(v, "Calculation").text = _inner_text(vnode)
    r = ET.SubElement(s, "Repetition"); ET.SubElement(r, "Calculation").text = _inner_text(p.find("repetition"))
    nm = p.find("Name")
    ET.SubElement(s, "Name").text = (nm.get("value") if nm is not None else "") or ""
    return s


def _emit_restore_only(step):                  # Else (69), Else If has calc; block markers with Restore
    return _step_el(step, restore=True)


def _emit_bare(step):                          # End If (70), End Loop (73) — DisableStepCollapsed only
    return _step_el(step, restore=False)


def _emit_set_field(step):                     # 76 — Set Field (value calc + resolved field + repetition)
    s = _step_el(step, restore=False)
    calc = step.find(".//Parameter[@type='Calculation']")
    if calc is not None:
        ET.SubElement(s, "Calculation").text = _inner_text(calc)
    fr = step.find(".//Parameter[@type='FieldReference']/FieldReference")
    if fr is not None:
        to = fr.find("TableOccurrenceReference")
        attrs = {}
        if to is not None and to.get("name"):
            attrs["table"] = to.get("name")
        attrs["id"] = fr.get("id") or ""
        attrs["name"] = fr.get("name") or ""
        ET.SubElement(s, "Field", attrs)
        rep = fr.find("repetition")
        if rep is not None:
            r = ET.SubElement(s, "Repetition")
            ET.SubElement(r, "Calculation").text = _inner_text(rep)
    return s


# ── packet 1041: eight assembler step types (verified against the SeedDB pair) ──
# Modes/options mapped from the DDR selector to the clip's flat grammar. Only the shapes present in
# the SeedDB ground truth are covered; every other shape is refused by the shape fence (grocery list
# of un-covered variants lives in docs/clip-emit-coverage.md). Constants (CurrentScript=Pause,
# Restore states) are the fixed values FileMaker itself writes across all observed occurrences.

_GOTO_LAYOUT_DEST = {"5": "SelectedLayout", "1": "OriginalLayout",
                     "3": "LayoutNameByCalc", "4": "LayoutNumberByCalc"}
_GOTO_RECORD_LOC = {"First": "First", "Next": "Next", "By Calculation…": "ByCalculation"}


def _emit_set_error_capture(step):             # 86 — FM's clipboard carries NO On/Off state (bare)
    return _step_el(step, restore=False)       # both On and Off round-trip to this exact bare clip


# ── packet 1044: trivial-shape step types (bare / NoInteract / duration) ────────
# Verified byte-exact against every occurrence in the committed SeedDB pair. Bare ids reuse _emit_bare
# (10, incl. 85/168 whose DDR on/off boolean the clip drops, like 86). The two below cover the shapes
# SeedDB evidences; every other shape of these ids is refused by the per-shape fence.

def _emit_noninteract(step):                   # 9/10/26/40/51/65/95/104/117 — "With dialog" → NoInteract
    # Output order (all family ids): NoInteract · DisableStepCollapsed · optional id-26 count Calculation.
    # id 117's second `Create folders` Boolean is DELIBERATELY projected away (the clip carries no
    # CreateDirectories for it) — sound ONLY because _cap_execute_sql validates its value (False) before
    # this runs; a capable shape is all this helper ever receives (packet 1103).
    s = ET.Element("Step", {"enable": step.get("enable", "True"),
                            "id": step.get("id"), "name": step.get("name")})
    b = step.find(".//Parameter[@type='Boolean']/Boolean[@type='With dialog']")
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if (b is not None and b.get("value") == "False") else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    calc = step.find(".//Parameter[@type='Calculation']")
    if calc is not None:                       # Omit Multiple's count calc (absent on Delete/Execute SQL)
        ET.SubElement(s, "Calculation").text = _inner_text(calc)
    return s


def _emit_pause_resume(step):                  # 62 — Duration mode: PauseTime ForDuration + seconds calc
    s = _step_el(step, restore=False)
    ET.SubElement(s, "PauseTime", {"value": "ForDuration"})
    ET.SubElement(s, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Options']"))
    return s


# ── packet 1045: bin ④ tranche 1 — selector / option-boolean steps ──────────────
# Verified byte-exact across every SeedDB occurrence. Child ORDER is significant (the fence canonicalises
# whitespace + attribute order, but compares children positionally) — some option elements precede
# DisableStepCollapsed, so these build the exact order FileMaker writes. Only observed shapes are
# verified; other modes (Adjust Window Minimize/Hide, etc.) are refused by the per-shape fence.

# packet 1107 — this ALSO serves as Adjust Window's independent capability value authority: `_cap_adjust_
# window` refuses any List mode not in this map BEFORE `_emit_adjust_window`'s `_ADJUST_WINDOW[...]` lookup
# (which would otherwise KeyError). It is a literal map, never derived from `_VERIFIED_SIGS`.
_ADJUST_WINDOW = {"Maximize": "Maximize", "Resize to Fit": "ResizeToFit", "Hide": "Hide"}  # packet 1129 — Hide


def _new_step(step):                           # empty <Step> shell (for manual child ordering)
    return ET.Element("Step", {"enable": step.get("enable", "True"),
                               "id": step.get("id"), "name": step.get("name")})


def _bool_state(step, btype):                  # a named option Boolean's value; 'False' if absent
    for b in step.findall(".//Parameter[@type='Boolean']/Boolean"):   # matched in Python, not XPath,
        if b.get("type") == btype:                                    # so a btype with an apostrophe
            return b.get("value")                                     # (Save-as-XML) is safe
    return "False"


def _emit_save_addon(step):                    # 96 — LinkAvail (Replace-UUIDs bool), then bare
    s = _new_step(step)
    ET.SubElement(s, "LinkAvail", {"state": _bool_state(step, "Replace UUIDs")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    return s


def _emit_show_hide_menubar(step):             # 166 — Lock, bare, ShowHide (= List name)
    s = _new_step(step)
    ET.SubElement(s, "Lock", {"state": _bool_state(step, "Lock")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "ShowHide", {"value": step.find(".//Parameter[@type='List']/List").get("name")})
    return s


def _emit_show_hide_toolbars(step):            # 29 — IncludeEditRecordToolbar, Lock, bare, ShowHide
    s = _new_step(step)
    ET.SubElement(s, "IncludeEditRecordToolbar",
                  {"state": _bool_state(step, "Include Edit Record Toolbar")})
    ET.SubElement(s, "Lock", {"state": _bool_state(step, "Lock")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "ShowHide", {"value": step.find(".//Parameter[@type='List']/List").get("name")})
    return s


def _emit_install_menu_set(step):              # 142 — UseAsFileDefault, bare, CustomMenuSet ref
    s = _new_step(step)
    ref = step.find(".//Parameter[@type='CustomMenuSet']/CustomMenuSetReference")
    u = ref.find("Boolean[@type='Use as file default']")
    ET.SubElement(s, "UseAsFileDefault", {"state": u.get("value") if u is not None else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "CustomMenuSet", {"id": ref.get("id") or "", "name": ref.get("name") or ""})
    return s


def _emit_adjust_window(step):                 # 31 — bare, then WindowState (mapped from the List name)
    s = _step_el(step, restore=False)
    ET.SubElement(s, "WindowState",
                  {"value": _ADJUST_WINDOW[step.find(".//Parameter[@type='List']/List").get("name")]})
    return s


def _emit_constrain_found(step):               # 126 — Option (find-without-indexes), bare, Restore off
    s = _new_step(step)
    ET.SubElement(s, "Option", {"state": _bool_state(step, "Find without indexes")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Restore", {"state": "False"})
    return s


def _emit_enter_browse(step):                  # 55 — bare, then Pause
    s = _step_el(step, restore=False)
    ET.SubElement(s, "Pause", {"state": _bool_state(step, "Pause")})
    return s


def _emit_extend_found(step):                  # 127 — bare, then Restore off (no params)
    return _step_el(step, restore=True)


# ── packet 1045: bin ④ tranche 2 — object-name family + ESS/status steps ────────

def _emit_object_name(step):                   # 145 Go to Object, 167 Refresh Object, 180 Refresh Portal
    s = _step_el(step, restore=False)
    p = step.find(".//Parameter[@type='Object']")
    on = ET.SubElement(s, "ObjectName")
    ET.SubElement(on, "Calculation").text = _inner_text(p.find("Name"))
    rep = p.find("repetition")                 # absent for Refresh Portal
    if rep is not None:
        r = ET.SubElement(s, "Repetition")
        ET.SubElement(r, "Calculation").text = _inner_text(rep)
    return s


def _emit_perform_js(step):                    # 175 — ObjectName + FunctionName + empty Parameters
    s = _step_el(step, restore=False)
    on = ET.SubElement(s, "ObjectName")
    ET.SubElement(on, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Name']"))
    fn = ET.SubElement(s, "FunctionName")
    ET.SubElement(fn, "Calculation").text = _inner_text(step.find(".//Parameter[@type='FunctionRef']"))
    argp = step.find(".//Parameter[@type='Parameter']")     # packet 1129 — N JS arguments
    args = argp.findall("Calculation") if argp is not None else []
    ps = ET.SubElement(s, "Parameters", {"Count": str(len(args))})
    for a in args:
        pel = ET.SubElement(ps, "P")
        ET.SubElement(pel, "Calculation").text = _inner_text(a)
    return s


def _emit_commit_records(step):                # 75 — NoInteract / Option / ESSForceCommit
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "Option", {"state": _bool_state(step, "Skip data entry validation")})
    ET.SubElement(s, "ESSForceCommit", {"state": _bool_state(step, "Force Commit")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    return s


def _emit_refresh_window(step):                # 80 — Option (join) / FlushSQLData (external)
    s = _new_step(step)
    ET.SubElement(s, "Option", {"state": _bool_state(step, "Flush cached join results")})
    ET.SubElement(s, "FlushSQLData", {"state": _bool_state(step, "Flush cached external data")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    return s


def _emit_open_transaction(step):              # 205 — Option / ESSForceCommit / SkipAutoEntry / Restore
    s = _new_step(step)
    ET.SubElement(s, "Option", {"state": _bool_state(step, "Skip data entry validation")})
    ET.SubElement(s, "ESSForceCommit", {"state": _bool_state(step, "Override ESS locking conflicts")})
    ET.SubElement(s, "SkipAutoEntry", {"state": _bool_state(step, "Skip auto-enter options")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Restore", {"state": "False"})
    return s


# ── packet 1045: bin ④ tranche 3 — window / field / account / file steps ────────

def _window_ref(s, step):
    """Append LimitToWindowsOfCurrentFile + Window from a WindowReference param; return the <Select>."""
    sel = step.find(".//Parameter[@type='WindowReference']/WindowReference/Select")
    if sel is not None and sel.get("type") == "Calculated":
        nm = sel.find("Name")
        ET.SubElement(s, "LimitToWindowsOfCurrentFile",
                      {"state": (nm.get("current") if nm is not None else None) or "False"})
        ET.SubElement(s, "Window", {"value": "ByName"})
    else:
        ET.SubElement(s, "LimitToWindowsOfCurrentFile", {"state": "False"})
        ET.SubElement(s, "Window", {"value": "Current"})
    return sel


def _emit_window_named(step):                  # 121 Close Window, 123 Select Window (opt. by-name calc)
    s = _step_el(step, restore=False)
    sel = _window_ref(s, step)
    nm = sel.find("Name") if sel is not None else None
    if nm is not None:
        n = ET.SubElement(s, "Name")
        ET.SubElement(n, "Calculation").text = _inner_text(nm)
    return s


def _emit_set_window_title(step):              # 124 — window ref + NewName (the Rename calc)
    s = _step_el(step, restore=False)
    _window_ref(s, step)
    nn = ET.SubElement(s, "NewName")
    ET.SubElement(nn, "Calculation").text = _inner_text(
        step.find(".//Parameter[@type='WindowReference']/WindowReference/Rename"))
    return s


def _emit_goto_field(step):                    # 17 — SelectAll, bare, optional Field/Repetition (packet 1129)
    s = _new_step(step)
    ET.SubElement(s, "SelectAll", {"state": _bool_state(step, "Select/perform")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    fr = step.find(".//Parameter[@type='FieldReference']/FieldReference")
    if fr is None:                             # no-field form — SelectAll only
        return s
    to = fr.find("TableOccurrenceReference")
    attrs = {}
    if to is not None and to.get("name"):
        attrs["table"] = to.get("name")
    attrs["id"] = fr.get("id") or ""
    attrs["name"] = fr.get("name") or ""
    ET.SubElement(s, "Field", attrs)
    rep = fr.find("repetition")
    if rep is not None:
        r = ET.SubElement(s, "Repetition")
        ET.SubElement(r, "Calculation").text = _inner_text(rep)
    return s


def _emit_open_url(step):                      # 111 — NoInteract / Option / bare / URL calc
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "Option", {"state": _bool_state(step, "In external browser")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Calculation").text = _inner_text(step.find(".//Parameter[@type='URL']"))
    return s


def _emit_delete_account(step):                # 135 — AccountName calc
    s = _step_el(step, restore=False)
    an = ET.SubElement(s, "AccountName")
    ET.SubElement(an, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Calculation']"))
    return s


def _emit_enable_account(step):                # 137 — AccountOperation (Activate/Deactivate) + AccountName
    s = _step_el(step, restore=False)
    b = step.find(".//Parameter[@type='Boolean']/Boolean[@type='enable']")
    ET.SubElement(s, "AccountOperation", {"value": b.get("name")})
    an = ET.SubElement(s, "AccountName")
    ET.SubElement(an, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Calculation']"))
    return s


def _emit_close_file(step):                    # 34 — current file only (bare); external fenced by sig
    return _step_el(step, restore=False)


# ── packet 1049: bin ④ tranche 7 — window/layout steps with NewWndStyles ────────

_NEWWND_DEFAULT = {"Style": "Document", "Close": "Yes", "Minimize": "Yes",   # baked default when a step
                   "Maximize": "Yes", "Resize": "Yes", "Styles": "3606018"}  # isn't opening a new window


def _newwnd_from_window(wref):
    """<NewWndStyles …> attrs from a WindowReference's <Style> + <Options> (each option bool
    True→Yes / False→No). The full 9-attr set (adds DimParentWindow/Toolbars/MenuBar)."""
    style = wref.find("Style")
    opts = wref.find("Options")
    def _yn(tag):
        e = opts.find(tag) if opts is not None else None
        return "Yes" if (e is not None and (e.text or "").strip() == "True") else "No"
    return {"DimParentWindow": _yn("DimParentWindow"), "Toolbars": _yn("Toolbar"),
            "MenuBar": _yn("MenuBar"), "Style": style.get("name") if style is not None else "",
            "Close": _yn("Close"), "Minimize": _yn("Minimize"), "Maximize": _yn("Maximize"),
            "Resize": _yn("Resize"), "Styles": style.get("value") if style is not None else ""}


def _append_layout(s, lrc):
    """A LayoutReferenceContainer → clip <Layout> element: a <Calculation> (name/number-by-calc) or a
    resolved id/name reference; nothing when the container carries neither."""
    calc = lrc.find("Calculation")
    ref = lrc.find("LayoutReference")
    if calc is not None:
        lay = ET.SubElement(s, "Layout")
        ET.SubElement(lay, "Calculation").text = _inner_text(lrc)
    elif ref is not None:
        ET.SubElement(s, "Layout", {"id": ref.get("id") or "", "name": ref.get("name") or ""})


def _emit_goto_related(step):                  # 74 — Go to Related Record
    rel = step.find(".//Parameter[@type='Related']")
    wref = rel.find("WindowReference")          # present → show in a new window
    ropts = rel.find("Options")
    s = _new_step(step)
    ET.SubElement(s, "Option", {"state": "False"})
    ET.SubElement(s, "MatchAllRecords",
                  {"state": "True" if (ropts is not None and ropts.get("matchFoundSet") == "True") else "False"})
    ET.SubElement(s, "ShowInNewWindow", {"state": "True" if wref is not None else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Restore", {"state": "True"})
    lrc = rel.find("LayoutReferenceContainer")
    ET.SubElement(s, "LayoutDestination", {"value": _GOTO_LAYOUT_DEST[lrc.get("value")]})
    if wref is not None:
        _append_bounds(s, wref.find("Bounds"))
    ET.SubElement(s, "NewWndStyles", _newwnd_from_window(wref) if wref is not None else dict(_NEWWND_DEFAULT))
    to = rel.find("TableOccurrenceReference")
    ET.SubElement(s, "Table", {"id": to.get("id") if to is not None else "0",
                               "name": to.get("name") if to is not None else ""})
    _append_layout(s, lrc)
    return s


def _emit_new_window(step):                    # 122 — New Window
    wref = step.find(".//Parameter[@type='WindowReference']/WindowReference")
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    lrc = wref.find("LayoutReferenceContainer")
    ET.SubElement(s, "LayoutDestination", {"value": _GOTO_LAYOUT_DEST[lrc.get("value")]})
    nm = wref.find("Name")
    if nm is not None and nm.find("Calculation") is not None:   # empty-string name still emits <Name>
        n = ET.SubElement(s, "Name")
        ET.SubElement(n, "Calculation").text = _inner_text(nm)
    _append_bounds(s, wref.find("Bounds"))
    ET.SubElement(s, "NewWndStyles", _newwnd_from_window(wref))
    _append_layout(s, lrc)
    return s


_GOTO_LIST_DEST = {"1": "CurrentLayout"}       # Go to List of Records LRC-value → destination (observed)


def _emit_goto_list(step):                     # 228 — Go to List of Records
    s = _new_step(step)
    ET.SubElement(s, "ShowInNewWindow", {"state": "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    lrc = step.find(".//Parameter[@type='LayoutReferenceContainer']/LayoutReferenceContainer")
    ET.SubElement(s, "LayoutDestination", {"value": _GOTO_LIST_DEST[lrc.get("value")]})
    ET.SubElement(s, "NewWndStyles", dict(_NEWWND_DEFAULT))
    return s


# ── packet 1050: bin ④ tranche 8 — Show Custom Dialog ──────────────────────────

_DIALOG_GEOMETRY = (("height", "Height"), ("width", "Width"),
                    ("top", "DistanceFromTop"), ("left", "DistanceFromLeft"))


def _emit_show_custom_dialog(step):            # 87 — Title? / Message / geometry? / 3 Buttons / 3 InputFields?
    s = _step_el(step, restore=False)
    title = step.find(".//Parameter[@type='Title']")
    if title is not None:
        t = ET.SubElement(s, "Title")
        ET.SubElement(t, "Calculation").text = _inner_text(title)
    m = ET.SubElement(s, "Message")
    ET.SubElement(m, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Message']"))
    for ddr_t, clip_t in _DIALOG_GEOMETRY:      # packet 1120 — each present dimension → its wrapper; absent → omitted
        g = step.find(f"ParameterValues/Parameter[@type='{ddr_t}']")
        if g is not None:
            ET.SubElement(ET.SubElement(s, clip_t), "Calculation").text = _inner_text(g)
    buttons = ET.SubElement(s, "Buttons")       # always exactly three <Button>
    for i in (1, 2, 3):
        bp = step.find(f".//Parameter[@type='Button{i}']")
        commit = bp.find("Boolean[@type='Commit']") if bp is not None else None
        b = ET.SubElement(buttons, "Button",
                          {"CommitState": commit.get("value") if commit is not None else "False"})
        # packet 1120 — two explicit label dialects: legacy `value` attr → a quoted calc literal, OR a child
        # <Calculation> → the calc verbatim (no synthesized quotes). Never both (capability forbids it).
        attr_label = bp.get("value") if bp is not None else None
        calc_label = bp.find("Calculation") if bp is not None else None
        if attr_label:
            ET.SubElement(b, "Calculation").text = f'"{attr_label}"'
        elif calc_label is not None:
            ET.SubElement(b, "Calculation").text = _inner_text(bp)
    fields = [step.find(f".//Parameter[@type='Field{i}']") for i in (1, 2, 3)]
    if any(f is not None for f in fields):      # any input field → all three <InputField> emitted
        ifs = ET.SubElement(s, "InputFields")
        for f in fields:
            pwd = f.find("Boolean[@type='Password']") if f is not None else None
            inp = ET.SubElement(ifs, "InputField",
                                {"UsePasswordCharacter": pwd.get("value") if pwd is not None else "False"})
            tgt = f.find("Parameter[@type='Target']") if f is not None else None
            var = tgt.find("Variable") if tgt is not None else None
            fr = tgt.find("FieldReference") if tgt is not None else None
            if var is not None:
                ET.SubElement(inp, "Field").text = var.get("value")
            elif fr is not None:
                to = fr.find("TableOccurrenceReference")
                ET.SubElement(inp, "Field", {"table": to.get("name") if to is not None else "",
                                             "id": fr.get("id") or "", "name": fr.get("name") or ""})
            else:                               # empty input slot
                ET.SubElement(inp, "Field", {"table": "", "id": "0", "name": ""})
            lbl = f.find("Parameter[@type='Label']") if f is not None else None
            if lbl is not None:
                lb = ET.SubElement(inp, "Label")
                ET.SubElement(lb, "Calculation").text = _inner_text(lbl)
    return s


# ── packet 1051: bin ④ tranche 9 — Insert from URL / Export Field Contents ──────

def _emit_insert_from_url(step):               # 160 — cURL / SSL / encode options + target
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    url = step.find(".//Parameter[@type='URL']/URL")
    ET.SubElement(s, "DontEncodeURL", {"state": "False" if url.get("autoEncode") == "True" else "True"})
    ET.SubElement(s, "SelectAll", {"state": _bool_state(step, "Select")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "VerifySSLCertificates", {"state": _bool_state(step, "Verify SSL Certificates")})
    curl = step.find(".//Parameter[@type='Calculation']")
    if curl is not None:
        co = ET.SubElement(s, "CURLOptions")
        ET.SubElement(co, "Calculation").text = _inner_text(curl)
    ET.SubElement(s, "Calculation").text = _inner_text(step.find(".//Parameter[@type='URL']"))
    _append_result_target(s, step)
    return s


def _emit_export_field(step):                  # 132 — Export Field Contents
    s = _new_step(step)
    ET.SubElement(s, "CreateDirectories", {"state": _bool_state(step, "Create folders")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    upl = step.find(".//Parameter[@type='UniversalPathList']/UniversalPathList")
    ET.SubElement(s, "AutoOpen", {"state": upl.get("AutoOpen") if upl is not None else "False"})
    ET.SubElement(s, "CreateEmail", {"state": "False"})   # no email option on Export Field Contents
    if upl is not None:
        loc = upl.find(".//Location")
        ET.SubElement(s, "UniversalPathList").text = (loc.text if loc is not None else "")
    fr = step.find(".//Parameter[@type='FieldReference']/FieldReference")
    to = fr.find("TableOccurrenceReference")
    attrs = {}
    if to is not None and to.get("name"):
        attrs["table"] = to.get("name")
    attrs["id"] = fr.get("id") or ""
    attrs["name"] = fr.get("name") or ""
    ET.SubElement(s, "Field", attrs)
    rep = fr.find("repetition")
    if rep is not None:
        r = ET.SubElement(s, "Repetition")
        ET.SubElement(r, "Calculation").text = _inner_text(rep)
    return s


def _emit_delete_file(step):                   # 197 — UniversalPathList (single Location text)
    s = _step_el(step, restore=False)
    loc = step.find(".//Parameter[@type='UniversalPathList']//Location")
    ET.SubElement(s, "UniversalPathList").text = (loc.text if loc is not None else "")
    return s


# ── packet 1052: bin ④ tranche 10 — Save a Copy as XML / Print ──────────────────

_PRINT_TYPE = {"Current record": "CurrentRecord", "Records being browsed": "BrowsedRecords"}


def _emit_save_as_xml(step):                   # 3 — Save a Copy as XML (fully DDR-derivable)
    s = _new_step(step)
    ET.SubElement(s, "Option", {"state": _bool_state(step, "Include details for analysis tools")})
    ET.SubElement(s, "OutputEntireBinaryData",
                  {"state": _bool_state(step, "Save each layout object's binary data under its node")})
    ET.SubElement(s, "SpecifyJSONOptions", {"state": _bool_state(step, "Specify options as JSON")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    loc = step.find(".//Parameter[@type='UniversalPathList']//Location")
    ET.SubElement(s, "UniversalPathList").text = (loc.text if loc is not None else "")
    ET.SubElement(s, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Calculation']"))
    ET.SubElement(s, "SaXML")
    return s


def _emit_print_setup(step):                   # 42 — Print Setup
    """Two shapes, and only one of them is honest.

    * `PageSetup:empty` (the DDR carries no saved page setup) — the real clip has NO `<PageFormat>` at
      all, so this shape is FULLY reproducible. Ordinary class-1 coverage; nothing is lost.
    * `PageSetup:set` — the real clip's `<PageFormat>` carries printer-COMPUTED geometry
      (`PrintableHeight`/`PrintableWidth`/`Paper*`) plus a machine-specific `PlatformData` ticket, none
      of which the DDR holds. We emit only the two attributes the DDR *does* hold (orientation, scale)
      and mask the rest. That clip is **source-incomplete** — it is NOT byte-exact and never can be, so
      it is registered in `_SOURCE_INCOMPLETE_SIGS`, not `_VERIFIED_SIGS`, and is emitted only on
      explicit request.
    """
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    rest = step.find(".//Parameter[@type='Restore']/Restore")
    ET.SubElement(s, "Restore", {"state": rest.get("value") if rest is not None else "False"})
    ps = step.find(".//Parameter[@type='PageSetup']/PageSetup")
    if ps is None or not len(ps):
        return s                               # the complete, faithful shape
    o = ps.find("Orientation")
    sc = ps.find("scale")
    # PASTE TEST: GREEN (dev, 2026-07-15, FM Pro 2026 on macOS). The masked clip PASTES; FileMaker fills
    # its own printer defaults for everything we omit (the local printer + its paper), and orientation +
    # scale survive exactly as emitted. So the opt-in emit-semantic-only path STAYS. Arguably it is the
    # better outcome than the "complete" one: a clip pasted on another machine gets THAT machine's
    # printer geometry rather than the exporter's driver blob.
    #
    # ⚠ PAPER SIZE IS A CLASS-1 LOSS INSIDE THIS CLASS-2 GAP — PROVEN 2026-07-15, not inferred.
    # The dev pasted our masked clip and re-exported: FileMaker's stored DDR came back
    # <size height="1100" width="850"/> — US Letter, its LOCAL DEFAULT — because our clip carries no
    # size at all. An A4 step round-trips through us as US Letter.
    #   The A4 capture (stepsamples_A, Portrait + Landscape) settles the encoding:
    #     paper_pt    = DDR <size> x 0.72        A4 826.39x1169.44 -> 595x842 ✓ ; Letter 850x1100 -> 612x792 ✓
    #     PaperRight  = PaperLeft + width_pt     -18 + 595 = 577 ✓
    #     PaperBottom = PaperTop  + height_pt    -18 + 842 = 824 ✓
    #   Orientation does NOT rotate the rect (A4 P/L share it); only Printable* swaps. And MMod is not
    #   opaque — it is an orientation byte + float32[scale,L,T,R,B,PrW,PrH], i.e. a struct of the
    #   attributes beside it.
    # So the residue is smaller and sharper than "Print Setup is class-2": the paper SIZE is class-1 and
    # recoverable; only the MARGIN it is measured from (-18,-18, the driver's) and Printable*/M_PM are
    # class-2. The rect ENTANGLES size with margin, which is why we still emit neither — emitting
    # PaperRight = -18 + 595 asserts a -18 margin observed on exactly ONE printer.
    # NOT FIXED: the next step is a PROBE, not an emit — paste a hand-built PageFormat with a ZERO
    # origin (0,0,595,842) and see whether FM honours the size while recomputing the margin, which is
    # what it already does for everything we omit. See docs/clip-emit-coverage.md.
    ET.SubElement(s, "PageFormat", {
        "PageOrientation": (o.get("name") if o is not None else "Portrait"),
        "ScaleFactor": _scale_factor(sc.get("value") if sc is not None else "100")})
    return s


def _scale_factor(ddr_scale: str) -> str:
    """DDR percent ('100'/'50') → the clip's ScaleFactor ('1'/'.5'). FileMaker writes a leading-dot
    decimal and trims trailing zeros, so 50 → '.5', not '0.50' — observed across the captured pairs."""
    try:
        v = float(ddr_scale) / 100.0
    except (TypeError, ValueError):
        return "1"
    if v == int(v):
        return str(int(v))
    return f"{v:g}".lstrip("0")                # 0.5 → '.5'


def _emit_print(step):                         # 43 — Print (PrintSettings; PageSetup geometry dropped)
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    rest = step.find(".//Parameter[@type='Restore']/Restore")
    ET.SubElement(s, "Restore", {"state": rest.get("value") if rest is not None else "False"})
    pr = step.find(".//Parameter[@type='Print']/Print")
    pages = pr.find("Pages")
    copies = pr.find("Copies")
    ET.SubElement(s, "PrintSettings", {
        "PageNumberingOffset": "0", "PrintToFile": pr.get("toFile"),
        "AllPages": pages.get("All") if pages is not None else "True", "collated": "True",
        "NumCopies": copies.get("value") if copies is not None else "1",
        "PrintType": _PRINT_TYPE[pr.get("name")]})
    return s


# ── packet 1045: bin ④ tranche 4 — account family + portal / sort / web viewer ──

def _unknown_to_empty(name):                   # DDR's "<unknown>" reference name → the clip's empty name
    return "" if name == "<unknown>" else (name or "")


def _account_name_password(s, step):           # shared: AccountName + Password calc pair
    an = ET.SubElement(s, "AccountName")
    ET.SubElement(an, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Name']"))
    pw = ET.SubElement(s, "Password")
    ET.SubElement(pw, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Password']"))


def _emit_reset_password(step):                # 136 — ChgPwdOnNextLogin + AccountName + Password
    s = _step_el(step, restore=False)
    b = step.find(".//Parameter[@type='Boolean']/Boolean[@type='Password']")
    ET.SubElement(s, "ChgPwdOnNextLogin", {"value": b.get("value") if b is not None else "False"})
    _account_name_password(s, step)
    return s


def _emit_add_account(step):                   # 134 — + PrivilegeSet + AddAccount/AccountType
    s = _step_el(step, restore=False)
    b = step.find(".//Parameter[@type='Boolean']/Boolean[@type='Expire password']")
    ET.SubElement(s, "ChgPwdOnNextLogin", {"value": b.get("value") if b is not None else "False"})
    _account_name_password(s, step)
    pr = step.find(".//Parameter[@type='PrivilegeSetReference']/PrivilegeSetReference")
    ET.SubElement(s, "PrivilegeSet", {"id": pr.get("id") or "", "name": _unknown_to_empty(pr.get("name"))})
    aa = ET.SubElement(s, "AddAccount")
    ET.SubElement(aa, "AccountType").text = step.find(".//Parameter[@type='AccountType']/List").get("name")
    return s


def _emit_relogin(step):                       # 138 — NoInteract + FileReference + AccountName/Password
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ds = step.find(".//Parameter[@type='DataSourceReference']/DataSourceReference")
    ET.SubElement(s, "FileReference", {"id": ds.get("id") or "", "name": _unknown_to_empty(ds.get("name"))})
    _account_name_password(s, step)
    return s


_GOTO_PORTAL_SIMPLE = {"First": "First", "Last": "Last", "Next": "Next", "Previous": "Previous"}  # packet 1129
_GOTO_PORTAL_EXIT_MODES = frozenset({"Next", "Previous"})   # carry an optional bounded 'Exit after last' Boolean


def _emit_goto_portal_row(step):               # 99 — By-Calculation mode + the direct nav modes (packet 1129)
    s = _new_step(step)
    p = step.find(".//Parameter[@type='Portal']/List")
    mode = p.get("name")
    if mode == _GOTO_PORTAL_MODE:              # By Calculation…
        wd = p.find("Boolean[@type='With dialog']")
        ET.SubElement(s, "NoInteract",
                      {"state": "True" if (wd is not None and wd.get("value") == "False") else "False"})
        ET.SubElement(s, "SelectAll", {"state": _bool_state(step, "Select")})
        ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
        ET.SubElement(s, "RowPageLocation", {"value": "ByCalculation"})
        ET.SubElement(s, "Calculation").text = _inner_text(p)
        return s
    ET.SubElement(s, "NoInteract", {"state": "False"})     # direct nav has no dialog
    ET.SubElement(s, "SelectAll", {"state": _bool_state(step, "Select")})
    exit_after = p.find("Boolean[@type='Exit after last']")
    if exit_after is not None:
        ET.SubElement(s, "Exit", {"state": exit_after.get("value")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "RowPageLocation", {"value": _GOTO_PORTAL_SIMPLE[mode]})
    return s


def _emit_sort_by_field(step):                 # 154 — SortRecordsByField (Sort<dir>) + Field + Repetition
    s = _step_el(step, restore=False)
    l = step.find(".//Parameter[@type='List']/List")
    ET.SubElement(s, "SortRecordsByField", {"value": "Sort" + l.get("name")})
    fr = step.find(".//Parameter[@type='FieldReference']/FieldReference")
    if fr is None:                             # packet 1129 — the no-field (direction-only) form
        return s
    to = fr.find("TableOccurrenceReference")
    attrs = {}
    if to is not None and to.get("name"):
        attrs["table"] = to.get("name")
    attrs["id"] = fr.get("id") or ""
    attrs["name"] = fr.get("name") or ""
    ET.SubElement(s, "Field", attrs)
    rep = fr.find("repetition")
    if rep is not None:
        r = ET.SubElement(s, "Repetition")
        ET.SubElement(r, "Calculation").text = _inner_text(rep)
    return s


_WEBVIEWER_ACTION = {"Go to URL...": "GoToURL"}   # observed only; other actions fenced


def _emit_set_web_viewer(step):                # 146 — Action + ObjectName + URL (Go-to-URL mode)
    s = _step_el(step, restore=False)
    act = step.find(".//Parameter[@type='action']/List")
    ET.SubElement(s, "Action", {"value": _WEBVIEWER_ACTION[act.get("name")]})
    on = ET.SubElement(s, "ObjectName")
    ET.SubElement(on, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Calculation']"))
    u = ET.SubElement(s, "URL", {"custom": "False"})
    ET.SubElement(u, "Calculation").text = _inner_text(act)
    return s


def _emit_install_ontimer(step):               # 148 — clear (bare), or Script + Interval (packet 1129)
    s = _step_el(step, restore=False)
    sr = step.find(".//Parameter[@type='ScriptReference']/ScriptReference")
    if sr is not None:
        i = ET.SubElement(s, "Interval")
        ET.SubElement(i, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Calculation']"))
        ET.SubElement(s, "Script", {"id": sr.get("id") or "", "name": sr.get("name") or ""})
    return s


def _emit_perform_quick_find(step):            # 150 — bare, or a search-term Calculation (packet 1129)
    s = _step_el(step, restore=False)
    p = step.find(".//Parameter[@type='Calculation']")
    if p is not None:
        ET.SubElement(s, "Calculation").text = _inner_text(p)
    return s


def _emit_set_field_by_name(step):             # 147 — Result (pos 0) then TargetName (pos 1)
    s = _step_el(step, restore=False)
    calcs = step.findall(".//Parameter[@type='Calculation']")
    def _pos(p):
        c = p.find("Calculation")
        return c.get("position") if c is not None else None
    result = next((c for c in calcs if _pos(c) == "0"), None)
    target = next((c for c in calcs if _pos(c) == "1"), None)
    r = ET.SubElement(s, "Result")
    ET.SubElement(r, "Calculation").text = _inner_text(result)
    t = ET.SubElement(s, "TargetName")
    ET.SubElement(t, "Calculation").text = _inner_text(target)
    return s


# ── packet 1047: bin ④ tranche 5 — password / calc-into-target / PSoS / move-window ─

def _emit_change_password(step):               # 83 — NoInteract + OldPassword + NewPassword
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    op = ET.SubElement(s, "OldPassword")
    ET.SubElement(op, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Old']"))
    np = ET.SubElement(s, "NewPassword")
    ET.SubElement(np, "Calculation").text = _inner_text(step.find(".//Parameter[@type='New']"))
    return s


def _append_result_target(s, step):
    """A Target param → either a resolved <Field …/> (field ref) or a <Text/> + <Field>$var</Field>
    (variable), with a trailing <Repetition>. Shared by Insert Calculated Result / Execute Data API."""
    fr = step.find(".//Parameter[@type='Target']/FieldReference")
    var = step.find(".//Parameter[@type='Target']/Variable")
    rep = None
    if fr is not None:
        to = fr.find("TableOccurrenceReference")
        attrs = {}
        if to is not None and to.get("name"):
            attrs["table"] = to.get("name")
        attrs["id"] = fr.get("id") or ""
        attrs["name"] = fr.get("name") or ""
        ET.SubElement(s, "Field", attrs)
        rep = fr.find("repetition")
    elif var is not None:
        ET.SubElement(s, "Text")
        ET.SubElement(s, "Field").text = var.get("value")
        rep = var.find("repetition")
    if rep is not None:
        r = ET.SubElement(s, "Repetition")
        ET.SubElement(r, "Calculation").text = _inner_text(rep)


def _emit_calc_into_target(step):              # 77 Insert Calculated Result, 203 Execute Data API
    s = _new_step(step)
    ET.SubElement(s, "SelectAll", {"state": _bool_state(step, "Select")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Calculation").text = _inner_text(step.find(".//Parameter[@type='Calculation']"))
    _append_result_target(s, step)
    return s


def _emit_perform_script_server(step):         # 164 — like Perform Script but WaitForCompletion
    lst = step.find(".//Parameter[@type='List']/List")
    param = step.find(".//Parameter[@type='Parameter']/Parameter")
    param_calc = _inner_text(param) if param is not None else ""
    wait = _bool_state(step, "Wait for completion")
    s = _new_step(step)
    if lst.get("name") == "By name":
        cd = ET.SubElement(s, "Calculated")
        ET.SubElement(cd, "Calculation").text = _inner_text(lst)
        ET.SubElement(s, "WaitForCompletion", {"state": wait})
        ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
        if param_calc:
            ET.SubElement(s, "Calculation").text = param_calc
        return s
    ET.SubElement(s, "WaitForCompletion", {"state": wait})   # From list
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    if param_calc:
        ET.SubElement(s, "Calculation").text = param_calc
    ref = lst.find("ScriptReference")
    if ref is not None:
        ET.SubElement(s, "Script", {"id": ref.get("id") or "", "name": ref.get("name") or ""})
    return s


def _append_bounds(s, bounds):
    """A window <Bounds> → clip <Height>/<Width>/<DistanceFromTop>/<DistanceFromLeft> for each
    PRESENT (non-empty) dimension calc, in that order. Shared by Move/Resize, New Window, GTRR."""
    if bounds is None:
        return
    for tag, elt in (("height", "Height"), ("width", "Width"),
                     ("top", "DistanceFromTop"), ("left", "DistanceFromLeft")):
        txt = _inner_text(bounds.find(tag))
        if txt:
            c = ET.SubElement(s, elt)
            ET.SubElement(c, "Calculation").text = txt


def _emit_move_resize_window(step):            # 119 — window ref + present bounds calcs
    s = _step_el(step, restore=False)
    _window_ref(s, step)
    _append_bounds(s, step.find(".//Parameter[@type='WindowReference']/WindowReference/Bounds"))
    return s


_LOOP_FLUSH = {"Minimum": "Min"}               # 1069§②: DDR "Minimum" → clip "Min"; Always/Defer pass through


def _emit_loop(step):                          # 71 — Restore + FlushType from the flush List name
    s = _step_el(step, restore=True)
    nm = (step.find(".//Parameter[@type='List']/List").get("name")) or ""
    ET.SubElement(s, "FlushType", {"value": _LOOP_FLUSH.get(nm, nm)})
    return s


def _emit_enter_find_mode(step):               # 22 — Pause (mirrors DDR) then Restore
    s = _step_el(step, restore=False)
    b = step.find(".//Parameter[@type='Boolean']/Boolean[@type='Pause']")
    ET.SubElement(s, "Pause", {"state": (b.get("value") if b is not None else "False")})
    ET.SubElement(s, "Restore", {"state": "False"})
    return s


# packet 1069§② — Go to Layout animation transitions. The DDR names them in prose
# ("Slide in from Left"), the clip in CamelCase ("SlideFromLeft"); "None" → no <Animation> element.
# Verified byte-exact vs the stepsamples_A OriginalLayout+animation pairs (a dev-authored capture).
_ANIMATION = {"Slide in from Left": "SlideFromLeft", "Slide in from Right": "SlideFromRight",
              "Slide in from Bottom": "SlideFromBottom", "Slide out to Left": "SlideToLeft",
              "Slide out to Right": "SlideToRight", "Slide out to Bottom": "SlideToBottom",
              "Flip from Left": "FlipFromLeft", "Flip from Right": "FlipFromRight",
              "Zoom In": "ZoomIn", "Zoom Out": "ZoomOut", "Cross Dissolve": "CrossDissolve"}


def _emit_goto_layout(step):                   # 6 — LayoutDestination + optional target ref / calc
    s = _step_el(step, restore=False)
    lrc = step.find(".//Parameter[@type='LayoutReferenceContainer']/LayoutReferenceContainer")
    ET.SubElement(s, "LayoutDestination", {"value": _GOTO_LAYOUT_DEST[lrc.get("value")]})
    ref = lrc.find("LayoutReference")
    if ref is not None:                        # value 5 — a specific layout
        ET.SubElement(s, "Layout", {"id": ref.get("id") or "", "name": ref.get("name") or ""})
    elif lrc.find("Calculation") is not None:  # value 3/4 — layout name/number by calculation
        ET.SubElement(ET.SubElement(s, "Layout"), "Calculation").text = _inner_text(lrc)
    anim = step.find(".//Parameter[@type='Animation']/Animation")   # non-None → a transition
    if anim is not None and anim.get("name") != "None":
        ET.SubElement(s, "Animation", {"value": _ANIMATION[anim.get("name")]})
    return s                                    # value 1 (OriginalLayout) — no target element


def _emit_goto_record(step):                   # 16 — NoInteract/Exit + RowPageLocation + optional calc
    l = step.find(".//Parameter[@type='Records']/List")
    wd = l.find("Boolean[@type='With dialog']")
    exit_after = l.find("Boolean[@type='Exit after last']")
    s = ET.Element("Step", {"enable": step.get("enable", "True"),
                            "id": step.get("id"), "name": step.get("name")})
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if (wd is not None and wd.get("value") == "False") else "False"})
    if exit_after is not None and exit_after.get("value") == "True":
        ET.SubElement(s, "Exit", {"state": "True"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "RowPageLocation", {"value": _GOTO_RECORD_LOC[l.get("name")]})
    if l.find("Calculation") is not None:
        ET.SubElement(s, "Calculation").text = _inner_text(l)
    return s


def _emit_perform_find(step):                  # 28 — Restore + Query built from the FindRequestSet
    s = _step_el(step, restore=False)
    fr = step.find(".//Parameter[@type='FindRequest']")
    if fr is None:                             # no stored requests — restore off, no query
        ET.SubElement(s, "Restore", {"state": "False"})
        return s
    ET.SubElement(s, "Restore", {"state": "True"})
    query = ET.SubElement(s, "Query")
    for req in fr.iter("FindRequest"):
        op = "Include" if req.get("action") == "find" else "Omit"
        row = ET.SubElement(query, "RequestRow", {"operation": op})
        for crit_el in [c for c in req if c.tag in ("find", "omit")]:
            crit = ET.SubElement(row, "Criteria")
            fref = crit_el.find("FieldReference")
            to = fref.find("TableOccurrenceReference") if fref is not None else None
            attrs = {}
            if to is not None and to.get("name"):
                attrs["table"] = to.get("name")
            attrs["id"] = fref.get("id") if fref is not None else ""
            attrs["name"] = fref.get("name") if fref is not None else ""
            ET.SubElement(crit, "Field", attrs)
            ET.SubElement(crit, "Text").text = crit_el.get("criteria") or ""
    return s


def _emit_sort_records(step):                  # 39 — NoInteract + Restore + SortList from SortSpecification
    ss = step.find(".//Parameter[@type='SortSpecification']/SortSpecification")
    wd = step.find(".//Parameter[@type='Boolean']/Boolean[@type='With dialog']")
    rst = step.find(".//Parameter[@type='Restore']/Restore")
    s = ET.Element("Step", {"enable": step.get("enable", "True"),
                            "id": step.get("id"), "name": step.get("name")})
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if (wd is not None and wd.get("value") == "False") else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Restore", {"state": (rst.get("value") if rst is not None else "False")})
    if ss is not None:                          # no SortSpecification → "clear the sort" (no SortList)
        sl = ET.SubElement(s, "SortList", {"BlanksLast": ss.get("blanksLast") or "False",
                                           "Maintain": ss.get("maintain") or "False",
                                           "value": ss.get("value") or "True"})
        for sort in ss.find("SortList").findall("Sort"):
            so = ET.SubElement(sl, "Sort", {"type": sort.get("type") or "Ascending"})
            pf = ET.SubElement(so, "PrimaryField")
            fref = sort.find(".//FieldReference")
            to = fref.find("TableOccurrenceReference") if fref is not None else None
            attrs = {}
            if to is not None and to.get("name"):
                attrs["table"] = to.get("name")
            attrs["id"] = fref.get("id") if fref is not None else ""
            attrs["name"] = fref.get("name") if fref is not None else ""
            ET.SubElement(pf, "Field", attrs)
    return s


# ── packet 1053 tranche 2 — base-shape option families (scriptstepsamples master pair) ──

def _first_bool_value(step) -> str:
    """The first `<Parameter type="Boolean">`'s value ('False' if none) — the single option flag these
    base shapes carry (Select / Open-hidden / enabled / Condition)."""
    b = step.find(".//Parameter[@type='Boolean']/Boolean")
    return b.get("value") if b is not None else "False"


def _emit_select_all_bare(step):               # 11-14,18,46,47,49,60 — Select bool → SelectAll, bare
    s = _new_step(step)
    ET.SubElement(s, "SelectAll", {"state": _first_bool_value(step)})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    return s


def _emit_option_bare(step):                   # 33,200,207 — first option bool → Option, bare
    s = _new_step(step)
    ET.SubElement(s, "Option", {"state": _first_bool_value(step)})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    return s


def _emit_insert_embedded(step):               # 56,158,159 — Insert Picture/PDF/Audio-Video (embedded)
    s = _step_el(step, restore=False)          # base shape: no path/field → UniversalPathList Embedded
    ET.SubElement(s, "UniversalPathList", {"type": "Embedded"})
    return s


# ── packet 1053 tranche 3 — base-shape selector / state families ──

def _selector_emitter(tag, vmap=None):
    """Factory: a base shape `<DisableStepCollapsed/><TAG value=…/>` where the value is the step's lone
    selector — a `<List name=…>` (most) or a `<Options type=…>` (Perform AppleScript) — optionally
    remapped. Only used where `_sig_token` captures the selector (List / Options / action), so the
    per-shape fence pins the exact mode and an unseen mode is refused (NOT for a param whose sig token
    collapses the selector, e.g. `Monitor`/`Source` — those stay deferred)."""
    def emit(step):
        lst = step.find(".//ParameterValues//List")
        if lst is not None:
            raw = lst.get("name")
        else:
            o = step.find(".//ParameterValues//Options")
            raw = o.get("type") if o is not None else ""
        s = _new_step(step)
        ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
        ET.SubElement(s, tag, {"value": (vmap or {}).get(raw, raw)})
        return s
    return emit


def _emit_enter_preview(step):                 # 41 — Pause bool → <Pause> after bare
    b = step.find(".//Parameter[@type='Boolean']/Boolean")
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Pause", {"state": b.get("value") if b is not None else "False"})
    return s


# ── packet 1126 — the Data File I/O family (188/189/190/191/192/193/194/195/196) ──
# One bounded family grammar, separate per-step projections. FileMaker's Data File clip KEEPS the path
# (<UniversalPathList>) and the file-handle/target calcs, but DROPS the DDR <Encoding name> (only its @type
# survives, as <DataSourceType value>), the Target <repetition>, and — where the clip is the LOSSIER
# projection — Read's byte-count <size> and Set Position's <position> calc (both target-absent in the clip).
# A Target is a variable ($name → <Text/><Field>$name</Field>) or a field (<Field table id name/>); the two
# forms are signature-discriminated. Ground truth: the paired DF Cases capture (datafile_cases.fmp12,
# variable targets, all nine ids) + the configured-master field targets for 192/193. The empty/default Read
# from Data File is a RECORDED FileMaker clipboard-serializer failure and refuses (never emits).

def _emit_datafile_target(s, param):
    """A Data File Target → <Field table id name/> (field ref) or <Text/> + <Field>$var</Field> (variable).
    No trailing <Repetition> — the Data File clip drops it (unlike 77/203/160's _append_result_target)."""
    fr = param.find("FieldReference")
    if fr is not None:
        to = fr.find("TableOccurrenceReference")
        attrs = {}
        if to is not None and to.get("name"):
            attrs["table"] = to.get("name")
        attrs["id"] = fr.get("id") or ""
        attrs["name"] = fr.get("name") or ""
        ET.SubElement(s, "Field", attrs)
    else:
        ET.SubElement(s, "Text")
        ET.SubElement(s, "Field").text = param.find("Variable").get("value")


def _emit_datafile_path_target(step):          # 188 Get File Exists, 189 Get File Size, 191 Open Data File
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    loc = step.find(".//Parameter[@type='UniversalPathList']//Location")
    if loc is not None:
        ET.SubElement(s, "UniversalPathList").text = loc.text or ""
    t = step.find(".//Parameter[@type='Target']")
    if t is not None:
        _emit_datafile_target(s, t)
    return s


def _emit_create_data_file(step):              # 190 — CreateDirectories bool, DisableStepCollapsed, path
    s = _new_step(step)
    ET.SubElement(s, "CreateDirectories", {"state": _bool_state(step, "Create folders")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    loc = step.find(".//Parameter[@type='UniversalPathList']//Location")
    if loc is not None:
        ET.SubElement(s, "UniversalPathList").text = loc.text or ""
    return s


def _emit_write_data_file(step):               # 192 — AppendLineFeed, DataSourceType(=Encoding@type), id, target
    s = _new_step(step)
    ET.SubElement(s, "AppendLineFeed", {"state": _bool_state(step, "Append line feed")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "DataSourceType", {"value": step.find("ParameterValues/Encoding").get("type")})
    idp = step.find(".//Parameter[@type='id']")
    if idp is not None:
        ET.SubElement(s, "Calculation").text = _inner_text(idp)
    t = step.find(".//Parameter[@type='Target']")
    if t is not None:
        _emit_datafile_target(s, t)
    return s


def _emit_read_data_file(step):                # 193 — DataSourceType(=Encoding@type), id, target (size DROPPED)
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "DataSourceType", {"value": step.find("ParameterValues/Encoding").get("type")})
    idp = step.find(".//Parameter[@type='id']")
    if idp is not None:
        ET.SubElement(s, "Calculation").text = _inner_text(idp)
    t = step.find(".//Parameter[@type='Target']")
    if t is not None:
        _emit_datafile_target(s, t)
    return s


def _emit_datafile_id_target(step):            # 194 Get Data File Position — id, target
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    idp = step.find(".//Parameter[@type='id']")
    if idp is not None:
        ET.SubElement(s, "Calculation").text = _inner_text(idp)
    t = step.find(".//Parameter[@type='Target']")
    if t is not None:
        _emit_datafile_target(s, t)
    return s


def _emit_datafile_id_only(step):              # 195 Set Data File Position (position DROPPED), 196 Close Data File
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    idp = step.find(".//Parameter[@type='id']")
    if idp is not None:
        ET.SubElement(s, "Calculation").text = _inner_text(idp)
    return s


def _emit_send_dde_execute(step):              # 64 — constant ContentType File (no DDR param)
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "ContentType", {"value": "File"})
    return s


def _emit_truncate_table(step):                # 182 — NoInteract + bare + BaseTable (current table)
    b = step.find(".//Parameter[@type='Boolean']/Boolean[@type='With dialog']")
    lst = step.find(".//Parameter[@type='List']/List")
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if (b is not None and b.get("value") == "False") else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "BaseTable", {"id": "-1", "name": lst.get("name")})   # -1 = <Current Table>
    return s


# ── packet 1053 tranche 4 — base-shape multi-flag steps ──

def _emit_paste(step):                         # 48 — NoStyle / SelectAll / LinkAvail(const) / bare
    s = _new_step(step)
    ET.SubElement(s, "NoStyle", {"state": _bool_state(step, "No style")})
    ET.SubElement(s, "SelectAll", {"state": _bool_state(step, "Select")})
    ET.SubElement(s, "LinkAvail", {"state": "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    return s


def _emit_set_zoom(step):                       # 97 — Lock / bare / Zoom (list name, % stripped)
    s = _new_step(step)
    ET.SubElement(s, "Lock", {"state": _bool_state(step, "Lock")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Zoom", {"value": step.find(".//Parameter[@type='List']/List").get("name").rstrip("%")})
    return s


def _emit_import_records(step):                 # 35 — base shape (no saved import order): Restore off
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Restore", {"state": "False"})
    ET.SubElement(s, "VerifySSLCertificates", {"state": _bool_state(step, "Verify SSL Certificates")})
    return s


def _emit_perform_script(step):                # 1 — from-list / by-name mode + optional parameter calc
    lst = step.find(".//Parameter[@type='List']/List")
    param = step.find(".//Parameter[@type='Parameter']/Parameter")
    param_calc = _inner_text(param) if param is not None else ""
    s = ET.Element("Step", {"enable": step.get("enable", "True"),
                            "id": step.get("id"), "name": step.get("name")})
    if lst.get("name") == "By name":           # script specified by a name calculation
        ET.SubElement(ET.SubElement(s, "Calculated"), "Calculation").text = _inner_text(lst)
        ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
        ET.SubElement(s, "CurrentScript", {"value": "Pause"})
        return s
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})   # From list
    ET.SubElement(s, "CurrentScript", {"value": "Pause"})
    if param_calc:
        ET.SubElement(s, "Calculation").text = param_calc
    ref = lst.find("ScriptReference")
    if ref is not None:
        ET.SubElement(s, "Script", {"id": ref.get("id") or "", "name": ref.get("name") or ""})
    return s


def _emit_speak(step):                         # 66 — SpeechOptions (WaitForCompletion + VoiceId)
    voice = step.find(".//Parameter[@type='Voice']/Voice")
    wait = step.find(".//Parameter[@type='Wait']/Boolean")
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "SpeechOptions",
                  {"WaitForCompletion": (wait.get("value") if wait is not None else "False"),
                   "VoiceId": (voice.get("value") if voice is not None else "0")})
    return s                                    # a spoken-text calc would add a Calculation → new sig → fenced


# ── packet 1068 — configured AI-config family (scriptstepsamples configured subset pair) ──

def _emit_configure_coreml(step):              # 202 Configure Machine Learning Model
    op = step.find(".//Parameter[@type='operation']/List")
    name = step.find(".//Parameter[@type='name']")
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    cc = ET.SubElement(s, "ConfigureCoreML")
    ET.SubElement(cc, "Operation").text = (op.get("name") or "").capitalize()
    ET.SubElement(ET.SubElement(cc, "Name"), "Calculation").text = _inner_text(name)
    return s


# packet 1078 — DDR provider List name → clip LLMType. OpenAI and Custom are REMAPPED; Anthropic/Cohere/Google
# are EXPLICIT identity entries (packet 1114 — the five committed provider pairs; no `.get(name, name)` fallback
# is permission, `_cap_configure_ai_account` refuses a provider absent from this map before the emitter reads it).
# DDR List values: OpenAI=0, Custom=20 (the only shape carrying <Endpoint>); an unsampled value (e.g. 3) refuses.
_LLM_PROVIDER = {"OpenAI": "ChatGPT", "Anthropic": "Anthropic", "Cohere": "Cohere",
                 "Google": "Google", "Custom": "Other"}
_LLM_ENDPOINT_PROVIDERS = frozenset({"Custom"})   # packet 1114 — the only provider branch carrying <LLMEndpoint>
#   (→ clip <Endpoint>). Endpoint is REQUIRED for Custom and FORBIDDEN for every standard provider (no matched
#   pair proves otherwise); the coupling is enforced structurally, independent of the fence.


def _emit_configure_ai_account(step):          # 212 Configure AI Account
    # `Verify SSL Certificates` is emitted ONLY when True — the clip omits the element for the default
    # False. The captured evidence confounds "emit iff True" with "emit iff provider is Other" (all four
    # standard providers were captured False + element-absent; only Custom was True + element-present).
    # The DDR breaks the tie: its <Options> bitmask carries the flag as an independent bit whose mask IS
    # the Boolean's own id (0x10000000) — Custom's 0x10004002 is the others' 0x4002 plus that bit, and the
    # provider is not in <Options> at all. So the flag is orthogonal to provider, not coupled to it.
    ssl = step.find(".//Parameter[@type='Boolean']/Boolean[@type='Verify SSL Certificates']")
    prov = step.find(".//Parameter[@type='List']/List")
    apikey = step.find(".//Parameter[@type='LLMAPIKey']")
    endpoint = step.find(".//Parameter[@type='LLMEndpoint']")
    acct = step.find(".//Parameter[@type='LLMAccountName']")
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    if ssl is not None and ssl.get("value") == "True":
        ET.SubElement(s, "VerifySSLCertificates", {"state": "True"})
    ET.SubElement(s, "LLMType", {"value": _LLM_PROVIDER.get(prov.get("name"), prov.get("name") or "")})
    set_acct = ET.SubElement(s, "SetLLMAccount")
    ET.SubElement(ET.SubElement(set_acct, "AccountName"), "Calculation").text = _inner_text(acct)
    if endpoint is not None:                   # Custom only — between AccountName and AccessAPIKey,
        ET.SubElement(ET.SubElement(set_acct, "Endpoint"), "Calculation").text = _inner_text(endpoint)
    ET.SubElement(ET.SubElement(set_acct, "AccessAPIKey"), "Calculation").text = _inner_text(apikey)
    return s


def _emit_configure_rag_account(step):         # 227 Configure RAG Account
    ssl = step.find(".//Parameter[@type='Boolean']/Boolean[@type='Verify SSL Certificates']")
    apikey = step.find(".//Parameter[@type='RAGAPIKey']")
    acct = step.find(".//Parameter[@type='RAGAccountName']")
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "VerifySSLCertificates", {"state": ssl.get("value") if ssl is not None else "False"})
    cfg = ET.SubElement(s, "ConfigureRAGAccount")
    ET.SubElement(ET.SubElement(cfg, "RAGAccountName"), "Calculation").text = _inner_text(acct)
    ET.SubElement(ET.SubElement(cfg, "AccessAPIKey"), "Calculation").text = _inner_text(apikey)
    return s


# ── packet 1068 — Send Mail (63): the first SUBTREE-FENCED emitter ──────────────
# All Send Mail configs share the top-level sig ('Email',) — the send mode + crypto enums live in the
# nested subtree. _email_fingerprint fences exactly what the emitter CANNOT reproduce generically (the
# send-mode structure + the encryption/auth/provider enum LOOKUPS); recipients/subject/body/attachment
# are copied straight from the DDR, so their variation never needs a new fixture.
_SMTP_ENCRYPTION = {"TLS": "SMTPEncryptionTLS"}                 # + absent → SMTPEncryptionNone
_SMTP_AUTH = {"Plain Password": "SMTPAuthenticationPlain"}      # + absent → SMTPAuthenticationNone
_OAUTH_PROVIDER = {"Google": "OAuthProviderGoogle"}            # + absent → OAuthProviderGoogle (default)


def _email_enum(email, block_tag, child_tag):
    b = email.find(block_tag)
    c = b.find(child_tag) if b is not None else None
    return c.get("name") if c is not None else None


def _email_fingerprint(p) -> str:
    """Structural fingerprint of a Send Mail Email param: send mode (has-SMTP / has-OAuth) + the three
    crypto enums the emitter maps by lookup. An unseen enum (e.g. an SSL encryption) or an unseen mode
    → a new fingerprint → REFUSED, never a lookup miss silently emitted."""
    smtp = p.find("SMTP")
    oauth = p.find("OAuthAuthentication")
    enc = _email_enum(p, "SMTP", "Encryption") or "none"
    auth = _email_enum(p, "SMTP", "Authentication") or "none"
    prov = _email_enum(p, "OAuthAuthentication", "OAuthProvider") or "none"
    return f"smtp{1 if smtp is not None else 0}:{enc}/{auth};oauth{1 if oauth is not None else 0}:{prov}"


def _email_calc(parent, node, clip_tag, attrs=None):
    """Emit <clip_tag [attrs]><Calculation>…</Calculation> when `node` carries a calc; else nothing."""
    if node is None or node.find(".//Calculation") is None:
        return
    el = ET.SubElement(parent, clip_tag, attrs or {})
    ET.SubElement(el, "Calculation").text = _inner_text(node)


def _emit_send_mail(step):                     # 63 — plain / SMTP / OAuth (subtree-fenced)
    email = step.find(".//Parameter[@type='Email']")
    send = email.find("Send")
    dlg = email.find("Boolean")
    smtp = email.find("SMTP")
    oauth = email.find("OAuthAuthentication")
    upl = email.find("UniversalPathList")
    s = ET.Element("Step", {"enable": step.get("enable", "True"),
                            "id": step.get("id"), "name": step.get("name")})
    no_dialog = dlg is not None and (
        (dlg.get("type") == "With dialog" and dlg.get("value") == "False") or
        (dlg.get("type") == "No dialog" and dlg.get("value") == "True"))
    ET.SubElement(s, "NoInteract", {"state": "True" if no_dialog else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    if upl is not None and upl.find(".//Location") is not None:
        att = ET.SubElement(s, "Attachment")
        ET.SubElement(att, "UniversalPathList").text = upl.find(".//Location").text
    for ddr_tag, clip_tag in (("To", "To"), ("CC", "Cc"), ("BCC", "Bcc")):
        node = send.find(ddr_tag)
        ca = node.find("CollectAddresses") if node is not None else None
        _email_calc(s, node, clip_tag, {"UseFoundSet": ca.get("value") if ca is not None else "False"})
    for tag in ("Subject", "Message"):
        _email_calc(s, send.find(tag), tag)
    if smtp is not None:
        for ddr_tag, clip_tag in (("Name", "SMTPNameDescription"), ("Email", "SMTPEmailAddress"),
                                  ("ReplyTo", "SMTPReplyAddress"), ("Server", "SMTPServer"),
                                  ("Port", "SMTPPort"), ("UserName", "SMTPUserName"),
                                  ("Password", "SMTPPassword")):
            _email_calc(s, smtp.find(ddr_tag), clip_tag)
    mult = send.find("Multiple")
    ET.SubElement(s, "MultipleEmails", {"state": mult.get("value") if mult is not None else "False"})
    ET.SubElement(s, "SendViaSMTP", {"state": send.get("SMTP") or "False"})
    ET.SubElement(s, "SendViaOAuthAuthentication", {"state": send.get("OAuthAuthentication") or "False"})
    ET.SubElement(s, "SMTPEncryptionType",
                  {"type": _SMTP_ENCRYPTION.get(_email_enum(email, "SMTP", "Encryption"), "SMTPEncryptionNone")})
    ET.SubElement(s, "SMTPAuthenticationType",
                  {"type": _SMTP_AUTH.get(_email_enum(email, "SMTP", "Authentication"), "SMTPAuthenticationNone")})
    ET.SubElement(s, "OAuthProvider",
                  {"type": _OAUTH_PROVIDER.get(_email_enum(email, "OAuthAuthentication", "OAuthProvider"),
                                               "OAuthProviderGoogle")})
    return s


# ── packet 1068 — PDF file ops (Open / Append / Close), File mode ──────────────
# Target mode carries a UniversalPathList path the DDR doesn't hold (irrelevant when writing to a field,
# but FileMaker still serialises a default) → not reproducible → fenced out (File-mode sigs only).

def _emit_open_append_pdf(step, wrapper):      # 246 Open PDF / 244 Append PDF (File mode)
    loc = step.find(".//Parameter[@type='UniversalPathList']//Location")
    frm = step.find(".//Parameter[@type='From']/List")
    pw = step.find(".//Parameter[@type='PDFPassword']")
    s = _new_step(step)
    ET.SubElement(s, "Option", {"state": "True"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "UniversalPathList").text = loc.text
    w = ET.SubElement(s, wrapper)
    ET.SubElement(w, "PDFSaveType").text = frm.get("name")     # File (Target fenced out)
    if pw is not None:
        ET.SubElement(ET.SubElement(w, "OpenPassword"), "Calculation").text = _inner_text(pw)
    return s


# ── packet 1082 — the top of the real-corpus queue: 91 · 130 · 61 ──────────────────────────────
# Ranked by occurrences in the REAL corpus (customer/dev files, authored sample files excluded), which
# is the honest priority signal: 91 ×36 · 131 ×24 · 130 ×23 · 61 ×5 carry 77% of all non-emitting usage;
# the whole AI family (213–222/226/240/241) is ×1 each and appears ONLY in the authored sample file.
# All three below are packet 1069 fence-holes — the token fix above is the load-bearing part.

def _emit_field_ref(parent, ref, tag="Field"):
    """<Field table=… id=… name=…> from a DDR FieldReference (+ its TableOccurrenceReference)."""
    if ref is None:
        return
    to = ref.find("TableOccurrenceReference")
    ET.SubElement(parent, tag, {"table": to.get("name") if to is not None else "",
                                "id": ref.get("id"), "name": ref.get("name")})


_REPLACE_WITH = {"0": "None", "1": "CurrentContents", "2": "SerialNumbers", "3": "Calculation"}


def _emit_replace_field_contents(step):        # 91 Replace Field Contents
    # The `replace` List's VALUE is the mode, and its @name lies: 'Current contents' is BOTH the unset
    # base (value 0 → <With value="None"/>) and the configured replace (value 1 → CurrentContents). The
    # three configured modes emit different clips, which is why the collapsed token was a fence-hole.
    # <SerialNumbers> is always present, even in modes that have nothing to do with serial numbers.
    #
    # packet 1120 — calculation mode (value 3) never reaches this emitter: its clip <SerialNumbers> reflects
    # the TARGET FIELD's serial state/defaults (not the step DDR), so `_cap_replace_field_contents` refuses it
    # before emission (replace_calculation_serial_state_source_incomplete). The serial mode's block, by
    # contrast, is fully step-derived and is projected value-by-value below.
    lst = step.find(".//Parameter[@type='replace']/List")
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ref = step.find(".//Parameter[@type='FieldReference']/FieldReference")
    ET.SubElement(s, "Restore", {"state": "True" if ref is not None else "False"})
    ET.SubElement(s, "With", {"value": _REPLACE_WITH[lst.get("value")]})
    if ref is None:                            # mode 0 (unset base): the empty serial block, unchanged
        ET.SubElement(s, "SerialNumbers", {"PerformAutoEnter": "False", "UpdateEntryOptions": "False",
                                           "increment": "0", "InitialValue": "",
                                           "UseEntryOptions": "False"})
        return s
    # modes 1/2 — value-driven <SerialNumbers> projected from the replace List (FileMaker attr order:
    # PerformAutoEnter, UpdateEntryOptions, [increment, InitialValue], UseEntryOptions).
    skip = lst.find("Boolean[@type='Skip auto-enter options']")
    upd = lst.find("Boolean[@type='Update Entry Options']")
    eov = lst.find("List[@name='Entry option values']")
    attrs = {"PerformAutoEnter": "False" if (skip is not None and skip.get("value") == "True") else "True",
             "UpdateEntryOptions": upd.get("value") if upd is not None else "False"}
    if eov is not None and eov.get("value") == "False":   # explicit serial: Initial/increment are step-held
        inc = eov.find("increment")
        init = eov.find("Initial")
        attrs["increment"] = inc.get("value") if inc is not None else ""
        attrs["InitialValue"] = init.get("value") if init is not None else ""
        attrs["UseEntryOptions"] = "False"
    else:                                      # current-contents, or serial deferring to the field's entry options
        attrs["UseEntryOptions"] = "True"
    ET.SubElement(s, "SerialNumbers", attrs)
    _emit_field_ref(s, ref)
    return s


def _emit_set_selection(step):                 # 130 Set Selection
    # Empty <Start/><End/> → the clip carries NO bounds at all; filled ones → <StartPosition>/
    # <EndPosition>. Packet 1069 named this one: the collapsed ('Select',) token would have let a
    # bounds-carrying step emit the base form and lose its selection.
    sel = step.find(".//Parameter[@type='Select']")
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    for ddr_tag, clip_tag in (("Start", "StartPosition"), ("End", "EndPosition")):
        node = sel.find(ddr_tag) if sel is not None else None
        if node is not None and node.find("Calculation") is not None:
            ET.SubElement(ET.SubElement(s, clip_tag), "Calculation").text = _inner_text(node)
    _emit_field_ref(s, step.find(".//Parameter[@type='FieldReference']/FieldReference"))
    return s


_INSERT_FILE_STORAGE = {"0": "UserChoice"}     # DDR Storage/Compress value → clip @type; 0 = "Let user
_INSERT_FILE_COMPRESS = {"0": "UserChoice"}    # choose". Other modes unsampled → fenced, never guessed.


def _emit_insert_file(step):                   # 131 Insert File
    # ⚠ Here the CLIP is the LOSSIER projection — the reverse of the usual direction. The DDR holds a
    # dialog Title calc, a <Filters> list and a Display option; the clip carries NONE of them (its
    # <FilterList/> comes out empty even when the DDR names a filter). That is FileMaker's own
    # projection loss, and reproducing it is correct — the fence proves we match FM's clip, not that we
    # preserve everything the DDR knows.
    #
    # `asFile="True"` is an observed CONSTANT across both committed shapes (the base DDR has no
    # parameters at all, mask 0, and still emits it), so it is reproduced rather than derived.
    # `enable` is CONFOUNDED across those two shapes — it tracks both "an Options param exists" and bit
    # 1 of the step's <Options> bitmask, and we cannot separate them from two samples. It does not
    # matter: the two shapes have distinct signatures, so each carries its own observed value and
    # anything else refuses. Reading the DDR is preferred to reading the bitmask because it is the
    # semantically obvious source, not because the evidence settles it.
    opts = step.findall(".//Parameter[@type='Options']/Options")
    loc = step.find(".//Parameter[@type='UniversalPathList']//Location")
    tgt = step.find(".//Parameter[@type='Target']/FieldReference")
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    upl = ET.SubElement(s, "UniversalPathList", {"type": "Embedded"})
    if loc is not None:
        upl.text = loc.text
    _emit_field_ref(s, tgt)
    do = ET.SubElement(s, "DialogOptions", {"asFile": "True", "enable": "True" if opts else "False"})
    by_type = {o.get("type"): o for o in opts}

    def _sel(kind, table, default="UserChoice"):
        o = by_type.get(kind)
        node = o.find(kind) if o is not None else None
        return table[node.get("value")] if node is not None else default

    ET.SubElement(do, "Storage", {"type": _sel("Storage", _INSERT_FILE_STORAGE)})
    ET.SubElement(do, "Compress", {"type": _sel("Compress", _INSERT_FILE_COMPRESS)})
    ET.SubElement(do, "FilterList")            # always empty — see the projection-loss note above
    return s


def _emit_insert_text(step):                   # 61 Insert Text
    # The text lives in an ATTRIBUTE (<Text value="…"/>), not element content. An empty <Text/> yields a
    # clip with no <Text> element at all — the fence-hole packet 1069 named.
    s = _new_step(step)
    ET.SubElement(s, "SelectAll", {"state": _bool_state(step, "Select")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    txt = step.find(".//Parameter[@type='Text']/Text")
    if txt is not None and txt.get("value"):
        ET.SubElement(s, "Text").text = txt.get("value")
    tgt = step.find(".//Parameter[@type='Target']")
    if tgt is not None:                        # packet 1129 — variable target → <Field>$var</Field>
        var = tgt.find("Variable")
        if var is not None:
            ET.SubElement(s, "Field").text = var.get("value")
        else:
            _emit_field_ref(s, tgt.find("FieldReference"))
    return s


# ── packet 1081 — the PDF-options family: 243 Create PDF + 144 Save Records as PDF ─────────────
#
# One subtree, two steps. 243 wraps it in <CreatePDFFile>, 144 in <PDFOptions> (whose FM2026 first child
# is <PDFSaveType>), but Document/Security/View underneath are the same shape — so the subtree emitters
# below are written ONCE and used twice. Ground truth: the 9 Create PDF + 8 Save-as-PDF configured pairs
# in scriptstepsamples_configured_fm2026_xmss.xml.
#
# Every map here was DERIVED from those pairs, not from the andykear spec: the clip value is NOT a
# mechanical de-spacing of the DDR name (`Filling in form fields and signing` → `FillingInForms`, and
# `Commenting, filling in form fields and signing` → `Commenting`), so guessing would have been wrong
# twice. Unsampled DDR values are ABSENT on purpose and refuse via the shape fence — notably
# Magnification values 3–6, which we have never seen.
_PDF_CONTROL_EDITING = {                       # DDR Security/Edit @name → clip @controlEditing
    "Not Permitted": "NotPermitted",
    "Inserting, deleting and rotating pages": "InsertingDeletingRotatingPages",
    "Filling in form fields and signing": "FillingInForms",
    "Commenting, filling in form fields and signing": "Commenting",
    "Any except extracting pages": "AnyExceptExtractingPages",
}
_PDF_CONTROL_PRINTING = {                      # DDR Security/Print @name → clip @controlPrinting
    "Not Permitted": "NotPermitted", "Low Resolution": "LowResolution",
    "High Resolution": "HighResolution",
}
_PDF_VIEW_SHOW = {"Page Only": "PageOnly", "Bookmarks Panel and Page": "BookmarksPanelAndPage",
                  "Pages Panel and Page": "PagesPanelAndPage"}
_PDF_VIEW_LAYOUT = {"Default": "Default", "Single Page": "SinglePage", "Continuous": "Continuous"}
_PDF_VIEW_MAGNIFICATION = {"Default": "Default", "Fit Page": "FitPage", "Fit Width": "FitWidth",
                           "100%": "100"}     # DDR values 3-6 unsampled → absent → fenced
# 144's record source → (@source, @appearance). The four blank-record variants share ONE @source and are
# told apart by a SECOND attribute, @appearance, which is omitted entirely for the non-blank sources.
# Worth remembering how this was found: reading @source alone made the clip look LOSSY (4 DDR values → 1
# clip value) and that reading was written down as fact. The byte-exact check against the committed pairs
# refuted it immediately — @appearance was right there. Reasoning about a projection lost to comparing it.
_PDF_SOURCE = {"Records being browsed": ("RecordsBeingBrowsed", None),
               "Current record": ("CurrentRecord", None),
               "Blank record, as formatted": ("BlankRecord", "AsFormatted"),
               "Blank record, with boxes": ("BlankRecord", "WithBoxes"),
               "Blank record, with underlines": ("BlankRecord", "WithUnderlines"),
               "Blank record, with placeholder text": ("BlankRecord", "WithPlaceholderText")}
_PDF_SAVE_TYPE = {"File": "File", "Target": "Target", "Currently open PDF": "Append"}


def _pdf_options_fingerprint(o) -> str:
    """Structural fingerprint of a PDF-family <Options> subtree — the fence key for 144/243.

    Without this the whole subtree collapsed to one token (`Options:{@type}`), so the BASE shape (an
    empty `<Options/>`) and every configured shape shared ONE signature: verifying a configured pair
    would have licensed the emitter to fire on the base shape and invent a Document/Security/View out of
    nothing. That is exactly the collision packet 1076 found in Print Setup, where the same collapse let
    a verified shape silently admit one whose clip it could not reproduce.

    It fingerprints (a) which sub-blocks are present, (b) which Document parameters are set, (c) the
    Pages shape, and (d) the enum values the emitter maps by LOOKUP — so an unseen enum (a new FM
    Magnification, say) becomes a new fingerprint and is REFUSED, never a lookup miss silently emitted.
    Same contract as _email_fingerprint. Calc TEXT is deliberately not fingerprinted: values are copied
    through generically, as everywhere else."""
    def enum(parent, tag):
        e = o.find(f"{parent}/{tag}") if parent else o.find(tag)
        return f"{tag}={e.get('value')}" if e is not None else f"{tag}=_"
    parts = []
    doc = o.find("Document")
    if doc is not None:
        parts.append("Doc[" + ",".join(p.get("type") or "?" for p in doc.findall("Parameter")) + "]")
    pages = o.find("Pages") if o.find("Pages") is not None else (doc.find("Pages") if doc is not None else None)
    if pages is not None:
        inc = pages.find("Include")
        parts.append("Pages[" + ",".join(p.get("type") or "?" for p in pages.findall("Parameter"))
                     + (f";All={inc.get('All')}" if inc is not None else "") + "]")
    sec = o.find("Security")
    if sec is not None:
        op, ctl = sec.find("Open"), sec.find("Control")
        parts.append("Sec[" + ",".join([
            f"Open={op.get('value') if op is not None else '_'}"
            + (":pw" if op is not None and op.find(".//Calculation") is not None else ""),
            f"Control={ctl.get('value') if ctl is not None else '_'}"
            + (":pw" if ctl is not None and ctl.find(".//Calculation") is not None else ""),
            enum("Security", "Print"), enum("Security", "Edit"),
            enum("Security", "EnableCopying"), enum("Security", "AllowScreenReader")]) + "]")
    view = o.find("View")
    if view is not None:
        parts.append("View[" + ",".join([enum("View", "show"), enum("View", "Layout"),
                                         enum("View", "Magnification")]) + "]")
    return "+".join(parts)


def _pdf_calc_param(parent, node, clip_tag):
    """<clip_tag><Calculation>…</Calculation></clip_tag> when the DDR node carries a calc, else nothing."""
    if node is None:
        return
    el = ET.SubElement(parent, clip_tag)
    ET.SubElement(el, "Calculation").text = _inner_text(node)


def _emit_pdf_document(wrapper, o):
    """<Document> — Title/Subject/Author/Keywords + the Pages block, shared by 144 and 243.

    Pages is the subtle one. 243's DDR has no Pages at all and its clip still carries
    `<Pages AllPages="True"><NumberFrom>1</NumberFrom></Pages>` — an inert FileMaker default, verified
    across all 9 pairs. 144's DDR DOES carry Pages (as a SIBLING of Document, not a child — the clip
    nests it under Document), and its clip adds an inert `<PageRange>1..1</PageRange>`. Both defaults are
    observed constants for the Include-All shape the fence verifies; an `Include All="False"` DDR is a
    different fingerprint and refuses, because we have never captured one."""
    doc_ddr = o.find("Document")
    d = ET.SubElement(wrapper, "Document")
    if doc_ddr is not None:
        for tag in ("Title", "Subject", "Author", "Keywords"):
            _pdf_calc_param(d, doc_ddr.find(f"Parameter[@type='{tag}']"), tag)
    pages_ddr = o.find("Pages")
    pages = ET.SubElement(d, "Pages", {"AllPages": "True"})
    nf = ET.SubElement(pages, "NumberFrom")
    frm = pages_ddr.find("Parameter[@type='from']") if pages_ddr is not None else None
    ET.SubElement(nf, "Calculation").text = _inner_text(frm) if frm is not None else "1"
    if pages_ddr is not None:                  # 144 only: the inert range FileMaker writes anyway
        pr = ET.SubElement(pages, "PageRange")
        for tag in ("From", "To"):
            ET.SubElement(ET.SubElement(pr, tag), "Calculation").text = "1"


def _emit_pdf_security(wrapper, o):
    """<Security> — the permission attributes + the two optional passwords."""
    sec = o.find("Security")
    if sec is None:
        return
    op, ctl = sec.find("Open"), sec.find("Control")
    ET.SubElement(wrapper, "Security", {
        "allowScreenReader": sec.find("AllowScreenReader").get("value"),
        "enableCopying": sec.find("EnableCopying").get("value"),
        "controlEditing": _PDF_CONTROL_EDITING[sec.find("Edit").get("name")],
        "controlPrinting": _PDF_CONTROL_PRINTING[sec.find("Print").get("name")],
        "requireControlEditPassword": ctl.get("value") if ctl is not None else "False",
        "requireOpenPassword": op.get("value") if op is not None else "False"})
    s = wrapper.find("Security")
    for node, tag in ((op, "OpenPassword"), (ctl, "ControlPassword")):
        if node is not None and node.find(".//Calculation") is not None:
            _pdf_calc_param(s, node.find("Parameter[@type='Password']"), tag)


def _emit_pdf_view(wrapper, o):
    """<View> — the three display enums."""
    view = o.find("View")
    if view is None:
        return
    ET.SubElement(wrapper, "View", {
        "magnification": _PDF_VIEW_MAGNIFICATION[view.find("Magnification").get("name")],
        "pageLayout": _PDF_VIEW_LAYOUT[view.find("Layout").get("name")],
        "show": _PDF_VIEW_SHOW[view.find("show").get("name")]})


def _emit_create_pdf(step):                    # 243 Create PDF
    # The bare <Calculation> between <Restore> and <CreatePDFFile> is the TITLE, MIRRORED — not an
    # output path. It was filed as a class-2 gap ("the clip carries a destination the DDR lacks") and
    # that was WRONG (reclassified 2026-07-15): Create PDF creates in MEMORY (Append/Close PDF do the
    # file work) so there is no destination to encode, and the PDF family encodes paths as
    # <UniversalPathList> (244/245/246) — never as a bare calc. All 9 committed pairs have
    # bare == Document/Title. Residual: every sample shares one title, so we have never OBSERVED
    # bare != Title; per the andykear spec FileMaker normalises them on round trip, so on that reading
    # no such case exists. If one ever appears it is an unseen shape and the fence refuses it.
    o = step.find(".//Parameter[@type='Options']/Options")
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Restore", {"state": step.find(".//Parameter[@type='Restore']/Restore").get("value")})
    title = o.find("Document/Parameter[@type='Title']")
    ET.SubElement(s, "Calculation").text = _inner_text(title) if title is not None else ""
    w = ET.SubElement(s, "CreatePDFFile")
    _emit_pdf_document(w, o)
    _emit_pdf_security(w, o)
    _emit_pdf_view(w, o)
    return s


def _emit_save_records_as_pdf(step):           # 144 Save Records as PDF
    # Child ORDER is FileMaker's, not ours: NoInteract · Option · CreateDirectories ·
    # DisableStepCollapsed · Restore · AutoOpen · CreateEmail · (path) · PDFOptions. The path element is
    # <UniversalPathList> in File mode and <Field> in Target mode — only the File shape is verified here;
    # Target/Append carry no DDR path and are fenced by their own signatures.
    o = step.find(".//Parameter[@type='Options']/Options")
    upl = step.find(".//Parameter[@type='UniversalPathList']/UniversalPathList")
    loc = upl.find(".//Location") if upl is not None else None
    tgt = step.find(".//Parameter[@type='Target']/FieldReference")
    s = _new_step(step)
    # NoInteract is the INVERSE of the DDR's "With dialog" (same as 9/10/26/75).
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "Option", {"state": _bool_state(step, "Append to existing PDF")})
    # In Target/Append mode the DDR carries NO option Booleans at all, yet the clip still writes
    # CreateDirectories="True" — so absent means True here, not False (_bool_state's default). Observed
    # in both committed pairs; the shape fence pins which sigs may take this branch. It is CONFOUNDED —
    # every sample we hold has Create-folders True — so this reads the DDR where it can and falls back
    # to the observed constant where the DDR is silent, rather than inventing a rule.
    cf = step.find(".//Parameter[@type='Boolean']/Boolean[@type='Create folders']")
    ET.SubElement(s, "CreateDirectories", {"state": cf.get("value") if cf is not None else "True"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "Restore", {"state": step.find(".//Parameter[@type='Restore']/Restore").get("value")})
    # AutoOpen/CreateEmail live on the UniversalPathList; with no path (Target/Append) both are False.
    ET.SubElement(s, "AutoOpen", {"state": upl.get("AutoOpen") if upl is not None else "False"})
    ET.SubElement(s, "CreateEmail", {"state": upl.get("CreateMail") if upl is not None else "False"})
    if loc is not None:
        ET.SubElement(s, "UniversalPathList").text = loc.text
    elif tgt is not None:                          # Target mode writes into a field, not a path
        to = tgt.find("TableOccurrenceReference")
        ET.SubElement(s, "Field", {"table": to.get("name") if to is not None else "",
                                   "id": tgt.get("id"), "name": tgt.get("name")})
    src, appearance = _PDF_SOURCE[o.get("type")]
    attrs = {"source": src}
    if appearance is not None:                     # blank-record variants only; FM omits it otherwise
        attrs["appearance"] = appearance
    w = ET.SubElement(s, "PDFOptions", attrs)
    # FM2026 puts <PDFSaveType> FIRST inside <PDFOptions>; FM2025 has no such element at all. We emit
    # FM2026-form (CLIP_TARGET_VERSION) — see clip_catalog.yaml version_sensitivity: 144.
    sr = step.find(".//Parameter[@type='SaveResult']/List")
    ET.SubElement(w, "PDFSaveType").text = _PDF_SAVE_TYPE[sr.get("name")]
    _emit_pdf_document(w, o)
    _emit_pdf_security(w, o)
    _emit_pdf_view(w, o)
    return s


_SNAPSHOT_SAVETYPE = {"Records being browsed": "BrowsedRecords", "Current record": "CurrentRecord"}


def _emit_snapshot_link(step):                 # 152 Save Records as Snapshot Link
    loc = step.find(".//Parameter[@type='UniversalPathList']//Location")
    lst = step.find(".//Parameter[@type='List']/List")
    cf = step.find(".//Parameter[@type='Boolean']/Boolean[@type='Create folders']")
    s = _new_step(step)
    ET.SubElement(s, "CreateDirectories", {"state": cf.get("value") if cf is not None else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "CreateEmail", {"state": "False"})
    ET.SubElement(s, "SaveType", {"value": _SNAPSHOT_SAVETYPE.get(lst.get("name"), lst.get("name"))})
    ET.SubElement(s, "UniversalPathList").text = loc.text
    return s


def _emit_close_pdf(step):                     # 245 Close PDF (File mode)
    loc = step.find(".//Parameter[@type='UniversalPathList']//Location")
    saveto = step.find(".//Parameter[@type='SaveTo']/List")
    cf = step.find(".//Parameter[@type='Boolean']/Boolean[@type='Create folders']")
    s = _new_step(step)
    ET.SubElement(s, "CreateDirectories", {"state": cf.get("value") if cf is not None else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "AutoOpen", {"state": "False"})
    ET.SubElement(s, "CreateEmail", {"state": "False"})
    ET.SubElement(s, "UniversalPathList").text = loc.text
    ET.SubElement(ET.SubElement(s, "ClosePDFFile"), "PDFSaveType").text = saveto.get("name")
    return s


# ── packet 1069§② — Save-as-X family (base shapes; Save a Copy as also carries an output path) ──
# Byte-exact vs the scriptstepsamples base clip (index-aligned pair). The CONFIGURED variants — Export
# format + field list (36), Excel worksheet/metadata (143), JSONL data-complete field/table (225), the
# PDF Document/Pages/Security tree (144, still no emitter) — are a DIFFERENT DDR sig, so the per-shape
# fence refuses them; they remain future work (see docs/clip-emit-coverage.md).

_SAVE_AS_TYPE = {"copy of current file": "Copy"}   # + clone / compacted copy (unobserved → fenced)


def _emit_save_a_copy_as(step):                # 37 — Save a Copy as (Copy mode; optional output path)
    s = _new_step(step)
    ET.SubElement(s, "CreateDirectories", {"state": _bool_state(step, "Create folders")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    upl = step.find(".//Parameter[@type='UniversalPathList']/UniversalPathList")
    ET.SubElement(s, "AutoOpen", {"state": (upl.get("AutoOpen") if upl is not None else None) or "False"})
    ET.SubElement(s, "CreateEmail", {"state": (upl.get("CreateMail") if upl is not None else None) or "False"})
    ET.SubElement(s, "SaveAsType",
                  {"value": _SAVE_AS_TYPE[step.find(".//Parameter[@type='List']/List").get("name")]})
    if upl is not None:
        loc = upl.find(".//Location")
        ET.SubElement(s, "UniversalPathList").text = loc.text if loc is not None else ""
    return s


# packet 1117 — the configured Export/Excel/JSONL branches. Every value authority is an EXPLICIT map
# independent of the fence (an unmapped value refuses in the capability rule, never a lookup miss); the
# per-fileType Profile constants are one bounded branch (evidenced COMS/XLXE), never inferred from a
# file extension. Explicit identity entries are still mappings.
_EXPORT_CHARSET = {"Macintosh": "Macintosh", "Unicode (UTF-16)": "Unicode"}   # packet 1129 — Unicode
_EXPORT_PROFILE = {                                         # per-fileType export Profile (bounded)
    "COMS": {"FieldDelimiter": "\t", "IsPredefined": "-1", "FieldNameRow": "-1", "DataType": "COMS"},
    "TABS": {"FieldDelimiter": "\t", "IsPredefined": "-1", "FieldNameRow": "-1", "DataType": "TABS"},  # 1129
}
_EXCEL_PROFILE = {
    "XLXE": {"FieldDelimiter": "\t", "IsPredefined": "-1", "FieldNameRow": "-1", "DataType": "XLXE"},
}
_EXCEL_SAVE_MODE = {"Records being browsed": "BrowsedRecords", "Current record": "CurrentRecord"}
_EXCEL_METADATA_TAGS = {"Worksheet": "WorkSheet", "Title": "Title", "Subject": "Subject", "Author": "Author"}
# the OBSERVED source→target coupling: FileMaker projects source useFieldNames="True" to clip
# UseFieldNames state="False" (verified byte-exact, both configured pairs) — NOT a Boolean inversion, a
# single evidenced coupling; any other value refuses until another pair establishes more.
_EXCEL_USE_FIELD_NAMES = {"True": "False"}


def _emit_export_records(step):                # 36 — Export Records (base + configured format/order)
    export = step.find(".//Parameter[@type='Export']/Export")
    upl = step.find(".//Parameter[@type='UniversalPathList']/UniversalPathList")
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "CreateDirectories", {"state": _bool_state(step, "Create folders")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    if export is None:                         # base shape (no export format specified)
        ET.SubElement(s, "Restore", {"state": "False"})
        ET.SubElement(s, "AutoOpen", {"state": "False"})
        ET.SubElement(s, "CreateEmail", {"state": "False"})
        return s
    ET.SubElement(s, "Restore", {"state": "True"})           # configured export → Restore the export order
    ET.SubElement(s, "AutoOpen", {"state": upl.get("AutoOpen") or "False"})     # packet 1129 — absent → False
    ET.SubElement(s, "CreateEmail", {"state": upl.get("CreateMail") or "False"})
    ET.SubElement(s, "Profile", dict(_EXPORT_PROFILE[upl.get("fileType")]))
    loc = upl.find("ObjectList/Location")
    ET.SubElement(s, "UniversalPathList").text = loc.text if loc is not None else ""
    o = export.find("Options")
    ET.SubElement(s, "ExportOptions", {"FormatUsingCurrentLayout": o.get("Formatting"),
                                       "CharacterSet": _EXPORT_CHARSET[o.get("name")]})
    entries = ET.SubElement(s, "ExportEntries")
    for order in export.findall("Order"):
        if order.get("type") != "Field":       # the Group marker is target-absent (proven omitted)
            continue
        for f in order.findall("Field"):
            _emit_field_ref(ET.SubElement(entries, "ExportEntry"), f.find("FieldReference"))
    return s


def _emit_save_excel(step):                    # 143 — Save Records as Excel (base + configured metadata)
    upl = step.find(".//Parameter[@type='UniversalPathList']/UniversalPathList")
    excel = upl.find("Excel") if upl is not None else None
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "CreateDirectories", {"state": _bool_state(step, "Create folders")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    r = step.find(".//Parameter[@type='Restore']/Restore")
    ET.SubElement(s, "Restore", {"state": r.get("value") if r is not None else "False"})
    if excel is None:                          # base shape (empty <Options/>)
        ET.SubElement(s, "AutoOpen", {"state": "False"})
        ET.SubElement(s, "CreateEmail", {"state": "False"})
        ET.SubElement(s, "SaveType", {"value": "BrowsedRecords"})   # empty DDR <Options/> → FM's default
        ET.SubElement(s, "UseFieldNames", {"state": "False"})
        return s
    ET.SubElement(s, "AutoOpen", {"state": upl.get("AutoOpen")})
    ET.SubElement(s, "CreateEmail", {"state": upl.get("CreateMail")})
    ET.SubElement(s, "Profile", dict(_EXCEL_PROFILE[upl.get("fileType")]))
    loc = upl.find("ObjectList/Location")
    ET.SubElement(s, "UniversalPathList").text = loc.text if loc is not None else ""
    for meta in excel.findall("Parameter"):
        ET.SubElement(ET.SubElement(s, _EXCEL_METADATA_TAGS[meta.get("type")]),
                      "Calculation").text = _inner_text(meta)
    ufn = excel.find("Boolean[@type='Use field names as column names']")
    ET.SubElement(s, "SaveType", {"value": _EXCEL_SAVE_MODE[excel.get("name")]})
    ET.SubElement(s, "UseFieldNames", {"state": _EXCEL_USE_FIELD_NAMES[ufn.get("value")]})
    return s


def _emit_save_jsonl(step):                    # 225 — Save Records as JSONL (base + configured data-complete)
    upl = step.find(".//Parameter[@type='UniversalPathList']/UniversalPathList")
    dcf = step.find(".//Parameter[@type='SaveAsJSONLDataCompleteField']/FieldReference")
    tbl = step.find(".//Parameter[@type='SaveAsJSONLTable']/TableOccurrenceReference")
    s = _new_step(step)
    ET.SubElement(s, "Option", {"state": "True" if dcf is not None else "False"})
    ET.SubElement(s, "CreateDirectories", {"state": _bool_state(step, "Create folders")})
    ET.SubElement(s, "FineTuneFormat", {"state": _bool_state(step, "Format for fine-tuning")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    ET.SubElement(s, "AutoOpen", {"state": (upl.get("AutoOpen") if upl is not None else None) or "False"})
    ET.SubElement(s, "CreateEmail", {"state": (upl.get("CreateMail") if upl is not None else None) or "False"})
    if dcf is None:                            # base shape (no data-complete field)
        ET.SubElement(s, "SaveAsJSONL")
        return s
    loc = upl.find("ObjectList/Location") if upl is not None else None
    ET.SubElement(s, "UniversalPathList").text = loc.text if loc is not None else ""
    ET.SubElement(s, "Table", {"id": tbl.get("id"), "name": tbl.get("name")})
    _emit_field_ref(s, dcf)                    # top-level <Field table id name>
    _emit_field_ref(ET.SubElement(s, "SaveAsJSONL"), dcf)   # nested <Field> (same data-complete field)
    return s


# Per-step-type emitters. Membership in this map IS the fence: an id here is round-trip-verified
# against the SeedDB DDR↔clip pair (100% of its occurrences) AND carries the step's full semantics
# (a calc / name / text / resolved reference — never an option the clip silently drops).
_EMITTERS = {
    89:  _emit_comment,                        # # (comment)      — Text
    68:  lambda s: _emit_calc(s, restore=True),   # If            — condition calc
    125: lambda s: _emit_calc(s, restore=True),   # Else If       — condition calc
    69:  _emit_restore_only,                   # Else
    70:  _emit_bare,                           # End If
    72:  lambda s: _emit_calc(s, restore=False),  # Exit Loop If  — condition calc
    73:  _emit_bare,                           # End Loop
    103: lambda s: _emit_calc(s, restore=False),  # Exit Script   — optional result calc
    141: _emit_set_variable,                   # Set Variable     — value / repetition / name
    76:  _emit_set_field,                      # Set Field        — value calc / field / repetition
    7:   _emit_bare,                           # New Record/Request — option-free
    23:  _emit_bare,                           # Show All Records   — option-free
    # packet 1041 — the eight assembler step types
    1:   _emit_perform_script,                 # Perform Script    — from-list / by-name + parameter
    6:   _emit_goto_layout,                    # Go to Layout      — 4 destination modes
    16:  _emit_goto_record,                    # Go to Record/Request/Page — First/Next/ByCalculation
    22:  _emit_enter_find_mode,                # Enter Find Mode   — Pause + Restore
    28:  _emit_perform_find,                   # Perform Find      — Restore + stored requests
    39:  _emit_sort_records,                   # Sort Records      — restored sort specification
    71:  _emit_loop,                           # Loop              — flush variant
    86:  _emit_set_error_capture,              # Set Error Capture — bare clip (state not in clipboard)
    # packet 1044 — trivial shapes verified against the committed SeedDB pair
    24:  _emit_bare,                           # Modify Last Find      — bare
    25:  _emit_bare,                           # Omit Record           — bare
    27:  _emit_bare,                           # Show Omitted Only     — bare
    79:  _emit_bare,                           # Freeze Window         — bare
    90:  _emit_bare,                           # Halt Script           — bare
    169: _emit_bare,                           # Close Popover         — bare
    183: _emit_bare,                           # Open Favorites        — bare
    206: _emit_bare,                           # Commit Transaction    — bare
    85:  _emit_bare,                           # Allow User Abort      — on/off bool dropped in clip
    168: _emit_bare,                           # Set Layout Object Animation — on/off bool dropped
    9:   _emit_noninteract,                    # Delete Record/Request — NoInteract
    10:  _emit_noninteract,                    # Delete All Records    — NoInteract
    26:  _emit_noninteract,                    # Omit Multiple Records — NoInteract + count calc
    62:  _emit_pause_resume,                   # Pause/Resume Script   — duration mode + seconds calc
    # packet 1045 — bin ④ tranche 1 (selector / option-boolean)
    96:  _emit_save_addon,                     # Save a Copy as Add-on Package
    166: _emit_show_hide_menubar,              # Show/Hide Menubar
    29:  _emit_show_hide_toolbars,             # Show/Hide Toolbars
    142: _emit_install_menu_set,               # Install Menu Set
    31:  _emit_adjust_window,                  # Adjust Window (Maximize / Resize to Fit)
    126: _emit_constrain_found,                # Constrain Found Set
    55:  _emit_enter_browse,                   # Enter Browse Mode
    127: _emit_extend_found,                   # Extend Found Set
    # packet 1045 — bin ④ tranche 2 (object-name family + ESS/status)
    145: _emit_object_name,                    # Go to Object
    167: _emit_object_name,                    # Refresh Object
    180: _emit_object_name,                    # Refresh Portal
    175: _emit_perform_js,                     # Perform JavaScript in Web Viewer
    75:  _emit_commit_records,                 # Commit Records/Requests
    80:  _emit_refresh_window,                 # Refresh Window
    205: _emit_open_transaction,               # Open Transaction
    # packet 1045 — bin ④ tranche 3 (window / field / account / file)
    121: _emit_window_named,                   # Close Window
    123: _emit_window_named,                   # Select Window
    124: _emit_set_window_title,               # Set Window Title
    17:  _emit_goto_field,                     # Go to Field
    111: _emit_open_url,                       # Open URL
    135: _emit_delete_account,                 # Delete Account
    137: _emit_enable_account,                 # Enable Account
    34:  _emit_close_file,                     # Close File (current file; named-file target fenced)
    197: _emit_delete_file,                    # Delete File
    # packet 1045 — bin ④ tranche 4 (account family + portal / sort / web viewer)
    134: _emit_add_account,                    # Add Account
    136: _emit_reset_password,                 # Reset Account Password
    138: _emit_relogin,                        # Re-Login
    99:  _emit_goto_portal_row,                # Go to Portal Row
    154: _emit_sort_by_field,                  # Sort Records by Field
    146: _emit_set_web_viewer,                 # Set Web Viewer
    147: _emit_set_field_by_name,              # Set Field By Name (Get()-keyword casing now canonicalized)
    # packet 1047 — bin ④ tranche 5
    83:  _emit_change_password,                # Change Password
    77:  _emit_calc_into_target,              # Insert Calculated Result
    203: _emit_calc_into_target,              # Execute FileMaker Data API
    164: _emit_perform_script_server,         # Perform Script on Server
    119: _emit_move_resize_window,            # Move/Resize Window
    # packet 1049 — bin ④ tranche 7 (window/layout with NewWndStyles)
    74:  _emit_goto_related,                  # Go to Related Record
    122: _emit_new_window,                    # New Window
    228: _emit_goto_list,                     # Go to List of Records
    87:  _emit_show_custom_dialog,            # Show Custom Dialog
    # packet 1051 — bin ④ tranche 9
    160: _emit_insert_from_url,               # Insert from URL
    132: _emit_export_field,                  # Export Field Contents
    # packet 1052 — bin ④ tranche 10
    3:   _emit_save_as_xml,                    # Save a Copy as XML
    43:  _emit_print,                          # Print (PrintSettings; PageSetup dropped)
    42:  _emit_print_setup,                    # packet 1076 — Print Setup (empty page-setup verified;
                                              #   populated shape is class-2, opt-in only)
    # packet 1053 tranche 1 — base-shape bare / NoInteract (scriptstepsamples master pair).
    # These reuse the existing bare / NoInteract emitters; each is byte-exact vs the base-shape
    # master clip AND its DDR shape is fenced. A `()`-sig step is safe because any real configuration
    # would surface as a Parameter → a different sig → refused (never a lossy emit).
    4:   _emit_bare,        # Go to Next Field
    5:   _emit_bare,        # Go to Previous Field
    8:   _emit_bare,        # Duplicate Record/Request
    19:  _emit_bare,        # Check Record
    20:  _emit_bare,        # Check Found Set
    21:  _emit_bare,        # Unsort Records
    32:  _emit_bare,        # Open Help
    38:  _emit_bare,        # Open Manage Database
    44:  _emit_bare,        # Exit Application
    50:  _emit_bare,        # Select All
    82:  _emit_bare,        # New File
    88:  _emit_bare,        # Open Script Workspace
    93:  _emit_bare,        # Beep
    94:  _emit_bare,        # Set Use System Formats (on/off bool dropped in clip)
    98:  _emit_bare,        # Copy All Records/Requests
    101: _emit_bare,        # Copy Record/Request
    102: _emit_bare,        # Flush Cache to Disk
    105: _emit_bare,        # Open Settings
    106: _emit_bare,        # Correct Word
    107: _emit_bare,        # Spelling Options
    108: _emit_bare,        # Select Dictionaries
    109: _emit_bare,        # Edit User Dictionary
    112: _emit_bare,        # Open Manage Value Lists
    113: _emit_bare,        # Open Sharing
    114: _emit_bare,        # Open File Options
    115: _emit_bare,        # Allow Formatting Bar (on/off bool dropped in clip)
    116: _emit_bare,        # Set Next Serial Value
    118: _emit_bare,        # Open Hosts
    129: _emit_bare,        # Open Find/Replace
    133: _emit_bare,        # Open Record/Request
    140: _emit_bare,        # Open Manage Data Sources
    148: _emit_install_ontimer,  # Install OnTimer Script (packet 1129 — clear or Script+interval)
    149: _emit_bare,        # Open Edit Saved Finds
    150: _emit_perform_quick_find,  # Perform Quick Find (packet 1129 — bare or search calc)
    151: _emit_bare,        # Open Manage Layouts
    156: _emit_bare,        # Open Manage Containers
    157: _emit_bare,        # Install Plug-In File
    165: _emit_bare,        # Open Manage Themes
    172: _emit_bare,        # Open Upload to Host
    179: _emit_bare,        # AVPlayer Set Options
    188: _emit_datafile_path_target,   # Get File Exists      — packet 1126 (path + Target)
    189: _emit_datafile_path_target,   # Get File Size        — packet 1126
    191: _emit_datafile_path_target,   # Open Data File       — packet 1126
    192: _emit_write_data_file,        # Write to Data File   — packet 1126 (Encoding→DataSourceType)
    193: _emit_read_data_file,         # Read from Data File  — packet 1126 (size dropped; empty form refuses)
    194: _emit_datafile_id_target,     # Get Data File Position — packet 1126 (id + Target)
    195: _emit_datafile_id_only,       # Set Data File Position — packet 1126 (position dropped)
    196: _emit_datafile_id_only,       # Close Data File      — packet 1126 (id)
    199: _emit_bare,        # Rename File
    208: _emit_bare,        # Set Session Identifier
    223: _emit_bare,        # Set Revert Transaction on Error (on/off bool dropped)
    40:  _emit_noninteract,  # Relookup Field Contents
    51:  _emit_noninteract,  # Revert Record/Request
    65:  _emit_noninteract,  # Dial Phone
    95:  _emit_noninteract,  # Recover File
    104: _emit_noninteract,  # Delete Portal Row
    117: _emit_noninteract,  # Execute SQL
    # packet 1053 tranche 2 — base-shape option families
    11:  _emit_select_all_bare,   # Insert from Index
    12:  _emit_select_all_bare,   # Insert from Last Visited
    13:  _emit_select_all_bare,   # Insert Current Date
    14:  _emit_select_all_bare,   # Insert Current Time
    18:  _emit_select_all_bare,   # Check Selection
    46:  _emit_select_all_bare,   # Cut
    47:  _emit_select_all_bare,   # Copy
    49:  _emit_select_all_bare,   # Clear
    60:  _emit_select_all_bare,   # Insert Current User Name
    33:  _emit_option_bare,       # Open File (current file; external target fenced)
    200: _emit_option_bare,       # Set Error Logging
    207: _emit_option_bare,       # Revert Transaction
    56:  _emit_insert_embedded,   # Insert Picture
    158: _emit_insert_embedded,   # Insert PDF
    159: _emit_insert_embedded,   # Insert Audio/Video
    # packet 1053 tranche 3 — base-shape selector / state families
    30:  _selector_emitter("View"),                    # View As
    45:  _selector_emitter("UndoRedo"),                # Undo/Redo
    81:  _selector_emitter("ScrollOperation"),         # Scroll Window
    92:  _selector_emitter("ShowHide"),                # Show/Hide Text Ruler
    178: _selector_emitter("PlaybackState"),           # AVPlayer Set Playback State
    209: _selector_emitter("MainDictionary"),          # Set Dictionary
    67:  _selector_emitter("ContentType"),             # Perform AppleScript
    187: _selector_emitter("Action"),                  # Configure Local Notification
    201: _selector_emitter("Action"),                  # Configure NFC Reading
    84:  _selector_emitter("MultiUser", {"On": "True"}),           # Set Multi-User
    120: _selector_emitter("WindowArrangement", {"Tile Horizontally": "TileHorizontally"}),  # Arrange All Windows
    174: _selector_emitter("ShowHide", {"On": "Show"}),            # Enable Touch Keyboard
    155: _selector_emitter("FindMatchingRecordsByField", {"Replace": "FindMatchingReplace"}),  # Find Matching Records
    41:  _emit_enter_preview,     # Enter Preview Mode
    190: _emit_create_data_file,  # Create Data File
    64:  _emit_send_dde_execute,  # Send DDE Execute
    182: _emit_truncate_table,    # Truncate Table
    # packet 1053 tranche 4 — base-shape multi-flag steps
    48:  _emit_paste,             # Paste
    97:  _emit_set_zoom,          # Set Zoom Level
    35:  _emit_import_records,    # Import Records (base shape — no saved import order)
    # packet 1068 — FM2026-only bare steps (scriptstepsamples FM2026 XMSS pair). No options to carry;
    # absent from FM2025 entirely, so no version-shape ambiguity.
    237: _emit_bare,             # Flush Web Viewer Cookies
    247: _emit_bare,             # Cancel PDF
    66:  _emit_speak,            # Speak — Voice + Wait → SpeechOptions (no-spoken-text shape)
    202: _emit_configure_coreml,       # Configure Machine Learning Model
    212: _emit_configure_ai_account,   # Configure AI Account
    227: _emit_configure_rag_account,  # Configure RAG Account
    63:  _emit_send_mail,              # Send Mail (subtree-fenced: plain / SMTP / OAuth)
    246: lambda s: _emit_open_append_pdf(s, "OpenPDFFile"),    # Open PDF (File mode)
    244: lambda s: _emit_open_append_pdf(s, "AppendPDFFile"),  # Append PDF (File mode)
    245: _emit_close_pdf,             # Close PDF (File mode)
    243: _emit_create_pdf,            # Create PDF          — packet 1081 (shared PDF-options subtree)
    91:  _emit_replace_field_contents, # Replace Field Contents — packet 1082 (x36, top of the queue)
    130: _emit_set_selection,          # Set Selection         — packet 1082 (x23)
    61:  _emit_insert_text,            # Insert Text           — packet 1082 (x5)
    131: _emit_insert_file,            # Insert File           — packet 1082 (x24, 9 files)
    144: _emit_save_records_as_pdf,   # Save Records as PDF — packet 1081 (shared PDF-options subtree)
    152: _emit_snapshot_link,         # Save Records as Snapshot Link
    # packet 1069§② — Save-as-X family base shapes (configured export/worksheet/JSONL/PDF fenced)
    37:  _emit_save_a_copy_as,        # Save a Copy as (Copy mode; optional path)
    36:  _emit_export_records,        # Export Records (base)
    143: _emit_save_excel,           # Save Records as Excel (base)
    225: _emit_save_jsonl,           # Save Records as JSONL (base)
}

VERIFIED_STEP_IDS = frozenset(_EMITTERS)

# packet 1068 finding C — the toggle family whose On/Off state serialises DIFFERENTLY by flavor: the
# bare-steps XMSS clip carries it as a leading <Set state="…"/> (= the DDR boolean), the whole-script
# XMSC clip drops it (identical bare clip for On and Off). The per-step emitters build the XMSC (bare)
# form; _build_step prepends <Set state> for XMSS. Ground truth: the FM2026 XMSS master. Without this,
# export_object_clip(as_steps=True) silently lost a toggle's state on paste.
_XMSS_SET_STATE = frozenset({85, 86, 94, 115, 168, 223})

# Per-id VERIFIED SHAPES — the shape fence. A verified id is emitted ONLY for a DDR parameter
# signature (see _step_signature) that was round-trip-verified against the SeedDB pair. A known id
# carrying an UNSEEN option shape — an extra option boolean, a missing/rearranged parameter, a mode we
# never saw — is REFUSED, not silently emitted by an id-only dispatch (emitters read specific paths and
# would otherwise ignore unmodelled options). Computed mechanically from the pair; kept honest by
# test_clip_emit (fixture ↔ VERIFIED_STEP_IDS ↔ _VERIFIED_SIGS lockstep).
_VERIFIED_SIGS = {
    7:   {()},
    23:  {()},
    68:  {("Boolean:Collapsed", "Calculation")},
    69:  {("Boolean:Collapsed", "Boolean:Collapsed")},
    70:  {()},
    72:  {("Calculation",)},
    73:  {()},
    76:  {("FieldReference:anchor+rep", "Calculation")},   # 1109: FieldReference topology repaired (anchor/rep)
    89:  {("Comment:set",)},                                # 1109: Comment value-present token
    103: {(), ("Calculation",)},                # Exit Script: no result / with result — both verified
    125: {("Boolean:Collapsed", "Calculation")},
    141: {("Variable:val=set",), ("Variable:val=empty",)},   # packet 1129 — empty <value/> omits <Value>
    148: {(), ("ScriptReference", "Calculation")},   # Install OnTimer (packet 1129)
    150: {(), ("Calculation",)},   # Perform Quick Find (packet 1129 — search calc)
    # packet 1041 — one entry per SeedDB-verified shape; every other shape of these ids is refused
    # packet 1113 — Parameter token repaired (present-empty vs present-populated); re-spelled from the three
    # committed id-1 pairs. by-name is only proven for an EMPTY param (a populated by-name param refuses).
    1:   {("List:From list<ScriptReference>", "Parameter:set"),    # Perform Script: from-list + populated param
          ("List:From list<ScriptReference>", "Parameter:empty"),  #   from-list + empty param
          ("List:By name<Calculation>", "Parameter:empty"),        #   by-name + empty param
          # packet 1119 — external From-list target (empty param); re-derived from clip_emit_external_pairs.xml
          ("List:From list<DataSourceReference><ScriptReference>", "Parameter:empty")},
    6:   {("LRC:5", "Animation:None"), ("LRC:1", "Animation:None"),   # Go to Layout: 4 destinations
          ("LRC:3", "Animation:None"), ("LRC:4", "Animation:None"),
          # 1069§②: OriginalLayout + each animation transition (byte-exact vs stepsamples_A)
          ("LRC:1", "Animation:Slide in from Left"), ("LRC:1", "Animation:Slide in from Right"),
          ("LRC:1", "Animation:Slide in from Bottom"), ("LRC:1", "Animation:Slide out to Left"),
          ("LRC:1", "Animation:Slide out to Right"), ("LRC:1", "Animation:Slide out to Bottom"),
          ("LRC:1", "Animation:Flip from Left"), ("LRC:1", "Animation:Flip from Right"),
          ("LRC:1", "Animation:Zoom In"), ("LRC:1", "Animation:Zoom Out"),
          ("LRC:1", "Animation:Cross Dissolve"),
          # 2026-07-15 dev capture: SelectedLayout + each animation. This closes the one question the
          # LRC:1 set could NOT answer — OriginalLayout emits no <Layout> element, so we had never seen
          # <Layout> and <Animation> in the same clip and did not know their ORDER. The capture confirms
          # <Layout> then <Animation>, which is what the emitter already built; all 11 were byte-exact on
          # the first run. NB the ordering is now settled generally, but ordering is not a shape.
          ("LRC:5", "Animation:Slide in from Left"), ("LRC:5", "Animation:Slide in from Right"),
          ("LRC:5", "Animation:Slide in from Bottom"), ("LRC:5", "Animation:Slide out to Left"),
          ("LRC:5", "Animation:Slide out to Right"), ("LRC:5", "Animation:Slide out to Bottom"),
          ("LRC:5", "Animation:Flip from Left"), ("LRC:5", "Animation:Flip from Right"),
          ("LRC:5", "Animation:Zoom In"), ("LRC:5", "Animation:Zoom Out"),
          ("LRC:5", "Animation:Cross Dissolve"),
          # packet 1130 (2026-07-18 Scratch6 capture): a by-calculation destination WITH an animation.
          # Confirms <Layout><Calculation> then <Animation> byte-exact for BOTH name-by-calc and
          # number-by-calc — no name-vs-number divergence, matching what the emitter already built. One
          # animation per destination settles the ordering/coupling; the other by-calc x animation cells
          # stay experimental (uncaptured), the same design as the LRC:1/LRC:5 animation sets above.
          ("LRC:3", "Animation:Zoom In"), ("LRC:4", "Animation:Zoom In")},
    16:  {("Records:First",),                    # Go to Record: First / Next+exit / ByCalculation
          ("Records:Next[Exit after last=True]",),
          ("Records:By Calculation…[With dialog=False]<Calculation>",)},
    22:  {("Boolean:Pause=False",),              # Enter Find Mode: pause off (no restored requests)
          ("Boolean:Pause=True",)},               # 1069§②: pause on (byte-exact vs scriptstepsamples)
    # packet 1111 — Find token repaired (per-criterion anchor presence; here one anchored find criterion).
    28:  {(), ("Find:find:A",)},                 # Perform Find: no requests / one include+one anchored criterion
    # packet 1111 — Sort token repaired (Restore value + SortList option attrs + per-sort direction/anchor);
    # re-spelled from the four committed pairs. Evidence UNCHANGED.
    39:  {("Boolean:With dialog=False", "Restore=True", "SortSpec:True,False,True|Ascending@A"),      # 1 ascending
          ("Boolean:With dialog=False", "Restore=True", "SortSpec:True,False,True|Descending@A"),     # 1 descending
          ("Boolean:With dialog=False", "Restore=True", "SortSpec:True,False,True|Ascending@A,Ascending@A"),  # 2 fields
          ("Boolean:With dialog=False", "Restore=False")},   # no sort spec ("clear the sort")

    71:  {("Boolean:Collapsed", "List:Always"), ("Boolean:Collapsed", "List:Defer"),   # Loop flush
          ("Boolean:Collapsed", "List:Minimum")},   # 1069§②: Minimum→Min
    86:  {("Boolean:_=True",), ("Boolean:_=False",)},   # Set Error Capture: On/Off (identical clip)
    # packet 1044 — trivial shapes
    24:  {()}, 25: {()}, 27: {()}, 79: {()}, 90: {()},   # bare (no ParameterValues)
    169: {()}, 183: {()}, 206: {()},
    85:  {("Boolean:_=False",)},                # Allow User Abort: on/off bool, dropped in clip
    168: {("Boolean:_=False",), ("Boolean:_=True",)},   # Set Layout Object Animation: state-independent
                                                #   XMSC (bare); XMSS carries <Set state> (both committed)
    9:   {("Boolean:With dialog=False",), ("Boolean:With dialog=True",)},   # Delete Record: both dialogs
    10:  {("Boolean:With dialog=False",)},       # Delete All Records
    26:  {("Boolean:With dialog=True",),         # Omit Multiple: no count / with POPULATED count calc
          ("Boolean:With dialog=False", "Calculation:set")},   # :set discriminator — packet 1103
    62:  {("Options:Duration (seconds): ",)},    # Pause/Resume: duration mode only
    # packet 1045 — bin ④ tranche 1
    96:  {("Boolean:Replace UUIDs=False",)},     # Save a Copy as Add-on Package
    166: {("List:Hide", "Boolean:Lock=False"), ("List:Hide", "Boolean:Lock=True"),
          ("List:Show", "Boolean:Lock=False")},  # Show/Hide Menubar
    29:  {("Boolean:Lock=False", "Boolean:Include Edit Record Toolbar=False", "List:Hide"),
          ("Boolean:Lock=False", "Boolean:Include Edit Record Toolbar=False", "List:Show"),
          ("Boolean:Lock=True", "Boolean:Include Edit Record Toolbar=False", "List:Hide")},  # Toolbars
    142: {("CustomMenuSet:default=True",)},      # Install Menu Set — 1108: default-flag value-scoped token
    31:  {("List:Maximize",), ("List:Resize to Fit",), ("List:Hide",)},   # Adjust Window (packet 1129 Hide)
    126: {("Boolean:Find without indexes=False",)},       # Constrain Found Set
    55:  {("Boolean:Pause=False",)},             # Enter Browse Mode
    127: {()},                                   # Extend Found Set (no params)
    # packet 1045 — bin ④ tranche 2
    # object-name family — 1108: repetition presence is signature topology (145/167 carry it; 180 does not)
    145: {("Object:rep",)}, 167: {("Object:rep",)}, 180: {("Object",)},
    175: {("Name", "FunctionRef"), ("Name", "FunctionRef", "Parameter:args=1"),
            ("Name", "FunctionRef", "Parameter:args=2")},   # Perform JavaScript (packet 1129 — args)
    75:  {("Boolean:Skip data entry validation=False", "Boolean:With dialog=False", "Boolean:Force Commit=False"),
          ("Boolean:Skip data entry validation=False", "Boolean:With dialog=True", "Boolean:Force Commit=False")},
    80:  {("Boolean:Flush cached join results=False", "Boolean:Flush cached external data=False")},
    205: {("Boolean:Collapsed", "Boolean:Skip auto-enter options=False",
           "Boolean:Skip data entry validation=False", "Boolean:Override ESS locking conflicts=False"),
          ("Boolean:Collapsed", "Boolean:Skip auto-enter options=True",
           "Boolean:Skip data entry validation=True", "Boolean:Override ESS locking conflicts=False")},
    # packet 1045 — bin ④ tranche 3. 1108: the WindowReference/FieldReference tokens are REPAIRED to carry the
    # target-driving topology (selection mode + current flag + Rename; TO-anchor + repetition) — re-derived
    # from these same committed pairs (topology fidelity, not evidence growth). 119/122 (WindowReference) and
    # 76/91/130/132 (FieldReference) are out of scope and keep the bare token (id-scoped in _step_signature).
    121: {("WindowReference:current",), ("WindowReference:byname(current=False)",)},   # current + by-name
    123: {("WindowReference:byname(current=True)",)},                                   # by-name, limit-to-file
    124: {("WindowReference:current+rename",)},                                         # Set Window Title
    17:  {("Boolean:Select/perform=True",),   # packet 1129 — no-field (Select-only) form
          ("Boolean:Select/perform=False", "FieldReference:anchor+rep"),
          ("Boolean:Select/perform=True", "FieldReference:anchor+rep")},
    111: {("Boolean:In external browser=True", "Boolean:With dialog=False", "URL")},
    135: {("Calculation",)},                    # Delete Account
    137: {("Calculation", "Boolean:enable=False"), ("Calculation", "Boolean:enable=True")},
    197: {("UniversalPathList",)},              # Delete File (single path)
    # packet 1045 — bin ④ tranche 4
    134: {("AccountType:FileMaker", "Name", "Password", "PrivilegeSetReference", "Boolean:Expire password=False")},
    136: {("Name", "Password", "Boolean:Password=False")},
    138: {("DataSourceReference:current", "Boolean:With dialog=False", "Name", "Password"),
          # packet 1119 — external Re-Login: no-creds (With dialog=False) + creds (With dialog=True), from
          # clip_emit_external_pairs.xml. Credentials both-present or both-absent (option-rule coupling).
          ("DataSourceReference:external", "Boolean:With dialog=False"),
          ("DataSourceReference:external", "Boolean:With dialog=True", "Name", "Password")},
    34:  {("DataSourceReference:current",),         # Close File — current file (named-file fenced)
          ("DataSourceReference:external",)},       # packet 1119 — external Close File (clip_emit_external_pairs.xml)
    # packet 1111 — Portal token repaired (inner With-dialog value → NoInteract).
    99:  {("Boolean:Select=True", "Portal:By Calculation…[With dialog=False]"),
            ("Boolean:Select=False", "Portal:First[With dialog=None]"),
            ("Boolean:Select=False", "Portal:Last[With dialog=None]"),
            ("Boolean:Select=False", "Portal:Next[With dialog=None]"),
            ("Boolean:Select=False", "Portal:Previous[With dialog=None]")},   # packet 1129 — direct nav
    154: {("List:Descending",),   # packet 1129 — no-field (direction-only) form
          ("List:Ascending", "FieldReference:anchor+rep"),        # 1108: FieldReference topology repaired
          ("List:Descending", "FieldReference:anchor+rep")},
    146: {("Calculation", "action:Go to URL...")},
    147: {("Boolean:Specify target field=True", "Calculation", "Calculation")},   # Set Field By Name
    # packet 1047 — bin ④ tranche 5
    83:  {("Old", "New", "Boolean:With dialog=False")},          # Change Password
    77:  {("Boolean:Select=True", "Target:field:anchor+rep", "Calculation")},   # 1109: field-target topology
    203: {("Boolean:Select=True", "Target:var+rep", "Calculation")},            # 1109: variable-target topology
    # packet 1113 — Parameter token repaired (present-empty vs present-populated); re-spelled from the three
    # committed id-164 pairs (by-name empty+waitFalse, by-name populated+waitTrue, from-list populated+waitTrue).
    164: {("List:By name<Calculation>", "Parameter:empty", "Boolean:Wait for completion=False"),
          ("List:By name<Calculation>", "Parameter:set", "Boolean:Wait for completion=True"),
          ("List:From list<ScriptReference>", "Parameter:set", "Boolean:Wait for completion=True"),
          # packet 1119 — external PSoS From-list (populated param), both Wait values; from clip_emit_external_pairs.xml
          ("List:From list<DataSourceReference><ScriptReference>", "Parameter:set", "Boolean:Wait for completion=True"),
          ("List:From list<DataSourceReference><ScriptReference>", "Parameter:set", "Boolean:Wait for completion=False")},
    # packet 1110 — WindowReference topology repaired (selection mode + per-bound presence); re-spelled from
    # the two committed pairs (current selection, all-four bounds vs width-only). Evidence UNCHANGED.
    119: {("MoveResize:current|bounds=1111",), ("MoveResize:current|bounds=0100",)},   # Move/Resize Window
    # packet 1049 — bin ④ tranche 7 · packet 1110 — Related topology repaired (matchFoundSet / new-window /
    # destination / bounds / style-options), re-spelled from the three committed pairs. Evidence UNCHANGED.
    74:  {("GTRR:match=False|window=absent|dest=5",),
          ("GTRR:match=False|window=absent|dest=3",),
          ("GTRR:match=True|window=present|dest=5|bounds=1111|style=Card,opts=0000001",)},   # Go to Related Record
    # packet 1110 — WindowReference topology repaired (destination / Name-calc presence / bounds / style-
    # options); re-spelled from the two committed pairs (Card+empty-name, Document+no-name). Evidence UNCHANGED.
    122: {("NewWindow:dest=5|name=calc|bounds=0000|style=Document,opts=1111110",),   # packet 1129 captures:
            ("NewWindow:dest=5|name=calc|bounds=0000|style=Document,opts=0110110",),
            ("NewWindow:dest=5|name=calc|bounds=0000|style=Dialog,opts=0000000",),
            ("NewWindow:dest=5|name=calc|bounds=0000|style=Card,opts=1000001",),
          ("NewWindow:dest=5|name=calc|bounds=0000|style=Card,opts=0000001",),
          ("NewWindow:dest=5|name=none|bounds=0000|style=Document,opts=1111110",)},          # New Window
    228: {("LRC:1", "Animation:None")},                          # Go to List of Records
    # packet 1116 — the Button/Field tokens re-spelled to carry Commit/label + input target/password/label
    # topology (repetition projected away); re-derived from the three committed dialog pairs. Title/Message keep
    # the bare token (presence is the discriminator; calc TEXT is content).
    # packet 1120 — button label token gained a SOURCE (attr/calc); geometry rides as height/width/top/left
    # tokens; the input-field kind now includes `field`. The three pre-1120 SeedDB pairs (attr-label buttons, no
    # geometry, variable/empty inputs) are re-spelled label=set→label=attr and stay byte-exact; the four refreshed
    # Scratch2 pairs add the calc-label + geometry + field/empty/variable input forms.
    87:  {("Message", "Button1:commit=False|label=attr", "Button2:commit=False|label=none",   # Show Custom Dialog
           "Button3:commit=False|label=none"),
          ("Title", "Message", "Button1:commit=False|label=attr", "Button2:commit=False|label=none",
           "Button3:commit=False|label=none"),
          ("Title", "Message", "Button1:commit=True|label=attr", "Button2:commit=False|label=attr",
           "Button3:commit=False|label=none", "Field1:var|pwd=True|label=set"),
          # packet 1120 — refreshed Scratch2: geometry + calc-backed buttons + the three input target forms
          ("Title", "Message", "height", "width", "top", "left",
           "Button1:commit=True|label=calc", "Button2:commit=True|label=calc", "Button3:commit=True|label=calc",
           "Field1:field|pwd=True|label=set", "Field2:field|pwd=True|label=set", "Field3:field|pwd=True|label=set"),
          ("Title", "Message", "height", "width", "top", "left",
           "Button1:commit=False|label=calc", "Button2:commit=False|label=calc", "Button3:commit=False|label=calc",
           "Field1:field|pwd=True|label=set"),
          ("Title", "Message", "height", "width", "top", "left",
           "Button1:commit=False|label=calc", "Button2:commit=False|label=calc", "Button3:commit=False|label=calc"),
          ("Title", "Message", "height", "width", "top", "left",
           "Button1:commit=False|label=calc", "Button2:commit=False|label=calc", "Button3:commit=False|label=calc",
           "Field1:var|pwd=False|label=none", "Field2:var|pwd=False|label=none", "Field3:var|pwd=False|label=none")},
    # packet 1051 — bin ④ tranche 9. packet 1115 — Target token → field/var+rep topology; URL token → autoEncode.
    160: {("Boolean:Verify SSL Certificates=False", "Boolean:Select=True", "Boolean:With dialog=False",
           "Target:field:anchor+rep", "URL:autoEncode=True"),
          ("Boolean:Verify SSL Certificates=False", "Boolean:Select=True", "Boolean:With dialog=False",
           "Target:var+rep", "URL:autoEncode=True", "Calculation")},
    # packet 1115 — FieldReference token → anchor+rep topology; the with-path UPL token carries AutoOpen.
    132: {("Boolean:Create folders=False", "FieldReference:anchor+rep"),
          ("Boolean:Create folders=True", "FieldReference:anchor+rep", "UniversalPathList:AO=True,CM=_")},
    # packet 1052 — bin ④ tranche 10
    3:   {("Calculation", "UniversalPathList", "Boolean:Include details for analysis tools=True",
          "Boolean:Save each layout object's binary data under its node=False",
          "Boolean:Specify options as JSON=False")},
    # packet 1076 — the `PageSetup` token gained an empty/set discriminator; 43's verified pairs carry a
    # POPULATED page setup that FileMaker's Print clip simply does not serialise (no <PageFormat> at
    # all), so these stay byte-exact. Note both are `With dialog=True`: the configured `With
    # dialog=False` shape's clip DOES carry a PlatformData printer ticket, and is correctly refused —
    # the dialog flag, already in the sig, is what separates them.
    # packet 1112 — Print token repaired (toFile + Pages/@All appended); re-spelled from the two committed pairs.
    43:  {("Boolean:With dialog=True", "Restore", "Print:Current record|toFile=False|all=True", "PageSetup:set"),
          ("Boolean:With dialog=True", "Restore", "Print:Records being browsed|toFile=False|all=True",
           "PageSetup:set")},
    # packet 1053 tranche 1 — base-shape bare / NoInteract. Each id's ONE observed default shape.
    4: {()}, 5: {()}, 8: {()}, 19: {()}, 20: {()}, 21: {()}, 32: {()}, 38: {()}, 44: {()},
    50: {()}, 82: {()}, 88: {()}, 93: {()}, 98: {()}, 101: {()}, 102: {()}, 105: {()}, 106: {()},
    107: {()}, 108: {()}, 109: {()}, 112: {()}, 113: {()}, 114: {()}, 116: {()}, 118: {()},
    129: {()}, 133: {()}, 140: {()}, 149: {()}, 151: {()}, 156: {()},
    157: {()}, 165: {()}, 172: {()}, 179: {()}, 199: {()}, 208: {()},
    94:  {("Boolean:_=True",)},     # Set Use System Formats (on/off dropped in clip)
    115: {("Boolean:_=False",)},    # Allow Formatting Bar
    223: {("Boolean:_=False",)},    # Set Revert Transaction on Error
    40:  {("Boolean:With dialog=False",)},   # Relookup Field Contents
    51:  {("Boolean:With dialog=False",)},   # Revert Record/Request
    65:  {("Boolean:With dialog=False",)},   # Dial Phone
    95:  {("Boolean:With dialog=False",)},   # Recover File
    104: {("Boolean:With dialog=True",)},    # Delete Portal Row
    117: {("Boolean:With dialog=False", "Boolean:Create folders=False")},   # Execute SQL
    # packet 1053 tranche 2 — base-shape option families
    11: {("Boolean:Select=True",)}, 12: {("Boolean:Select=True",)}, 13: {("Boolean:Select=True",)},
    14: {("Boolean:Select=True",)}, 18: {("Boolean:Select=True",)}, 46: {("Boolean:Select=True",)},
    47: {("Boolean:Select=True",)}, 49: {("Boolean:Select=True",)}, 60: {("Boolean:Select=True",)},
    33:  {("Boolean:Open hidden=False", "DataSourceReference:current"),    # Open File (current)
          # packet 1119 — external Open File, both Open-hidden values (clip_emit_external_pairs.xml)
          ("Boolean:Open hidden=False", "DataSourceReference:external"),
          ("Boolean:Open hidden=True", "DataSourceReference:external")},
    200: {("Boolean:enabled=False",)},                                     # Set Error Logging
    207: {("Boolean:Condition=False", "Boolean:Error Code=False")},        # Revert Transaction
    56:  {("Boolean:Store only a reference=False",)},   # Insert Picture (embedded)
    158: {("Boolean:Store only a reference=False",)},   # Insert PDF
    159: {("Boolean:Store only a reference=False",)},   # Insert Audio/Video
    # packet 1053 tranche 3 — base-shape selector / state families
    30: {("List:Cycle",)}, 45: {("Boolean:Collapsed=False", "List:Undo")}, 81: {("List:Home",)},   # 1106 :value
    92: {("List:Show",)}, 178: {("List:Stopped",)}, 209: {("List:US English",)},
    67: {("Options:Text",)}, 187: {("action:Queue",)}, 201: {("action:Read",)},
    84: {("List:On",)}, 120: {("List:Tile Horizontally",)}, 174: {("List:On",)}, 155: {("List:Replace",)},
    41:  {("Boolean:Pause=False",)},           # Enter Preview Mode
    # packet 1126 — the Data File I/O family. Base (empty/bool-only) shapes stay verified; the configured
    # shapes are the paired DF Cases capture (variable targets, all 9 ids) + the configured-master field
    # targets (192/193). Encoding@type is appended to 192/193's signature so an uncaptured encoding emits
    # experimental (not verified). Read's byte <size> and Set Position's <position> are shape (present/absent
    # is a distinct shape) though the clip drops their value.
    188: {(), ("UniversalPathList", "Target:var+rep")},          # Get File Exists
    189: {(), ("UniversalPathList", "Target:var+rep")},          # Get File Size
    191: {(), ("UniversalPathList", "Target:var+rep")},          # Open Data File
    194: {(), ("id", "Target:var+rep")},                         # Get Data File Position
    195: {()},                                                  # Set Data File Position — base only (pkt 1127:
                                                                #   a present New position is unrepresentable → refuse)
    196: {(), ("id",)},                                          # Close Data File
    192: {("id", "Target:var+rep", "Boolean:Append line feed=True", "Encoding:1"),        # Write (variable)
          ("id", "Target:field:anchor+rep", "Boolean:Append line feed=True", "Encoding:1")},  # Write (field)
    # packet 1127 Stage E — the size-bearing 193 shapes are MATERIALLY UNREPRESENTABLE (Amount lost on the
    # native clip AND on paste round-trip; they moved to the projection-conflict fixture and refuse). The ONE
    # verified 193 shape is the NO-Amount form, paste-proven idempotent by the Stage-B return (1f7f8a11).
    193: {("id", "Target:var+rep", "Encoding:3")},              # Read from Data File — no-Amount, variable, Bytes
    190: {("Boolean:Create folders=True",),                      # Create Data File — base (bool only)
          ("UniversalPathList", "Boolean:Create folders=True")}, #   configured (path + Create folders)
    64:  {()},                                  # Send DDE Execute (constant ContentType)
    182: {("Boolean:With dialog=True", "List:<Current Table>")},   # Truncate Table (current table)
    # packet 1053 tranche 4 — base-shape multi-flag steps
    48:  {("Boolean:Select=True", "Boolean:No style=True")},                   # Paste
    97:  {("Boolean:Lock=False", "List:100%")},                                # Set Zoom Level
    35:  {("Boolean:Verify SSL Certificates=False", "Boolean:With dialog=False")},  # Import Records
    # packet 1068 — FM2026-only bare steps
    237: {()}, 247: {()},
    # packet 1114 — Voice/Wait tokens re-spelled to carry the effect-driving VoiceId + WaitForCompletion values.
    66:  {("Voice:0", "Wait:True")},    # Speak — no-spoken-text base shape (a spoken-text calc refuses by name)
    # packet 1068 — configured AI-config family (one verified shape each; unseen shapes refused)
    202: {("operation:uninstall", "name")},   # packet 1069 — selector-fenced to the verified operation
    # packet 1078 — the five captured provider shapes. The SSL flag + provider + endpoint-presence are part of
    # each sig. packet 1114 — under the capability model SSL is orthogonal to provider (the Options-bit proof),
    # so the two uncaptured SSL/provider recombinations now emit generated_EXPERIMENTAL (capability-complete),
    # while an unseen PROVIDER or a mismatched endpoint coupling refuses capability-first. Custom carries the
    # extra LLMEndpoint param, hence its own longer shape.
    212: {("Boolean:Verify SSL Certificates=False", "List:OpenAI", "LLMAPIKey", "LLMAccountName"),
          ("Boolean:Verify SSL Certificates=False", "List:Anthropic", "LLMAPIKey", "LLMAccountName"),
          ("Boolean:Verify SSL Certificates=False", "List:Cohere", "LLMAPIKey", "LLMAccountName"),
          ("Boolean:Verify SSL Certificates=False", "List:Google", "LLMAPIKey", "LLMAccountName"),
          ("Boolean:Verify SSL Certificates=True", "List:Custom", "LLMAPIKey", "LLMEndpoint",
           "LLMAccountName")},
    227: {("Boolean:Verify SSL Certificates=True", "RAGAPIKey", "RAGAccountName")},
    # packet 1068 — Send Mail: the send-mode + crypto fingerprints. packet 1114 — the Email token is re-spelled
    # to carry the FULL target-driving topology (dialog/Multiple/attachment/recipient/CollectAddresses/content
    # presence + SMTP-field presence), re-derived from the FOUR committed pairs. The plain Multiple=False and
    # Multiple=True pairs (which collided under the old fingerprint) are now distinct verified tuples.
    63:  {("Email:smtp0:none/none;oauth0:none|dlg=True|mult=False|att=1|To1:True/CC1:True/BCC1:True|s1m1|smtp[]",),
          ("Email:smtp1:TLS/Plain Password;oauth0:none|dlg=True|mult=False|att=1|"
           "To1:True/CC1:True/BCC1:True|s1m1|smtp[1111111]",),
          ("Email:smtp0:none/none;oauth1:Google|dlg=True|mult=False|att=1|To1:True/CC1:True/BCC1:True|s1m1|smtp[]",),
          ("Email:smtp0:none/none;oauth0:none|dlg=True|mult=True|att=1|To1:_/CC1:_/BCC1:_|s1m1|smtp[]",)},
    # packet 1068 — PDF file ops, File mode only (Target mode's clip path isn't in the DDR → fenced).
    # packet 1069 — the From/SaveTo save-mode is now selector-fenced (File); other modes refused.
    # packet 1082 — the top of the real-corpus queue. Each shape byte-exact vs a committed pair; the
    # base+configured pairs BOTH verified on purpose, because these are 1069 fence-holes: it is the pair
    # of shapes that proves the discriminator works, not either one alone.
    # packet 1120 — serial mode is value-DRIVEN (Entry-option-values now fenced into the replace token); the
    # calculation-mode shape is RETRACTED (its clip SerialNumbers is the target field's state, not step-derived —
    # see clip_emit_calc_conflict.xml + _cap_replace_field_contents). Two refreshed serial shapes added.
    91:  {("Boolean:With dialog=False", "replace:Current contents=0[Skip auto-enter options=False]"),
          ("Boolean:With dialog=False", "FieldReference",
           "replace:Current contents=1[Skip auto-enter options=False]"),
          ("Boolean:With dialog=False", "FieldReference",         # serial, defer to entry options, Update=False
           "replace:Replace with serial numbers: =2[Skip auto-enter options=False]"
           "[Update Entry Options=False][Entry option values=True]"),
          ("Boolean:With dialog=False", "FieldReference",         # 1120 — serial, Update Entry Options=True
           "replace:Replace with serial numbers: =2[Skip auto-enter options=False]"
           "[Update Entry Options=True][Entry option values=True]"),
          ("Boolean:With dialog=False", "FieldReference",         # 1120 — serial, explicit Initial/increment
           "replace:Replace with serial numbers: =2[Skip auto-enter options=False]"
           "[Update Entry Options=False][Entry option values=False+iv]")},
    130: {("Select:empty",), ("FieldReference", "Select:startend"), ("FieldReference", "Select:start")},  # 1129 lone bound
    # 131 Insert File — the base shape has NO parameters at all (its clip is still a full DialogOptions
    # skeleton), and the configured one carries all five <Options> siblings. The fingerprint exposes the
    # Storage/Display/Compress enums the old `Options:Title` token hid; only 'Let user choose' (=0) is
    # sampled, so any other dialog mode is a new sig and refuses.
    # packet 1115 — the Target token → anchor presence (131's _emit_field_ref drops the repetition).
    131: {(),
          ("Options:[Title,Filters,Storage=0,Display=0,Compress=0]", "Target:anchor", "UniversalPathList")},
    61:  {("Boolean:Select=True", "Text:empty"), ("Boolean:Select=True", "Target:field", "Text:set"),
          ("Boolean:Select=True", "Target:var", "Text:set"), ("Boolean:Select=True", "Text:set")},  # 1129 var / no-target
    246: {("PDFPassword", "UniversalPathList", "Boolean:Create folders=False", "From:File")},
    244: {("PDFPassword", "UniversalPathList", "Boolean:Create folders=False", "From:File")},
    245: {("UniversalPathList", "Boolean:Create folders=False", "SaveTo:File")},
    # packet 1081 — the PDF-options family. Each shape below is byte-exact against a committed pair in
    # scriptstepsamples_configured_fm2026_xmss.xml; the fingerprint (see _pdf_options_fingerprint) makes
    # the enum LOOKUPS part of the fence, so an unseen Security/View value refuses instead of missing a
    # lookup. The dev's samples vary ONE axis at a time — 243 holds View fixed while walking Edit/Print,
    # then holds Security fixed while walking View — so each axis's mapping is independently observed.
    # NOTE what is deliberately ABSENT: the BASE shape of both ids (an empty <Options/> for 243; no
    # Security/View for 144). Its clip carries a full non-default config (AnyExceptExtractingPages /
    # HighResolution / 100 / SinglePage / PagesPanelAndPage) that the DDR does not hold at all — so the
    # DDR does not determine the clip there and no emitter can. That is a class-2 SIGNATURE, but we have
    # one sample and class-2 needs the higher bar (243 was already mis-filed as class-2 once), so it is
    # recorded as an open question in docs/clip-emit-coverage.md, NOT declared. Either way it refuses.
    243: {("Restore", f"Options:None|Doc[Title,Subject,Author,Keywords]+Sec[Open=True:pw,Control=True:pw,"
                      f"Print={pr},Edit={ed},EnableCopying=True,AllowScreenReader=True]+"
                      f"View[show={sh},Layout={la},Magnification={mg}]")
          for pr, ed, sh, la, mg in (("0", "0", "0", "0", "0"),   # all-default security + view
                                     ("1", "0", "0", "0", "0"),   # controlPrinting: Low Resolution
                                     ("2", "0", "0", "0", "0"),   # controlPrinting: High Resolution
                                     ("0", "1", "0", "0", "0"),   # controlEditing: inserting/deleting
                                     ("0", "2", "0", "0", "0"),   # controlEditing: filling in forms
                                     ("0", "3", "0", "0", "0"),   # controlEditing: commenting
                                     ("0", "4", "0", "0", "0"),   # controlEditing: any except extract
                                     ("0", "0", "1", "1", "1"),   # view: bookmarks/single/fit-page
                                     ("0", "0", "2", "2", "2"))},  # view: pages/continuous/fit-width
    144: ({("Restore", f"Options:{src}|Doc[]+Pages[from;All=True]+Sec[Open=False,Control=False,Print=2,"
                       f"Edit=4,EnableCopying=True,AllowScreenReader=True]+"
                       f"View[show=2,Layout=1,Magnification=7]",
            "Boolean:With dialog=False", "Boolean:Append to existing PDF=True", "UniversalPathList",
            "Boolean:Create folders=True", "SaveResult")
           for src in ("Records being browsed", "Current record", "Blank record, as formatted",
                       "Blank record, with boxes", "Blank record, with underlines",
                       "Blank record, with placeholder text")}          # File mode, each record source
          | {("Restore", "Options:Records being browsed|Doc[]+Pages[from;All=True]+Sec[Open=False,"
                         "Control=False,Print=2,Edit=4,EnableCopying=True,AllowScreenReader=True]+"
                         "View[show=2,Layout=1,Magnification=7]", tail, "SaveResult")
             for tail in ("Target",)}                                   # Target mode → clip <Field>
          | {("Restore", "Options:Records being browsed|Doc[]+Pages[from;All=True]+Sec[Open=False,"
                         "Control=False,Print=2,Edit=4,EnableCopying=True,AllowScreenReader=True]+"
                         "View[show=2,Layout=1,Magnification=7]", "SaveResult")}),  # Append mode
    152: {("UniversalPathList", "List:Records being browsed", "Boolean:Create folders=True"),
          ("UniversalPathList", "List:Current record", "Boolean:Create folders=True")},
    # packet 1069§② — Save-as-X family base shapes (configured variants carry a different sig → fenced).
    # packet 1115 — the with-path UPL token carries its AutoOpen/CreateMail (absent → `_`).
    37:  {("List:copy of current file", "Boolean:Create folders=True"),
          ("UniversalPathList:AO=_,CM=_", "List:copy of current file", "Boolean:Create folders=True")},
    # packet 1117 — base + the configured shapes (id-scoped topology tokens re-derived from the four
    # committed configured pairs; base sigs byte-identical). 143 carries both save modes.
    36:  {("Boolean:With dialog=False", "Boolean:Create folders=False", "ExportUPL:TABS",
           "Export:cs=Unicode (UTF-16),fmt=False,order=Group;Field:2"),   # packet 1129 — TABS/Unicode
          ("Boolean:With dialog=False", "Boolean:Create folders=True"),
          ("Boolean:With dialog=False", "Boolean:Create folders=True", "ExportUPL:COMS",
           "Export:cs=Macintosh,fmt=True,order=Group;Field:1")},
    143: {("Restore", "Boolean:With dialog=False", "Options:None", "Boolean:Create folders=True"),
          ("Restore", "Boolean:With dialog=False",
           "ExcelUPL:ft=XLXE,mode=Records being browsed=1,ufn=True,meta=Worksheet|Title|Subject|Author",
           "Options:None", "Boolean:Create folders=True"),
          ("Restore", "Boolean:With dialog=False",
           "ExcelUPL:ft=XLXE,mode=Current record=2,ufn=True,meta=Worksheet|Title|Subject|Author",
           "Options:None", "Boolean:Create folders=True")},
    225: {("Boolean:Format for fine-tuning=False", "Boolean:Create folders=False"),
          ("JSONLPath", "JSONLField:anchored", "JSONLTable",
           "Boolean:Format for fine-tuning=False", "Boolean:Create folders=False")},
    # packet 1076 — Print Setup, EMPTY page-setup shape only. The populated shape is source-incomplete
    # (see _SOURCE_INCOMPLETE_SIGS) and deliberately NOT verified: it cannot be byte-exact, ever.
    42:  {("Restore", "Boolean:With dialog=False", "PageSetup:empty")},
}
assert set(_VERIFIED_SIGS) == set(_EMITTERS), "every verified id must declare its verified shape(s)"


# ── packet 1076 — SOURCE-INCOMPLETE shapes: the class-2 register ────────────────
#
# This is the first deliberate departure from "emit only what is byte-exact", and it is narrow ON
# PURPOSE. A shape belongs here ONLY when the clip provably carries data the DDR does not hold — a
# CLASS-2 (source-completeness) gap, not a class-1 coverage gap. The distinction is not stylistic:
#
#   class 1 — "not yet".            A capture fixes it. It goes in _VERIFIED_SIGS once captured.
#   class 2 — "never, from here".   No capture and no emitter recovers it. It goes HERE, labelled.
#
# For Print Setup the class-2 claim is PROVEN, not argued: two steps with byte-identical DDR content
# produce clips with different PlatformData (sha cf61b50e… vs f8816f59…, 14196 vs 15034 chars). The
# DDR→clip transform is therefore not a function, so no emitter can reproduce the clip from the DDR.
#
# THREE RULES, all load-bearing:
#   1. These shapes NEVER enter _VERIFIED_SIGS. Byte-exactness is what that set means; claiming it here
#      would corrupt the one word the whole fence rests on.
#   2. Emission is the DEFAULT (packet 1089): a registered source-incomplete shape generates its
#      schema-held minimum, with the limitations disclosed in the RESULT METADATA (never in the clip XML).
#      A caller that explicitly asks for strict/verified-only output still gets no clip. The label is the
#      guard now, not opt-in refusal.
#   3. Every entry splits its target facts THREE ways (packet 1089), each independently machine-readable —
#      an ordinary implementation omission must never be mislabelled unrecoverable:
#        · emitted_from_source        — facts actually emitted from the SaveAsXML data;
#        · source_held_unimplemented  — facts the SaveAsXML DOES hold that this emitter does not yet map
#                                        (class-1; implementable; a capture does NOT fix it, code does);
#        · source_absent_for_target   — facts the SaveAsXML projection provably never contained (class-2;
#                                        no capture and no emitter recovers them; must stay UNSET).
#
# source_absent_for_target lists clip attributes/elements we cannot produce; a consumer must treat them as
# unset, not defaulted. Inventing plausible values was considered and REJECTED (packet 1076 option C):
# machine state presented as schema is exactly the silent-lossy paste the fence forbids.
_SOURCE_INCOMPLETE_SIGS = {
    42: {("Restore", "Boolean:With dialog=False", "PageSetup:set"): {
        "gap_class": 2,
        "emitted_from_source": ["PageFormat/@PageOrientation", "PageFormat/@ScaleFactor"],
        # PAPER SIZE is source-HELD, not source-absent: the DDR's <PageSetup><size> carries it (proven
        # 2026-07-15 — a masked clip round-tripped an A4 step back as US Letter precisely because we emit
        # NO size). It is a class-1 IMPLEMENTATION omission, deliberately not built: the clip's Paper* rect
        # entangles the paper size with the driver's print MARGIN (the -18,-18 origin), which IS
        # source-absent, so emitting size alone would assert a margin we do not have. Naming it here keeps
        # us honest — the transform did NOT reproduce everything the source held. The mapping is a later
        # narrow decision (NOT part of the closed 1086–1090 sequence); do NOT open a capture campaign or
        # build it here.
        "source_held_unimplemented": ["PageFormat paper size (DDR <PageSetup><size>)"],
        "source_absent_for_target": ["PageFormat/@PrintableHeight", "PageFormat/@PrintableWidth",
                                     "PageFormat/@PaperTop", "PageFormat/@PaperLeft",
                                     "PageFormat/@PaperRight", "PageFormat/@PaperBottom",
                                     "PageFormat/PlatformData"],
        "why": "The clip's <PageFormat> carries printer-COMPUTED geometry (the Paper* margin rect + "
               "Printable*) and a machine-specific PlatformData ticket, none of which the DDR holds. "
               "Proven unrecoverable: two Print Setup steps with byte-identical DDR content produce clips "
               "with different PlatformData, so the DDR does not determine the clip. Paper SIZE is the one "
               "exception — the DDR DOES hold it — but it is not emitted (source_held_unimplemented), "
               "because the Paper* rect entangles it with the absent driver margin.",
        # packet 1112 — corrected: the paste test was RUN and came back GREEN (dev, FM Pro 2026/macOS,
        # 2026-07-15 — see the emitter comment + changelog). The masked clip PASTES; FileMaker fills its own
        # printer defaults for the omitted geometry and orientation+scale survive. `paste_untested` was a stale
        # True; the source-incompleteness is unchanged (still class-2, Paper*/PlatformData unrecoverable).
        "paste_untested": False,
    }},
}


def _source_incomplete_entry(step):
    """The class-2 entry for this step's shape, or None. Separate from `_unsupported_reason` on
    purpose: a source-incomplete shape is not 'unsupported' (we CAN emit its schema-held part) and
    not 'verified' (we can never emit all of it). It is its own third answer."""
    try:
        sid = int(step.get("id"))
    except (TypeError, ValueError):
        return None
    return _SOURCE_INCOMPLETE_SIGS.get(sid, {}).get(_step_signature(step))


# ── packet 1091 — code-adjacent capability rules (the script analogue of field_emit._field_capability) ─
#
# Until now the script emitter's permission model was "exact verified signature or refuse". Packet 1088
# established for FIELDS that permission must come from IMPLEMENTED CAPABILITY, with fixture membership
# demoted to EVIDENCE (verified vs experimental). This is the first — deliberately narrow — migration of
# that split to the SCRIPT emitter: ONE family, Delete Record/Request (9) and Delete All Records (10),
# whose entire option grammar is a single `With dialog` Boolean that the shared _emit_noninteract already
# maps in both polarities (False→NoInteract True, True→NoInteract False).
#
# A capability rule receives the actual DDR <Step> and returns None (the current transform fully accounts
# for this shape → it may emit EXPERIMENTALLY when uncaptured) or a concrete (reason_code, detail) naming
# the source structure the emitter would otherwise silently ignore. The ABSENCE of a rule for an id means
# "not migrated": an unseen shape of that id stays refused, exactly as before. A rule NEVER duplicates the
# verified signature set — verified shapes are matched earlier, as evidence, and need no capability entry.
#
# SCOPE FENCE (do NOT widen without a packet). The migrated set is the SIMPLE one-Boolean family — an id
# whose ONLY target-driving parameter is the single `With dialog` Boolean the shared helper fully consumes:
# 9/10 (packet 1091) + 40/51/65/95/104 (packet 1092 — Relookup / Revert Record / Dial Phone / Recover File
# / Delete Portal Row; each inspected against its committed DDR half). Deliberately EXCLUDED, even though
# they share _emit_noninteract: 26 (Omit Multiple — an optional count <Calculation>) and 117 (Execute SQL —
# a second `Create folders` Boolean the helper does not read); their grammar is NOT one Boolean, so an
# unseen shape of theirs stays refused. The other users (35/63/75/83/111/138/160/182 …) likewise carry
# extra options and are unmigrated. Sharing a Python helper does not prove identical source capability.
_NOINTERACT_DIALOG_VALUES = frozenset({"True", "False"})   # the observed FileMaker 'With dialog' values


def _cap_noninteract_dialog(step) -> "tuple[str, str] | None":
    """ids 9/10 capability rule. Capable iff EXACTLY one `<Parameter type="Boolean">` carrying one
    `<Boolean type="With dialog">` whose value is an observed True/False — and nothing else. Any extra
    parameter, attribute, child, or an out-of-vocabulary value is a shape the ids-9/10 grammar does not
    account for, and refuses BY NAME (it would otherwise be silently ignored by _emit_noninteract, which
    reads only the With-dialog Boolean and an optional count calc that these two ids never carry)."""
    pv = step.find("ParameterValues")
    if pv is not None and any(c.tag != "Parameter" for c in pv):
        return ("capability_unaccounted_shape",
                "a non-Parameter child under <ParameterValues> that the ids-9/10 grammar does not model")
    params = pv.findall("Parameter") if pv is not None else []
    if len(params) != 1:
        return ("capability_unaccounted_shape",
                "the Delete Record/Delete All Records capability accounts for exactly one 'With dialog' "
                f"Boolean parameter; this step carries {len(params)} parameter(s) — a shape the emitter "
                "does not consume")
    p = params[0]
    if p.get("type") != "Boolean" or (set(p.attrib) - {"type"}):
        return ("capability_unaccounted_shape",
                f"the sole parameter is not a bare type=\"Boolean\" (got type={p.get('type')!r}, "
                f"attrs {sorted(p.attrib)}) — outside the ids-9/10 grammar")
    bools = p.findall("Boolean")
    if len(bools) != 1 or bools[0].get("type") != "With dialog":
        return ("capability_unaccounted_shape",
                "the Boolean parameter is not a single type=\"With dialog\" flag — outside the ids-9/10 "
                "grammar")
    b = bools[0]
    if (set(b.attrib) - {"type", "value", "id"}) or len(b):
        return ("capability_unaccounted_shape",
                f"the 'With dialog' Boolean carries child element(s)/attribute(s) ({sorted(b.attrib)}) the "
                "emitter does not consume")
    val = b.get("value")
    if val not in _NOINTERACT_DIALOG_VALUES:
        return ("capability_unaccounted_shape",
                f"'With dialog' value {val!r} is outside the observed FileMaker vocabulary "
                f"{sorted(_NOINTERACT_DIALOG_VALUES)} — not passed through unchecked")
    return None


# ── packet 1103 — completing the _emit_noninteract family: 26 (Omit Multiple) + 117 (Execute SQL) ──
#
# The two ids the packet-1091/1092 simple-family migration deliberately EXCLUDED, now given DEDICATED
# predicates (NOT by widening _cap_noninteract_dialog, which stays frozen for the seven simple ids — their
# grammar is not one Boolean). Each accounts for the COMPLETE demonstrated grammar its emitter consumes or
# deliberately projects away; anything else refuses BY NAME rather than being silently ignored by the
# shared _emit_noninteract helper. Neither predicate reads _VERIFIED_SIGS — permission is IMPLEMENTED
# CAPABILITY (packet 1088's split), so fixture removal cannot revoke a grammar and fixture addition cannot
# grant a new option value.
#
# Evidence bound (recorded 2026-07-16 — a BOUNDED lookup, NOT a capture campaign): every id-26 and id-117
# occurrence across all committed masters AND the fms-dev stored script-sample clips was inspected. The
# committed pairs remain the sole evidence authority:
#   26 — two shapes: (With dialog=True, no calc) → NoInteract False, no clip Calculation; (With dialog=False,
#        POPULATED count calc `$ReportRows.Count`) → NoInteract True + flattened <Calculation>. Both dialog
#        polarities AND both calc-presence states are proven, but CONFOUNDED across the two captures — so the
#        two cross-combinations ((False, no calc) and (True, populated calc)) are capability-complete and
#        emit EXPERIMENTALLY. A present-but-EMPTY count calc is a DISTINCT unobserved shape and refuses (its
#        clip form is unknown), never conflated with "calc absent".
#   117 — one shape: (With dialog=False, Create folders=False) → NoInteract True; the clip carries NO
#        CreateDirectories or any other representation of the Create-folders Boolean. `Create folders` is NOT
#        universally target-absent (ids 36/132/190/244/245/246 DO emit <CreateDirectories> from it), so
#        id-117 `Create folders=True`'s target form is UNKNOWN — no matched pair proves it. Capability
#        accepts Create folders=False ONLY; True refuses by a named evidence-bounded hazard
#        (`execute_sql_create_folders_true_unmapped`), never guessed as absent. With dialog=True with the
#        evidenced Create folders=False emits experimentally through the proven NoInteract polarity.
_EXECUTE_SQL_CREATE_FOLDERS_CAPABLE = frozenset({"False"})   # the ONLY evidenced id-117 Create-folders value


def _with_dialog_boolean_reason(p, family: str) -> "tuple[str, str] | None":
    """None if `p` is a bare `<Parameter type="Boolean">` holding exactly one `<Boolean type="With dialog">`
    with a bounded True/False value; else a (code, detail) naming the violation. Shared by the id-26/117
    predicates ONLY — _cap_noninteract_dialog stays frozen for the simple family (packet 1103)."""
    if p.get("type") != "Boolean" or (set(p.attrib) - {"type"}):
        return ("capability_unaccounted_shape",
                f"{family}: the 'With dialog' parameter is not a bare type=\"Boolean\" "
                f"(attrs {sorted(p.attrib)})")
    bs = p.findall("Boolean")
    if len(bs) != 1 or bs[0].get("type") != "With dialog":
        return ("capability_unaccounted_shape",
                f"{family}: expected exactly one Boolean type=\"With dialog\" flag")
    b = bs[0]
    if (set(b.attrib) - {"type", "value", "id"}) or len(b):
        return ("capability_unaccounted_shape",
                f"{family}: the 'With dialog' Boolean carries unexpected attribute(s)/child(ren) "
                f"({sorted(b.attrib)})")
    if b.get("value") not in _NOINTERACT_DIALOG_VALUES:
        return ("capability_unaccounted_shape",
                f"{family}: 'With dialog' value {b.get('value')!r} is outside the observed FileMaker "
                f"vocabulary {sorted(_NOINTERACT_DIALOG_VALUES)}")
    return None


def _count_calc_reason(p) -> "tuple[str, str] | None":
    """None if `p` is the exact observed Omit-Multiple count-Calculation parameter — a bare
    `<Parameter type="Calculation">` wrapping ONE nested `<Calculation>` with exactly one non-empty `<Text>`
    that `_inner_text` consumes; else (code, detail). A present-but-EMPTY calc is a DISTINCT unobserved shape
    and refuses (packet 1103) — 'Calculation present-but-empty' is never conflated with 'Calculation absent'
    (the separate capable no-calc shape)."""
    if set(p.attrib) - {"type"}:
        return ("capability_unaccounted_shape",
                f"Omit Multiple: the count Calculation parameter carries unexpected attribute(s) "
                f"({sorted(p.attrib)})")
    if len(p.findall("Calculation")) != 1:
        return ("capability_unaccounted_shape",
                "Omit Multiple: expected exactly one <Calculation> wrapper in the count parameter")
    texts = p.findall(".//Text")
    if len(texts) != 1:
        return ("capability_unaccounted_shape",
                f"Omit Multiple: expected exactly one <Text> in the count Calculation, got {len(texts)} "
                "(_inner_text's first-match .find would silently pick one)")
    if (texts[0].text or "").strip() == "":
        return ("omit_multiple_empty_count_calc",
                "Omit Multiple: the count Calculation is present but its text is empty — an UNOBSERVED "
                "shape (only a POPULATED count calc is evidenced). A present-but-empty Calculation is not "
                "the same as an absent one; refused rather than guessing FileMaker's empty-calc clip form")
    return None


def _cap_omit_multiple(step) -> "tuple[str, str] | None":
    """id 26 (Omit Multiple Records) capability. Capable iff EXACTLY one bare `With dialog` Boolean
    parameter (bounded True/False) plus ZERO or ONE count Calculation parameter with the exact observed
    nested wrapper + non-empty text — and nothing else. Both dialog polarities and both calc-presence states
    are proven (confounded across two captures), so their cross-combinations emit experimentally; every other
    structure the helper would silently ignore refuses BY NAME (packet 1103)."""
    pv = step.find("ParameterValues")
    if pv is not None and any(c.tag != "Parameter" for c in pv):
        return ("capability_unaccounted_shape",
                "Omit Multiple: a non-Parameter child under <ParameterValues> the grammar does not model")
    params = pv.findall("Parameter") if pv is not None else []
    bools = [p for p in params if p.get("type") == "Boolean"]
    calcs = [p for p in params if p.get("type") == "Calculation"]
    if len(bools) != 1:
        return ("capability_unaccounted_shape",
                f"Omit Multiple accounts for exactly one 'With dialog' Boolean parameter; got {len(bools)} "
                "(no duplicate Boolean is picked by first-match .find)")
    if len(calcs) > 1:
        return ("capability_unaccounted_shape",
                f"Omit Multiple accounts for at most one count Calculation parameter; got {len(calcs)}")
    if len(params) != len(bools) + len(calcs):
        return ("capability_unaccounted_shape",
                "Omit Multiple accounts only for one Boolean + an optional count Calculation; an unrelated "
                "parameter is present and would be silently ignored")
    b_reason = _with_dialog_boolean_reason(bools[0], "Omit Multiple")
    if b_reason is not None:
        return b_reason
    if calcs:
        return _count_calc_reason(calcs[0])
    return None


def _cap_execute_sql(step) -> "tuple[str, str] | None":
    """id 117 (Execute SQL) capability. Capable iff EXACTLY two bare Boolean parameters in the observed
    order — [0] a `With dialog` Boolean (bounded True/False), [1] a `Create folders` Boolean whose value is
    the ONLY evidenced one, False. Both dialog polarities are capability-complete via the proven NoInteract
    mapping (True → experimental). The Create-folders Boolean is deliberately projected away (target-absent)
    for False; `Create folders=True` has NO matched pair and is NOT universally target-absent, so it refuses
    by a named evidence-bounded hazard rather than being guessed (packet 1103)."""
    pv = step.find("ParameterValues")
    if pv is not None and any(c.tag != "Parameter" for c in pv):
        return ("capability_unaccounted_shape",
                "Execute SQL: a non-Parameter child under <ParameterValues> the grammar does not model")
    params = pv.findall("Parameter") if pv is not None else []
    if len(params) != 2:
        return ("capability_unaccounted_shape",
                "Execute SQL accounts for exactly two Boolean parameters ('With dialog' then "
                f"'Create folders'); got {len(params)}")
    d_reason = _with_dialog_boolean_reason(params[0], "Execute SQL")
    if d_reason is not None:
        return d_reason
    cf = params[1]
    if cf.get("type") != "Boolean" or (set(cf.attrib) - {"type"}):
        return ("capability_unaccounted_shape",
                f"Execute SQL: the second parameter is not a bare type=\"Boolean\" (attrs {sorted(cf.attrib)})")
    cbs = cf.findall("Boolean")
    if len(cbs) != 1 or cbs[0].get("type") != "Create folders":
        return ("capability_unaccounted_shape",
                "Execute SQL: the second Boolean is not a single type=\"Create folders\" flag (a swapped, "
                "missing, or duplicated flag lands here)")
    cb = cbs[0]
    if (set(cb.attrib) - {"type", "value", "id"}) or len(cb):
        return ("capability_unaccounted_shape",
                f"Execute SQL: the 'Create folders' Boolean carries unexpected attribute(s)/child(ren) "
                f"({sorted(cb.attrib)})")
    cfv = cb.get("value")
    if cfv == "True":
        return ("execute_sql_create_folders_true_unmapped",
                "Execute SQL 'Create folders=True' has no matched FileMaker pair proving its clip target "
                "form. 'Create folders' is NOT universally target-absent (ids 36/132/190/244/245/246 emit "
                "<CreateDirectories> from it), so id-117 True is refused as an evidence-bounded mapping "
                "hazard rather than guessed as target-absent; only the evidenced False projection emits")
    if cfv not in _EXECUTE_SQL_CREATE_FOLDERS_CAPABLE:
        return ("capability_unaccounted_shape",
                f"Execute SQL: 'Create folders' value {cfv!r} is outside the observed FileMaker Boolean "
                "vocabulary (False emits; True refuses by name; anything else is unaccounted)")
    return None


# ── packet 1104 — direct-Boolean base-shape family: 11 ids whose emitted option is one bounded Boolean ──
#
# The SelectAll family (11/12/13/14/18/46/47/49/60 — Insert-from-Index/Last-Visited/Current-Date/Current-
# Time, Check Selection, Cut/Copy/Clear, Insert Current User Name), all emitting one `Select` Boolean →
# <SelectAll @state>; Set Error Logging (200, `enabled` → <Option @state>); and Revert Transaction (207,
# ordered `Condition` + `Error Code`, only Condition → <Option @state>). Each option is driven DIRECTLY by a
# bounded Boolean the shared emitter reads, so both {True, False} values are capability-complete and the
# uncaptured opposite emits experimentally — but a malformed source that `_step_signature` flattens into a
# verified-looking token (an extra attr/child/param) must refuse, which is why capability runs BEFORE
# evidence for every registered id (see step_generation_assessment). id 33 Open File was EXCLUDED here (it
# shares `_emit_option_bare` but adds a DataSourceReference the 1104 rules do not model); it was migrated
# LATER by packet 1108's `_cap_open_file`, which validates the current-file DataSourceReference and refuses an
# external target — so sharing `_emit_option_bare` was never sufficient grounds to register it here.
_DIRECT_BOOLEAN_VALUES = frozenset({"True", "False"})   # bounded FileMaker Boolean vocabulary for these ids


def _bare_boolean_reason(p, btype: str, family: str, *, values) -> "tuple[str, str] | None":
    """(code, detail) or None — one Parameter must be a bare `<Parameter type="Boolean">` holding exactly one
    `<Boolean type=btype>` (FileMaker's internal `@id` allowed as projection metadata; no other attr, no
    child, no loose text on either node). When `values` is not None the Boolean's value must be in it. Shared
    by the packet-1104 direct-Boolean base-shape rules; refuses a malformed tree even when `_step_signature`
    would flatten it into a verified-looking token."""
    if p.get("type") != "Boolean" or (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape",
                f"{family}: expected a bare type=\"Boolean\" parameter for '{btype}' "
                f"(attrs {sorted(p.attrib)})")
    if len(list(p)) != 1:
        return ("capability_unaccounted_shape",
                f"{family}: the '{btype}' parameter must hold exactly one Boolean child, no extra structure")
    bs = p.findall("Boolean")
    if len(bs) != 1 or bs[0].get("type") != btype:
        return ("capability_unaccounted_shape",
                f"{family}: the parameter is not a single type=\"{btype}\" Boolean")
    b = bs[0]
    if (set(b.attrib) - {"type", "value", "id"}) or len(b) or (b.text or "").strip():
        return ("capability_unaccounted_shape",
                f"{family}: the '{btype}' Boolean carries unexpected attribute(s)/child(ren)/text "
                f"({sorted(b.attrib)})")
    if values is not None and b.get("value") not in values:
        return ("capability_unaccounted_shape",
                f"{family}: '{btype}' value {b.get('value')!r} is outside the observed FileMaker vocabulary "
                f"{sorted(values)}")
    return None


def _single_option_boolean_reason(step, btype: str, family: str) -> "tuple[str, str] | None":
    """(code, detail) or None — the one-bare-Boolean base-shape grammar: exactly one `<ParameterValues>`
    whose only child is one bare `<Parameter type="Boolean">` of type `btype`, value bounded to
    `_DIRECT_BOOLEAN_VALUES`. Shared by the SelectAll family and Set Error Logging."""
    pv = step.find("ParameterValues")
    if pv is not None and any(c.tag != "Parameter" for c in pv):
        return ("capability_unaccounted_shape",
                f"{family}: a non-Parameter child under <ParameterValues> the grammar does not model")
    params = pv.findall("Parameter") if pv is not None else []
    if len(params) != 1:
        return ("capability_unaccounted_shape",
                f"{family} accounts for exactly one bare '{btype}' Boolean parameter; got {len(params)}")
    return _bare_boolean_reason(params[0], btype, family, values=_DIRECT_BOOLEAN_VALUES)


def _cap_select_all_boolean(step) -> "tuple[str, str] | None":
    """ids 11/12/13/14/18/46/47/49/60 — one bare `Select` Boolean → `<SelectAll @state>` (packet 1104). Both
    values map directly; the captured `True` side is verified, `False` emits experimentally."""
    return _single_option_boolean_reason(step, "Select", "SelectAll base shape")


def _cap_set_error_logging(step) -> "tuple[str, str] | None":
    """id 200 (Set Error Logging) — one bare `enabled` Boolean → `<Option @state>` (packet 1104). Captured
    `False` is verified; `True` emits experimentally by the same direct mapping."""
    return _single_option_boolean_reason(step, "enabled", "Set Error Logging")


def _cap_revert_transaction(step) -> "tuple[str, str] | None":
    """id 207 (Revert Transaction) — EXACTLY two bare Boolean parameters in the observed order: [0] a
    `Condition` Boolean (bounded True/False, the one `_emit_option_bare` reads first and maps directly to
    `<Option @state>`), [1] an `Error Code` Boolean. The evidenced `Error Code=False` is target-absent (the
    clip carries only `<Option>`); `Error Code=True` has NO matched pair proving its target form and the
    emitter drops it, so it refuses by a named evidence-bounded hazard rather than silently omitting a value
    the clip may need (False omission does not prove True omission). Condition=True emits experimentally
    (packet 1104). Capability validates BOTH Booleans before emit — never a generic first-Boolean shortcut."""
    pv = step.find("ParameterValues")
    if pv is not None and any(c.tag != "Parameter" for c in pv):
        return ("capability_unaccounted_shape",
                "Revert Transaction: a non-Parameter child under <ParameterValues> the grammar does not model")
    params = pv.findall("Parameter") if pv is not None else []
    if len(params) != 2:
        return ("capability_unaccounted_shape",
                "Revert Transaction accounts for exactly two Boolean parameters ('Condition' then "
                f"'Error Code'); got {len(params)}")
    cond = _bare_boolean_reason(params[0], "Condition", "Revert Transaction", values=_DIRECT_BOOLEAN_VALUES)
    if cond is not None:
        return cond
    ec = _bare_boolean_reason(params[1], "Error Code", "Revert Transaction", values=None)
    if ec is not None:
        return ec
    ecv = params[1].find("Boolean").get("value")
    if ecv == "True":
        return ("revert_transaction_error_code_true_unmapped",
                "Revert Transaction 'Error Code=True' has no matched FileMaker pair proving its clip target "
                "form and the current emitter drops it (only the target-absent False projection is evidenced),"
                " so it is refused as an evidence-bounded mapping hazard rather than silently omitting a value"
                " the clip may need")
    if ecv != "False":
        return ("capability_unaccounted_shape",
                f"Revert Transaction: 'Error Code' value {ecv!r} is outside the observed FileMaker Boolean "
                "vocabulary (False is target-absent; True refuses by name; anything else is unaccounted)")
    return None


# ── packet 1105 — the base-bare + toggle families: the 65 `_emit_bare` ids plus id 86 ──
#
# `_emit_bare` (and `_emit_set_error_capture` for id 86) produce only the Step shell + <DisableStepCollapsed>
# — no target-driving parameter. Three bounded base grammars are migrated (this is BASE-shape capability,
# NOT completeness for every UI configuration of these step types — a configured calc/field/selector/etc.
# still refuses):
#   A. CLEAN base-bare (54 ids) — no parameters, or the optional Collapsed Boolean grammar.
#   B. RAW SaveAsXML projection (6 ids: 7/23/70/73 SourceUUID form, 237/247 OwnerID form) — the clean grammar
#      OR the exact ordered provenance bundle [UUID, SourceUUID|OwnerID, Options=0, DDRREF] (+ Step hash/index
#      attrs) that the emitter deliberately DROPS (target-absent). Mutating provenance values does not change
#      output; a malformed bundle refuses. Not a wildcard UUID/DDRREF stripper.
#   C. FLAVOR-SENSITIVE toggle (6 ids: 85/86/94/115/168/223) — exactly one UNTYPED Boolean (bounded
#      {True,False}). XMSC drops the state (bare); XMSS prepends <Set state=value> (packet 1068 / _XMSS_SET_
#      STATE). No Collapsed recombination — the shared _first_bool_value (which sources the XMSS <Set>) cannot
#      disambiguate a Collapsed Boolean from the toggle Boolean, so that combination is refused as unobserved.
#
# The optional Collapsed value is NOT added to the signature: within this wave no committed shape carries
# Collapsed (every verified shape is `()` or the untyped toggle Boolean), so absent (verified) vs present
# (experimental) is already distinguished by `()` vs `("Boolean:Collapsed",)`, and present-True/False share
# one experimental token — no verified collision to break, so the pre-1105 Collapsed token stays byte-
# identical (ids 68/125 carry it and are out of scope). Capability runs BEFORE evidence (packet 1104), so a
# malformed tree whose `_step_signature` collides with `()` still refuses.
_CLEAN_BARE_IDS = frozenset({
    4, 5, 8, 19, 20, 21, 24, 25, 27, 32, 38, 44, 50, 79, 82, 88, 90, 93, 98, 101, 102, 105, 106, 107, 108,
    109, 112, 113, 114, 116, 118, 129, 133, 140, 149, 151, 156, 157, 165, 169, 172, 179, 183,
    199, 206, 208})   # packet 1126 removed 188/189/191/194/195/196 → the Data File family's own rules
_RAW_SOURCE_UUID_IDS = frozenset({7, 23, 70, 73})
_RAW_OWNER_ID_IDS = frozenset({237, 247})
_TOGGLE_IDS = frozenset({85, 86, 94, 115, 168, 223})

# The Step-level attributes the clip does NOT carry — target-absent SaveAsXML step-envelope provenance,
# dropped by every clip builder (which constructs <Step> from scratch with only enable/id/name). `hash`/
# `index` are the raw envelope (packet 1122). `breakpoint` is debugger state (packet 1125): a
# breakpoint="True" attribute a developer's set breakpoint leaves on a step; it never appears in a copied
# clip (0 occurrences across every committed fixture) and the emitter drops it, so a breakpoint step emits
# BYTE-IDENTICAL to its non-breakpoint shape. `enable`/`breakpoint` are bounded to the FileMaker Boolean
# vocabulary when present; `id`/`name`/`hash`/`index` values are not shape.
_TARGET_ABSENT_STEP_ATTRS = frozenset({"id", "name", "enable", "hash", "index", "breakpoint"})
_BOUNDED_STEP_BOOL_ATTRS = ("enable", "breakpoint")


def _step_shell_bool_reason(step, fam):
    """Bounded-Boolean check for the target-absent `enable`/`breakpoint` Step attrs (present → must be a
    FileMaker Boolean). Shared by the two shell front-ends so a malformed value fails loud, not silent."""
    for attr in _BOUNDED_STEP_BOOL_ATTRS:
        v = step.get(attr)
        if v is not None and v not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape",
                    f"{fam}: {attr}={v!r} is outside the FileMaker Boolean vocabulary")
    return None


def _clean_shell_reason(step, *, extra_attrs=frozenset()) -> "tuple[str, str] | None":
    """The clean base-shape Step shell: attrs ⊆ {id, name, enable, hash, index, breakpoint} (+ extra_attrs),
    enable/breakpoint bounded to a FileMaker Boolean, no loose top-level text. `name` is copied content (any
    value); `id`/`hash`/`index`/`breakpoint`/provenance values are NOT shape. packet 1122 — `hash`/`index`
    are the real SaveAsXML step envelope's provenance attrs (target-absent, exactly as `_step_body` already
    tolerates); packet 1125 adds `breakpoint` (debugger state, likewise target-absent — see
    `_TARGET_ABSENT_STEP_ATTRS`), so the shell accepts them universally rather than only via the
    raw-projection path."""
    allowed = _TARGET_ABSENT_STEP_ATTRS | extra_attrs
    unknown = set(step.attrib) - allowed
    if unknown:
        return ("capability_unaccounted_shape",
                f"base shape: unexpected Step attribute(s) {sorted(unknown)}")
    r = _step_shell_bool_reason(step, "base shape")
    if r is not None:
        return r
    if (step.text or "").strip():
        return ("capability_unaccounted_shape", "base shape: loose direct text under <Step>")
    return None


def _provenance_prefix_reason(step) -> "tuple[str, str] | None":
    """packet 1122 — validate the FileMaker SaveAsXML raw step envelope as TARGET-ABSENT provenance, if any is
    present. The clipboard (FMObjectList) format re-encodes a step's options as explicit child elements
    (`<DisableStepCollapsed>`, …) and carries no raw `<Options>` bitmask, `<UUID>`, `<SourceUUID>/<OwnerID>`,
    or `<DDRREF>`, so every base/toggle/window emitter DROPS this bundle — it changes no target byte. A step
    with NO provenance children (the normalized master dialect) passes unchanged.

    When present, accept EXACTLY the ordered leading bundle `[UUID, <SourceUUID|OwnerID>, Options, DDRREF]`,
    each at its legal grammar: `<UUID>` a plain text node; the second slot EITHER `<SourceUUID>` (non-empty
    text) OR `<OwnerID>` (empty) — both target-absent, same clip; `<Options>` a plain SIGNED-INTEGER text node
    of ANY value (the raw step bitmask is target-absent — the clip never carries it); `<DDRREF kind="StepText">`
    (attrs ⊆ {kind, hash}). A reordered / duplicated / partial bundle, a non-integer Options, an attr'd/childed
    UUID/Options, or a wrong DDRREF kind refuses by a stable named reason (never a wildcard strip). This does
    NOT loosen any target-driving check; callers still validate the remaining `<ParameterValues>` structure."""
    prov = [c for c in step if c.tag in _PROVENANCE_TAGS]
    if not prov:
        return None
    tags = [c.tag for c in prov]
    if tags not in (["UUID", "SourceUUID", "Options", "DDRREF"], ["UUID", "OwnerID", "Options", "DDRREF"]):
        return ("capability_unaccounted_shape",
                f"raw envelope: provenance children {tags} are not the exact ordered bundle "
                "['UUID', <'SourceUUID'|'OwnerID'>, 'Options', 'DDRREF'] (no reorder/duplicate/partial/wrong slot)")
    uuid_el, slot_el, opts_el, ddrref_el = prov
    if set(uuid_el.attrib) or len(uuid_el):
        return ("capability_unaccounted_shape", "raw envelope: <UUID> must be a plain text node")
    if slot_el.tag == "SourceUUID":
        if set(slot_el.attrib) or len(slot_el) or not (slot_el.text or "").strip():
            return ("capability_unaccounted_shape", "raw envelope: <SourceUUID> must be a non-empty text node")
    else:                                            # OwnerID
        if set(slot_el.attrib) or len(slot_el) or (slot_el.text or "").strip():
            return ("capability_unaccounted_shape", "raw envelope: <OwnerID> must be empty")
    if set(opts_el.attrib) or len(opts_el):
        return ("capability_unaccounted_shape", "raw envelope: <Options> must be a plain text node")
    try:
        int((opts_el.text or "").strip())
    except ValueError:
        return ("capability_unaccounted_shape",
                f"raw envelope: <Options>{(opts_el.text or '').strip()!r}</Options> is not an integer step bitmask")
    if (set(ddrref_el.attrib) - {"kind", "hash"}) or len(ddrref_el):
        return ("capability_unaccounted_shape",
                f"raw envelope: <DDRREF> unexpected attrs/children ({sorted(ddrref_el.attrib)})")
    if ddrref_el.get("kind") != "StepText":
        return ("capability_unaccounted_shape",
                f"raw envelope: <DDRREF kind={ddrref_el.get('kind')!r}> is not the observed 'StepText'")
    return None


def _collapsed_pv_reason(pv) -> "tuple[str, str] | None":
    """A base-shape <ParameterValues>: EMPTY, or exactly one bare Boolean Parameter holding one `Collapsed`
    Boolean bounded {True,False}. Returns (code, detail) or None. `_collapsed_state` consumes exactly this."""
    if any(c.tag != "Parameter" for c in pv):
        return ("capability_unaccounted_shape",
                "base shape: a non-Parameter child under <ParameterValues> the grammar does not model")
    params = pv.findall("Parameter")
    if not params:
        return None                                  # empty ParameterValues — same target as absent
    if len(params) != 1:
        return ("capability_unaccounted_shape",
                f"base shape accounts for at most one Collapsed Boolean parameter; got {len(params)}")
    return _bare_boolean_reason(params[0], "Collapsed", "base shape", values=_DIRECT_BOOLEAN_VALUES)


def _cap_clean_bare(step) -> "tuple[str, str] | None":
    """Rule A (packet 1105) — the 54 clean base-bare ids. Capable iff a clean shell with NO top-level child
    except at most one <ParameterValues> that is empty or the optional Collapsed grammar. Any configured
    parameter or extra child refuses (sharing `_emit_bare` does not make a configured variant safe)."""
    shell = _clean_shell_reason(step)
    if shell is not None:
        return shell
    prov = _provenance_prefix_reason(step)            # packet 1122 — the raw SaveAsXML envelope, target-absent
    if prov is not None:
        return prov
    non_pv = sorted({c.tag for c in step if c.tag != "ParameterValues" and c.tag not in _PROVENANCE_TAGS})
    if non_pv:
        return ("capability_unaccounted_shape",
                f"clean base shape: unexpected top-level child element(s) {non_pv} — a configured variant the "
                "bare emitter would silently ignore")
    pvs = step.findall("ParameterValues")
    if len(pvs) > 1:
        return ("capability_unaccounted_shape",
                f"clean base shape: {len(pvs)} <ParameterValues> blocks (at most one)")
    return _collapsed_pv_reason(pvs[0]) if pvs else None


def _cap_toggle(step) -> "tuple[str, str] | None":
    """Rule C (packet 1105) — ids 85/86/94/115/168/223. Capable iff a clean shell + exactly one
    <ParameterValues> holding exactly one bare Parameter with one UNTYPED Boolean bounded {True,False}. The
    XMSS <Set state> reads that value; XMSC drops it. No Collapsed recombination (disambiguation with the
    toggle Boolean is not safe under the shared _first_bool_value), no extra structure."""
    shell = _clean_shell_reason(step)
    if shell is not None:
        return shell
    prov = _provenance_prefix_reason(step)            # packet 1122 — the raw SaveAsXML envelope, target-absent
    if prov is not None:
        return prov
    non_pv = sorted({c.tag for c in step if c.tag != "ParameterValues" and c.tag not in _PROVENANCE_TAGS})
    if non_pv:
        return ("capability_unaccounted_shape",
                f"toggle base shape: unexpected top-level child element(s) {non_pv}")
    pvs = step.findall("ParameterValues")
    if len(pvs) != 1:
        return ("capability_unaccounted_shape",
                f"toggle base shape accounts for exactly one <ParameterValues>; got {len(pvs)}")
    if any(c.tag != "Parameter" for c in pvs[0]):
        return ("capability_unaccounted_shape",
                "toggle base shape: a non-Parameter child under <ParameterValues>")
    params = pvs[0].findall("Parameter")
    if len(params) != 1:
        return ("capability_unaccounted_shape",
                f"toggle base shape accounts for exactly one toggle Boolean parameter; got {len(params)}")
    p = params[0]
    if p.get("type") != "Boolean" or (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape",
                f"toggle base shape: the parameter is not a bare type=\"Boolean\" (attrs {sorted(p.attrib)})")
    if len(list(p)) != 1 or len(p.findall("Boolean")) != 1:
        return ("capability_unaccounted_shape",
                "toggle base shape: the parameter must hold exactly one Boolean child")
    b = p.find("Boolean")
    if b.get("type") is not None:
        return ("capability_unaccounted_shape",
                f"toggle base shape: the flavor-toggle Boolean must be UNTYPED (got semantic "
                f"type={b.get('type')!r} — not this grammar, and it could collide with the Collapsed flag)")
    if (set(b.attrib) - {"value", "id"}) or len(b) or (b.text or "").strip():
        return ("capability_unaccounted_shape",
                f"toggle base shape: the toggle Boolean carries unexpected attribute(s)/child(ren)/text "
                f"({sorted(b.attrib)})")
    if b.get("value") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape",
                f"toggle base shape: value {b.get('value')!r} is outside the FileMaker Boolean vocabulary")
    return None


def _cap_raw_source_uuid(step) -> "tuple[str, str] | None":
    """Rule B (packet 1105; generalized 1122) — the SaveAsXML raw-projection ids 7/23/70/73. These are bare
    `_emit_bare` ids that DROP the whole provenance envelope, so they are exactly `_cap_clean_bare` cases: a
    clean shell + the target-absent raw envelope (`_provenance_prefix_reason`) + optional empty/Collapsed
    ParameterValues. Packet 1122 retired the SourceUUID-only / Options=0 pin: the real FM2026 app dialect uses
    the `<OwnerID>` slot with a non-zero `<Options>` bitmask, both target-absent (same bare clip), so a captured
    `SourceUUID` shape and the live `OwnerID` shape share this ONE rule and emit the same target."""
    return _cap_clean_bare(step)


def _cap_raw_owner_id(step) -> "tuple[str, str] | None":
    """Rule B / raw-projection ids 237/247 — identical bare grammar as `_cap_raw_source_uuid` (packet 1122
    unified the SourceUUID/OwnerID slots; both are target-absent)."""
    return _cap_clean_bare(step)


# ── packet 1106 — the selector-enum + embedded-insert families ──
#
# A. SELECTOR-ENUM (13 ids via `_selector_emitter`): each maps ONE source selector value → one target
#    `<TAG value=…>`, dropping the numeric source code and (for `action`/`Options`) the container wrapper.
#    Permission is an EXPLICIT per-id source→target map declared here (identity entries spelled out just like
#    remaps), independent of `_VERIFIED_SIGS`; an unmapped/case-variant value REFUSES by name (never the
#    factory's raw pass-through). The maps are bounded to MATCHED (DDR, clip) evidence — the committed pairs.
#    Clip-only master values seen on a shared target tag (e.g. ShowHide `Hide`, ContentType `File`/`Calculation`,
#    Action `Reset`) are NOT matched to a DDR source, so they are deliberately NOT in any map (a string hit is
#    not a pair); a DDR step carrying them refuses until a real pair is captured. The optional `Collapsed`
#    Boolean is accepted (its value drives `<DisableStepCollapsed>`, distinguished by a selector-scoped
#    signature token — see `_step_signature`). This is per-id enum vocabulary, NOT completeness for every
#    FileMaker mode of these step types.
#
# B. EMBEDDED-INSERT (56/158/159 via `_emit_insert_embedded`): one `Store only a reference` Boolean. `False`
#    is the proven Embedded branch. `True` changes storage topology (clip `<UniversalPathList type="Reference">`,
#    observed only on OTHER ids) — there is NO matched pair for 56/158/159 and the emitter hardcodes Embedded,
#    so True refuses by `insert_reference_storage_unimplemented` (the whole script is withheld), never a silent
#    Embedded clip.
_SELECTOR_SPECS = {
    #   id : {container, values: {source → target}}   — target MUST equal what _selector_emitter emits
    30:  {"container": "List",    "values": {"Cycle": "Cycle"}},
    45:  {"container": "List",    "values": {"Undo": "Undo"}},
    81:  {"container": "List",    "values": {"Home": "Home"}},
    84:  {"container": "List",    "values": {"On": "True"}},                          # non-identity remap
    92:  {"container": "List",    "values": {"Show": "Show"}},
    120: {"container": "List",    "values": {"Tile Horizontally": "TileHorizontally"}},  # non-identity remap
    155: {"container": "List",    "values": {"Replace": "FindMatchingReplace"}},      # non-identity remap
    174: {"container": "List",    "values": {"On": "Show"}},                          # non-identity remap
    178: {"container": "List",    "values": {"Stopped": "Stopped"}},
    209: {"container": "List",    "values": {"US English": "US English"}},
    67:  {"container": "Options", "values": {"Text": "Text"}},                        # <Options @type> selector
    187: {"container": "action",  "values": {"Queue": "Queue"}},                      # <action><List> selector
    201: {"container": "action",  "values": {"Read": "Read"}},
}
_SELECTOR_ID_STRS = frozenset(str(sid) for sid in _SELECTOR_SPECS)   # for _step_signature's Collapsed scope
_EMBEDDED_INSERT_IDS = frozenset({56, 158, 159})

# per-container: the Parameter @type, the selector NODE tag, the attr carrying the value, and the node's
# allowed attrs (the numeric `value` code on a List is source-only provenance, dropped by the emitter).
_SELECTOR_CONTAINERS = {
    "List":    {"param_type": "List",    "node": "List",    "value_attr": "name", "node_attrs": {"name", "value"}},
    "Options": {"param_type": "Options", "node": "Options", "value_attr": "type", "node_attrs": {"type"}},
    "action":  {"param_type": "action",  "node": "List",    "value_attr": "name", "node_attrs": {"name", "value"}},
}


def _cap_selector(step) -> "tuple[str, str] | None":
    """Rule A (packet 1106) — the 13 `_selector_emitter` ids. ONE shared predicate reading the per-id
    `_SELECTOR_SPECS` declaration. Capable iff a clean shell + exactly one <ParameterValues> holding exactly
    one selector Parameter of the id's container kind (its node's value in the id's explicit map) plus at most
    one optional Collapsed Boolean — nothing else. An unmapped/case-variant value refuses by name, never
    passed through; a wrong container, missing/duplicate/extra parameter, or malformed node refuses.

    packet 1128 — the real SaveAsXML dialect carries the target-absent step envelope
    `[UUID, <SourceUUID|OwnerID>, Options, DDRREF]` on a configured selector step (observed on id 81 Scroll
    Window in the business corpora). The emitter reads ONLY <ParameterValues>, so an enveloped selector step
    emits BYTE-IDENTICAL to its verified bare pair; the envelope is validated + dropped by
    `_provenance_prefix_reason` (a malformed/reordered bundle still refuses), never a wildcard strip."""
    sid = int(step.get("id"))                       # dispatch guarantees a registered selector id
    spec = _SELECTOR_SPECS[sid]
    cont = _SELECTOR_CONTAINERS[spec["container"]]
    fam = f"selector id {sid} ({spec['container']})"
    shell = _clean_shell_reason(step)
    if shell is not None:
        return shell
    prov = _provenance_prefix_reason(step)          # packet 1128 — tolerate the raw SaveAsXML envelope
    if prov is not None:                             # (target-absent provenance, exactly as the base/toggle/
        return prov                                  # window families already do — the emitter reads only
    non_pv = sorted({c.tag for c in step             # <ParameterValues>, so an enveloped selector step emits
                     if c.tag != "ParameterValues" and c.tag not in _PROVENANCE_TAGS})
    if non_pv:
        return ("capability_unaccounted_shape", f"{fam}: unexpected top-level child element(s) {non_pv}")
    pvs = step.findall("ParameterValues")
    if len(pvs) != 1:
        return ("capability_unaccounted_shape", f"{fam}: expected exactly one <ParameterValues>; got {len(pvs)}")
    if any(c.tag != "Parameter" for c in pvs[0]):
        return ("capability_unaccounted_shape", f"{fam}: a non-Parameter child under <ParameterValues>")
    params = pvs[0].findall("Parameter")
    selectors = [p for p in params if p.get("type") == cont["param_type"]]
    collapsed = [p for p in params if p.get("type") == "Boolean"]
    if len(selectors) != 1:
        return ("capability_unaccounted_shape",
                f"{fam}: expected exactly one type=\"{cont['param_type']}\" selector parameter; got "
                f"{len(selectors)}")
    if len(collapsed) > 1:
        return ("capability_unaccounted_shape", f"{fam}: at most one Collapsed parameter")
    if len(params) != len(selectors) + len(collapsed):
        return ("capability_unaccounted_shape",
                f"{fam}: an unexpected parameter is present (only the selector + an optional Collapsed)")
    sp = selectors[0]
    if (set(sp.attrib) - {"type"}) or (sp.text or "").strip():
        return ("capability_unaccounted_shape",
                f"{fam}: the selector parameter is not a bare type=\"{cont['param_type']}\"")
    nodes = sp.findall(cont["node"])
    if len(list(sp)) != 1 or len(nodes) != 1:
        return ("capability_unaccounted_shape",
                f"{fam}: the selector parameter must hold exactly one <{cont['node']}> node")
    node = nodes[0]
    if (set(node.attrib) - cont["node_attrs"]) or len(node) or (node.text or "").strip():
        return ("capability_unaccounted_shape",
                f"{fam}: the <{cont['node']}> carries unexpected attribute(s)/child(ren) ({sorted(node.attrib)})")
    val = node.get(cont["value_attr"])
    if val not in spec["values"]:
        return ("selector_unmapped_value",
                f"{fam}: source selector value {val!r} is not in this id's capability map "
                f"{sorted(spec['values'])} — an unmapped/case-variant selector value is refused by name, never "
                "passed through the factory unchanged (and never widened from a value observed on another id)")
    if collapsed:
        cr = _bare_boolean_reason(collapsed[0], "Collapsed", fam, values=_DIRECT_BOOLEAN_VALUES)
        if cr is not None:
            return cr
    return None


def _cap_insert_embedded(step) -> "tuple[str, str] | None":
    """Rule B (packet 1106) — ids 56/158/159. Clean shell + exactly one <ParameterValues> with exactly one
    bare `Store only a reference` Boolean (bounded {True,False}). `False` → Embedded (the proven branch).
    `True` changes the storage topology and has NO matched pair for these ids; the emitter hardcodes
    Embedded, so True refuses by a named hazard rather than emit a wrong Embedded clip."""
    shell = _clean_shell_reason(step)
    if shell is not None:
        return shell
    non_pv = sorted({c.tag for c in step if c.tag != "ParameterValues"})
    if non_pv:
        return ("capability_unaccounted_shape",
                f"Insert (embedded): unexpected top-level child element(s) {non_pv}")
    r = _single_option_boolean_reason(step, "Store only a reference", "Insert (embedded)")
    if r is not None:
        return r
    val = step.find(".//Parameter[@type='Boolean']/Boolean[@type='Store only a reference']").get("value")
    if val == "True":
        return ("insert_reference_storage_unimplemented",
                "Insert (embedded) 'Store only a reference=True' changes the storage topology to a reference "
                "(clip <UniversalPathList type=\"Reference\">), which for ids 56/158/159 has NO matched "
                "(DDR, clip) pair and which the emitter cannot produce (it hardcodes type=\"Embedded\" and "
                "consumes nothing about this Boolean); the whole script is withheld rather than emit a wrong "
                "Embedded clip — a bounded developer-feedback item, not a user capture task")
    return None                                     # False → the proven Embedded branch


# ── packet 1107 — the remaining simple option-bearing base emitters (14 ids) ──
#
# The base/simple option grammar of 14 already-emitting ids. Each emitter consumes only bounded Boolean /
# List / base-state grammar and emits NO user calculation, object reference, destination, credential,
# layout, or rich option subtree — so this migrates the BASE shape, NOT completeness for every UI
# configuration of these step types. A configured import order (35), an explicit non-current truncate
# table (182), or any richer configured form of the same id carries additional structure and REFUSES by
# name; sharing an id with a base shape does not make a configured form a base shape.
#
# Three shared source grammars + dedicated predicates where topology differs (no 14 copy-pasted rules, no
# permissive union):
#   • one-named-Boolean (41/55 Pause, 96 Replace UUIDs, 126 Find without indexes, 190 Create folders) —
#     `_single_option_boolean_reason` (the packet-1104 helper); the fixed target facts (LinkAvail=False,
#     Restore=False, ContentType/CreateDirectories) have NO DDR source and live in the emitter;
#   • clean parameterless / optional-Collapsed base (64 Send DDE, 127 Extend Found Set) — `_cap_clean_bare`;
#   • dedicated multi-parameter / selector predicates (29/166 Show/Hide, 31 Adjust Window, 35 Import base,
#     48 Paste, 97 Set Zoom, 182 Truncate Table) — each validating the exact parameter order/cardinality,
#     semantic Boolean types + bounded values, and (where a selector is present) the value against an
#     EXPLICIT per-id source→target map, before the emitter's first-match/`.rstrip`/`dict[...]` can flatten
#     or crash on it. Every value authority is a literal independent of `_VERIFIED_SIGS`; no value transfers
#     between ids merely because they share a target element.
#
# 29 (Show/Hide Toolbars) and 166 (Menubar) validate DISTINCT flag sets — 29 carries the extra
# `Include Edit Record Toolbar` Boolean, 166 does not — so the two ids cannot exchange grammar. Both consume
# the same `_SHOWHIDE_MODES` selector, legitimate because Hide AND Show are matched by a committed pair on
# BOTH ids (not a cross-id transfer). No new signature token: none of the 14 ids has a verified collision
# (the single-option/multi-param rules require the exact observed parameter set, so a Collapsed recombination
# is a distinct — refused — shape; 64/127 distinguish absent `()` vs `("Boolean:Collapsed",)` generically).
_SHOWHIDE_MODES = {"Hide": "Hide", "Show": "Show"}   # ShowHide selector (29 + 166): both matched on BOTH ids
_ZOOM_LEVELS = {"100%": "100"}                        # Set Zoom (97): the ONLY matched zoom source→target
_TRUNCATE_CURRENT_TABLE = frozenset({"<Current Table>"})   # Truncate Table (182): the only matched selector


def _selector_list_value(p, *, fam, allowed_attrs=frozenset({"name", "value"})):
    """(name, None) if `p` is a bare `<Parameter type="List">` holding exactly one `<List>` node with attrs
    ⊆ `allowed_attrs`, no children, no loose text; else (None, (code, detail)). The numeric `value` code is
    source-only provenance the emitter drops. Shared by the packet-1107 selector predicates."""
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return None, ("capability_unaccounted_shape", f"{fam}: the List parameter is not a bare type=\"List\"")
    nodes = p.findall("List")
    if len(list(p)) != 1 or len(nodes) != 1:
        return None, ("capability_unaccounted_shape", f"{fam}: the List parameter must hold exactly one <List> node")
    node = nodes[0]
    if (set(node.attrib) - allowed_attrs) or len(node) or (node.text or "").strip():
        return None, ("capability_unaccounted_shape",
                      f"{fam}: the <List> carries unexpected attribute(s)/child(ren) ({sorted(node.attrib)})")
    return node.get("name"), None


def _base_params(step, fam):
    """(params, None) if `step` is a clean shell whose ONLY top-level child is exactly one <ParameterValues>
    with all-<Parameter> children; else (None, (code, detail)). The shared front-end of the packet-1107
    multi-parameter predicates — rejects extra Step attrs, loose text, a missing/duplicate ParameterValues,
    or a non-Parameter child before any positional read."""
    shell = _clean_shell_reason(step)
    if shell is not None:
        return None, shell
    prov = _provenance_prefix_reason(step)            # packet 1122 — the raw SaveAsXML envelope, target-absent
    if prov is not None:
        return None, prov
    non_pv = sorted({c.tag for c in step if c.tag != "ParameterValues" and c.tag not in _PROVENANCE_TAGS})
    if non_pv:
        return None, ("capability_unaccounted_shape", f"{fam}: unexpected top-level child element(s) {non_pv}")
    pvs = step.findall("ParameterValues")
    if len(pvs) != 1:
        return None, ("capability_unaccounted_shape", f"{fam}: expected exactly one <ParameterValues>; got {len(pvs)}")
    if any(c.tag != "Parameter" for c in pvs[0]):
        return None, ("capability_unaccounted_shape", f"{fam}: a non-Parameter child under <ParameterValues>")
    return pvs[0].findall("Parameter"), None


def _cap_pause_boolean(step) -> "tuple[str, str] | None":
    """ids 41 (Enter Preview Mode) + 55 (Enter Browse Mode) — one bare `Pause` Boolean → `<Pause @state>`.
    Same semantic Boolean type AND identical structure, so ONE shared predicate (packet 1107). Captured
    Pause=False is verified; True emits experimentally by the same direct mapping."""
    return _single_option_boolean_reason(step, "Pause", "Pause-mode base shape")


def _cap_create_data_file(step) -> "tuple[str, str] | None":
    """id 190 (Create Data File) — one bare `Create folders` Boolean → `<CreateDirectories @state>` (packet
    1107). The emitter CONSUMES this Boolean directly (unlike Execute SQL id 117, which drops it), so BOTH
    values are capability-complete: captured True is verified, False emits experimentally."""
    return _single_option_boolean_reason(step, "Create folders", "Create Data File")


def _cap_save_addon(step) -> "tuple[str, str] | None":
    """id 96 (Save a Copy as Add-on Package) — one bare `Replace UUIDs` Boolean → `<LinkAvail @state>`
    (packet 1107). No absent-Boolean default: the observed shape carries the Boolean, so it is REQUIRED
    (exactly one), never inferred False from absence. Captured False verified; True experimental."""
    return _single_option_boolean_reason(step, "Replace UUIDs", "Save a Copy as Add-on Package")


def _cap_constrain_found(step) -> "tuple[str, str] | None":
    """id 126 (Constrain Found Set) — one bare `Find without indexes` Boolean → `<Option @state>`, plus the
    fixed target fact `<Restore state="False">` (no DDR source) (packet 1107). Captured False verified; True
    experimental."""
    return _single_option_boolean_reason(step, "Find without indexes", "Constrain Found Set")


def _cap_send_dde(step) -> "tuple[str, str] | None":
    """id 64 (Send DDE Execute) — the parameterless / optional-Collapsed base grammar that produces the FIXED
    `<ContentType value="File">`. The constant is a proven target fact for THIS base shape, NOT a general DDE
    content-type rule; it has no DDR source and lives in the emitter. The source grammar is the clean-base
    family's, so this delegates to `_cap_clean_bare` (packet 1107)."""
    return _cap_clean_bare(step)


def _cap_extend_found(step) -> "tuple[str, str] | None":
    """id 127 (Extend Found Set) — the parameterless / optional-Collapsed base grammar plus the fixed
    `<Restore state="False">` target fact (packet 1107). A configured find request/option carries extra
    structure and refuses via the clean-base grammar."""
    return _cap_clean_bare(step)


def _cap_adjust_window(step) -> "tuple[str, str] | None":
    """id 31 (Adjust Window) — exactly one bare `<Parameter type="List">` whose `<List name>` is a matched
    window mode in the independent `_ADJUST_WINDOW` authority (Maximize→Maximize, Resize to Fit→ResizeToFit).
    An unknown/case-variant window state refuses BEFORE the emitter's `_ADJUST_WINDOW[...]` lookup (packet
    1107). Both matched modes are captured → verified."""
    params, reason = _base_params(step, "Adjust Window")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "List":
        return ("capability_unaccounted_shape",
                "Adjust Window accounts for exactly one type=\"List\" window-mode parameter")
    val, reason = _selector_list_value(params[0], fam="Adjust Window")
    if reason is not None:
        return reason
    if val not in _ADJUST_WINDOW:
        return ("adjust_window_unmapped_mode",
                f"Adjust Window: window state {val!r} is not a matched mode in {sorted(_ADJUST_WINDOW)} — an "
                "unknown/case-variant state is refused before the emitter's dict lookup, never guessed")
    return None


def _cap_show_hide_toolbars(step) -> "tuple[str, str] | None":
    """id 29 (Show/Hide Toolbars) — EXACTLY three parameters in the observed order: [0] `Lock` Boolean,
    [1] `Include Edit Record Toolbar` Boolean (both bounded True/False → `<Lock>` / `<IncludeEditRecord
    Toolbar>`), [2] a `<List>` Show/Hide selector in `_SHOWHIDE_MODES`. The extra Include-Edit-Record-Toolbar
    flag is what distinguishes 29 from Menubar (166): the two ids cannot exchange grammar. An unknown
    Show/Hide mode, or a missing/duplicate/extra parameter, refuses (packet 1107)."""
    params, reason = _base_params(step, "Show/Hide Toolbars")
    if reason is not None:
        return reason
    if len(params) != 3:
        return ("capability_unaccounted_shape",
                f"Show/Hide Toolbars accounts for exactly three parameters (Lock, Include Edit Record "
                f"Toolbar, Show/Hide List); got {len(params)}")
    for p, bt in ((params[0], "Lock"), (params[1], "Include Edit Record Toolbar")):
        r = _bare_boolean_reason(p, bt, "Show/Hide Toolbars", values=_DIRECT_BOOLEAN_VALUES)
        if r is not None:
            return r
    if params[2].get("type") != "List":
        return ("capability_unaccounted_shape",
                "Show/Hide Toolbars: the third parameter is not the Show/Hide List selector")
    val, reason = _selector_list_value(params[2], fam="Show/Hide Toolbars")
    if reason is not None:
        return reason
    if val not in _SHOWHIDE_MODES:
        return ("showhide_unmapped_mode",
                f"Show/Hide Toolbars: mode {val!r} is not a matched Show/Hide value {sorted(_SHOWHIDE_MODES)} "
                "— an unknown/case-variant mode is refused, never passed through")
    return None


def _cap_show_hide_menubar(step) -> "tuple[str, str] | None":
    """id 166 (Show/Hide Menubar) — EXACTLY two parameters in the observed order: [0] a `<List>` Show/Hide
    selector in `_SHOWHIDE_MODES`, [1] a `Lock` Boolean (bounded True/False → `<Lock>`). NO Include-Edit-
    Record-Toolbar flag (that is 29's grammar) — the two ids cannot exchange grammar (packet 1107)."""
    params, reason = _base_params(step, "Show/Hide Menubar")
    if reason is not None:
        return reason
    if len(params) != 2:
        return ("capability_unaccounted_shape",
                f"Show/Hide Menubar accounts for exactly two parameters (Show/Hide List, Lock); got {len(params)}")
    if params[0].get("type") != "List":
        return ("capability_unaccounted_shape",
                "Show/Hide Menubar: the first parameter is not the Show/Hide List selector")
    val, reason = _selector_list_value(params[0], fam="Show/Hide Menubar")
    if reason is not None:
        return reason
    if val not in _SHOWHIDE_MODES:
        return ("showhide_unmapped_mode",
                f"Show/Hide Menubar: mode {val!r} is not a matched Show/Hide value {sorted(_SHOWHIDE_MODES)} "
                "— an unknown/case-variant mode is refused, never passed through")
    return _bare_boolean_reason(params[1], "Lock", "Show/Hide Menubar", values=_DIRECT_BOOLEAN_VALUES)


def _cap_import_records_base(step) -> "tuple[str, str] | None":
    """id 35 (Import Records) — the BASE shape ONLY: EXACTLY two Booleans in the observed order,
    [0] `Verify SSL Certificates`, [1] `With dialog` (both bounded True/False), plus the emitter's fixed
    `<Restore state="False">` projection (no DDR source). Any saved import order, source/destination
    reference, matching rule, character set, or other configured import structure carries additional
    parameters/children — NOT a base shape — and refuses by name (packet 1107)."""
    params, reason = _base_params(step, "Import Records (base shape)")
    if reason is not None:
        return reason
    if len(params) != 2:
        return ("capability_unaccounted_shape",
                "Import Records base shape accounts for exactly two Booleans (Verify SSL Certificates, With "
                f"dialog); got {len(params)} — a saved import order / source / destination / matching rule / "
                "character set is a configured shape, not a base shape")
    for p, bt in ((params[0], "Verify SSL Certificates"), (params[1], "With dialog")):
        r = _bare_boolean_reason(p, bt, "Import Records (base shape)", values=_DIRECT_BOOLEAN_VALUES)
        if r is not None:
            return r
    return None


def _cap_paste(step) -> "tuple[str, str] | None":
    """id 48 (Paste) — the COMPLETE bounded two-Boolean grammar in the observed order: [0] `Select`,
    [1] `No style` (both bounded True/False), plus the fixed target fact `<LinkAvail state="False">` (no DDR
    source — never inferred as an option). The two axes are structurally independent, so all four bounded
    recombinations are capability-complete (captured Select=True/No style=True verified, the rest
    experimental). A missing/duplicate/extra parameter refuses rather than taking first matches (packet
    1107)."""
    params, reason = _base_params(step, "Paste")
    if reason is not None:
        return reason
    if len(params) != 2:
        return ("capability_unaccounted_shape",
                "Paste accounts for exactly two Booleans ('Select' then 'No style'); got "
                f"{len(params)} — a missing/duplicate/extra parameter refuses, never a first-match")
    for p, bt in ((params[0], "Select"), (params[1], "No style")):
        r = _bare_boolean_reason(p, bt, "Paste", values=_DIRECT_BOOLEAN_VALUES)
        if r is not None:
            return r
    return None


def _cap_set_zoom(step) -> "tuple[str, str] | None":
    """id 97 (Set Zoom Level) — EXACTLY two parameters in the observed order: [0] a `Lock` Boolean (bounded
    True/False), [1] a `<List>` zoom selector whose name is in the explicit `_ZOOM_LEVELS` map. `.rstrip("%")`
    is NOT permission for an arbitrary percentage — only a zoom value whose target spelling is established by
    matched evidence emits; anything else refuses by name (packet 1107)."""
    params, reason = _base_params(step, "Set Zoom Level")
    if reason is not None:
        return reason
    if len(params) != 2:
        return ("capability_unaccounted_shape",
                f"Set Zoom Level accounts for exactly two parameters (Lock, zoom List); got {len(params)}")
    r = _bare_boolean_reason(params[0], "Lock", "Set Zoom Level", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    if params[1].get("type") != "List":
        return ("capability_unaccounted_shape", "Set Zoom Level: the second parameter is not the zoom List selector")
    val, reason = _selector_list_value(params[1], fam="Set Zoom Level")
    if reason is not None:
        return reason
    if val not in _ZOOM_LEVELS:
        return ("zoom_unmapped_level",
                f"Set Zoom Level: zoom value {val!r} has no matched target spelling (only "
                f"{sorted(_ZOOM_LEVELS)} is evidenced); .rstrip('%') is not permission for an arbitrary "
                "percentage — refused rather than guessed")
    return None


def _cap_truncate_table(step) -> "tuple[str, str] | None":
    """id 182 (Truncate Table) — the CURRENT-TABLE base grammar: EXACTLY two parameters in the observed
    order, [0] a `With dialog` Boolean (bounded True/False, dialog→NoInteract polarity), [1] a `<List>`
    selector whose name is the evidenced `<Current Table>` (→ fixed target `<BaseTable id="-1" name>`).
    An explicit/non-current table has a different reference topology and target id, so an unknown selector,
    a duplicate List, or an alternate reference refuses — a base-table id is never invented (packet 1107)."""
    params, reason = _base_params(step, "Truncate Table")
    if reason is not None:
        return reason
    if len(params) != 2:
        return ("capability_unaccounted_shape",
                f"Truncate Table accounts for exactly two parameters (With dialog, current-table List); got "
                f"{len(params)}")
    r = _bare_boolean_reason(params[0], "With dialog", "Truncate Table", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    if params[1].get("type") != "List":
        return ("capability_unaccounted_shape",
                "Truncate Table: the second parameter is not the current-table List selector (an explicit-"
                "table reference is a different topology)")
    val, reason = _selector_list_value(params[1], fam="Truncate Table")
    if reason is not None:
        return reason
    if val not in _TRUNCATE_CURRENT_TABLE:
        return ("truncate_table_non_current",
                f"Truncate Table: selector {val!r} is not the evidenced current-table selector "
                f"{sorted(_TRUNCATE_CURRENT_TABLE)}; an explicit/non-current table has a different reference "
                "topology and target BaseTable id (never invent a base-table id) — refused")
    return None


# ── packet 1108 — the bounded reference-bearing emitters (11 ids) ──
#
# 11 already-emitting ids whose emitters fully consume ONE bounded reference/content topology each. NOT a
# universal reference grammar — each reference kind has its own bounded source topology and target
# projection; external-file targets, layout/script references, paths, destinations, credentials, arbitrary
# calculations, and richer configured variants stay OUT of scope and refuse. Reference id/name are CONTENT
# (copied, not shape); target-driving topology (selection mode, anchor/repetition presence, the
# Use-as-file-default / current flags) IS shape and is repaired into the signature (see `_step_signature`).
#
# EVIDENCE-TOKEN REPAIR, NOT growth. The `WindowReference` / `FieldReference` / `Object` / `CustomMenuSet`
# tokens each collapsed a target-driving topology to one string, so an uncaptured topology could inherit a
# verified verdict. Repaired with the smallest id-scoped discriminator, re-derived from the SAME committed
# pairs — `VERIFIED_STEP_IDS` and the pair fixtures are unchanged.
_OBJECT_NAME_SIG_IDS = frozenset({"145", "167", "180"})
_WINDOWREF_SIG_IDS = frozenset({"121", "123", "124"})
_FIELDREF_SIG_IDS = frozenset({"17", "154", "76", "132"})   # 1109 adds 76; 1115 adds 132 (Export Field Contents)


def _menu_default_value(param) -> str:
    b = param.find(".//Boolean[@type='Use as file default']")
    return b.get("value") if b is not None else "?"


def _windowref_sig_token(param) -> str:
    """The target-driving WindowReference topology: selection mode (current vs calculated-by-name), the
    calculated `current` flag that drives <LimitToWindowsOfCurrentFile>, and Rename presence (id 124's
    <NewName>). Window-name / rename calculation TEXT stays out of shape (it is content)."""
    wref = param.find("WindowReference")
    if wref is None:
        return "WindowReference"
    sel = wref.find("Select")
    rename = wref.find("Rename") is not None
    if sel is None:
        base = "?"
    elif sel.get("type") == "Calculated":
        nm = sel.find("Name")
        base = f"byname(current={nm.get('current') if nm is not None else '?'})"
    elif sel.get("type") == "current":
        base = "current"
    else:
        base = f"sel={sel.get('type')}"
    return "WindowReference:" + base + ("+rename" if rename else "")


def _fieldref_sig_token(param) -> str:
    """The target-driving FieldReference topology: TO-anchor presence (drives the target `<Field table>`) and
    repetition presence (drives a target `<Repetition>`). Field identity + repetition TEXT stay content."""
    fr = param.find("FieldReference")
    if fr is None:
        return "FieldReference"
    a = fr.find("TableOccurrenceReference") is not None
    r = fr.find("repetition") is not None
    suffix = "anchor+rep" if (a and r) else "anchor" if a else "rep" if r else "bare"
    return f"FieldReference:{suffix}"


def _calc_subtree_reason(container, fam, label) -> "tuple[str, str] | None":
    """A calc container (<Name>/<repetition>/<Rename>) must wrap EXACTLY one outer <Calculation> holding
    exactly one inner <Calculation> whose children are an optional <DDRREF> + exactly one <Text> — the exact
    grammar `_inner_text` reads (its `.//Text` first-match is unambiguous only if there is one Text). No other
    child / loose text; calc datatype/position attrs are metadata (allowed). Calc TEXT is content."""
    outer = container.findall("Calculation")
    if len(list(container)) != 1 or len(outer) != 1:
        return ("capability_unaccounted_shape", f"{fam}: {label} must hold exactly one <Calculation> wrapper")
    inner = outer[0].findall("Calculation")
    if len(list(outer[0])) != 1 or len(inner) != 1:
        return ("capability_unaccounted_shape",
                f"{fam}: {label} outer <Calculation> must hold exactly one inner <Calculation>")
    other = [c.tag for c in inner[0] if c.tag not in ("DDRREF", "Text")]
    if other:
        return ("capability_unaccounted_shape", f"{fam}: {label} inner calc has unexpected child(ren) {other}")
    if len(inner[0].findall("Text")) != 1:
        return ("capability_unaccounted_shape",
                f"{fam}: {label} inner calc must hold exactly one <Text> (a first-match .//Text would otherwise "
                "silently pick one)")
    return None


# ── A — Install Menu Set (142) ──

def _cap_install_menu_set(step) -> "tuple[str, str] | None":
    """id 142 — exactly one `CustomMenuSet` parameter holding one `CustomMenuSetReference` (id/name/UUID
    content; UUID dropped) with exactly one bounded `Use as file default` Boolean → `<UseAsFileDefault
    @state>` (packet 1108). The reference id/name are CONTENT; the Use-as-file-default VALUE changes target
    state and is signature-distinguished (True verified / False experimental). No duplicate/extra structure."""
    params, reason = _base_params(step, "Install Menu Set")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "CustomMenuSet":
        return ("capability_unaccounted_shape", "Install Menu Set accounts for exactly one CustomMenuSet parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Install Menu Set: the parameter is not a bare type=\"CustomMenuSet\"")
    refs = p.findall("CustomMenuSetReference")
    if len(list(p)) != 1 or len(refs) != 1:
        return ("capability_unaccounted_shape", "Install Menu Set: exactly one <CustomMenuSetReference>")
    ref = refs[0]
    if set(ref.attrib) - {"id", "name", "UUID"}:
        return ("capability_unaccounted_shape",
                f"Install Menu Set: <CustomMenuSetReference> unexpected attribute(s) {sorted(ref.attrib)}")
    bools = ref.findall("Boolean")
    if len(list(ref)) != 1 or len(bools) != 1 or bools[0].get("type") != "Use as file default":
        return ("capability_unaccounted_shape",
                "Install Menu Set: the reference must hold exactly one 'Use as file default' Boolean")
    b = bools[0]
    if (set(b.attrib) - {"type", "value", "id"}) or len(b) or (b.text or "").strip():
        return ("capability_unaccounted_shape",
                f"Install Menu Set: the 'Use as file default' Boolean carries unexpected attrs/children "
                f"({sorted(b.attrib)})")
    if b.get("value") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape",
                f"Install Menu Set: 'Use as file default' value {b.get('value')!r} is outside the FileMaker "
                "Boolean vocabulary")
    return None


# ── B — object-name family (145/167/180) ──

# Per-id repetition policy — NOT inferred from the shared `_emit_object_name`, but from each id's grammar and
# occurrences: Go to Object (145) / Refresh Object (167) target an object that CAN carry a repetition (observed
# present → the repetition is OPTIONAL, a no-repetition shape is capability-complete → experimental); Refresh
# Portal (180) has no repetition concept (observed absent → a repetition is FORBIDDEN, refuses).
_OBJECT_NAME_REPETITION = {145: "optional", 167: "optional", 180: "forbidden"}


def _cap_object_name(step) -> "tuple[str, str] | None":
    """ids 145/167/180 — one `Object` parameter with exactly one object-`Name` calculation and, per the per-id
    policy, an optional/forbidden `repetition` calculation (packet 1108). The name calc TEXT is content
    (`_inner_text`); repetition PRESENCE is topology (adds a target `<Repetition>`) and is signature-
    distinguished so a no-repetition 145/167 emits experimentally rather than inheriting the verified
    repetition shape. A missing Object/Name, duplicate Name/repetition, a repetition on 180, or an unexpected
    child refuses."""
    sid = int(step.get("id"))
    fam = f"object-name id {sid}"
    params, reason = _base_params(step, fam)
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "Object":
        return ("capability_unaccounted_shape", f"{fam} accounts for exactly one Object parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the parameter is not a bare type=\"Object\"")
    extra = sorted({c.tag for c in p if c.tag not in ("Name", "repetition")})
    if extra:
        return ("capability_unaccounted_shape", f"{fam}: unexpected Object child element(s) {extra}")
    names = p.findall("Name")
    reps = p.findall("repetition")
    if len(names) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one object <Name> calculation")
    if set(names[0].attrib):
        return ("capability_unaccounted_shape", f"{fam}: object <Name> carries unexpected attribute(s)")
    r = _calc_subtree_reason(names[0], fam, "the object-name calculation")
    if r is not None:
        return r
    if len(reps) > 1:
        return ("capability_unaccounted_shape", f"{fam}: at most one <repetition>")
    if reps and _OBJECT_NAME_REPETITION[sid] == "forbidden":
        return ("capability_unaccounted_shape",
                f"{fam} (Refresh Portal) does not carry a repetition — a portal has no repetition concept; "
                "refused rather than emitting an invented <Repetition>")
    if reps:
        if set(reps[0].attrib):
            return ("capability_unaccounted_shape", f"{fam}: <repetition> carries unexpected attribute(s)")
        r = _calc_subtree_reason(reps[0], fam, "the repetition calculation")
        if r is not None:
            return r
    return None


# ── C — WindowReference family (121/123/124) ──

def _window_select_reason(sel, fam) -> "tuple[str, str] | None":
    """One `<Select>` node: `type="current"` (no children → fixed `<LimitToWindowsOfCurrentFile
    state="False"/>` + `<Window value="Current"/>`) or `type="Calculated"` (exactly one `<Name current=…>`
    calc, `current` bounded True/False → `<Window value="ByName"/>` + `<Name>`). The Select's own attrs (e.g.
    `kind`) are source provenance, tolerated. Extracted from packet 1108's `_window_reference_reason` so
    packet-1110 id 119 can reuse the SAME selection grammar by composition — 121/123/124 keep the identical
    checks. Calc TEXT is content; an unknown selection type refuses rather than being treated as current."""
    seltype = sel.get("type")
    if seltype == "current":
        if len(sel):
            return ("capability_unaccounted_shape",
                    f"{fam}: a current <Select> carries no children (a stray <Name> would be silently dropped)")
        return None
    if seltype == "Calculated":
        names = sel.findall("Name")
        if len(list(sel)) != 1 or len(names) != 1:
            return ("capability_unaccounted_shape", f"{fam}: a Calculated <Select> must hold exactly one <Name>")
        nm = names[0]
        if set(nm.attrib) - {"current"}:
            return ("capability_unaccounted_shape", f"{fam}: <Name> unexpected attribute(s) {sorted(nm.attrib)}")
        if nm.get("current") not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape",
                    f"{fam}: <Name current={nm.get('current')!r}> is outside the FileMaker Boolean vocabulary")
        return _calc_subtree_reason(nm, fam, "the by-name calculation")
    return ("window_selection_unknown",
            f"{fam}: <Select type={seltype!r}> is not a known window selection (only 'current' or "
            "'Calculated') — refused rather than silently treated as current")


def _window_reference_reason(step, fam, *, require_rename) -> "tuple[str, str] | None":
    """One `WindowReference` parameter holding one `<WindowReference>` with exactly one `<Select>` (packet
    1108). Selection vocabulary is `current` (→ fixed `<LimitToWindowsOfCurrentFile state="False"/>` +
    `<Window value="Current"/>`, NO Name) or `Calculated` (→ a `<Name current=…>` calc: `current` bounded
    True/False drives `<LimitToWindowsOfCurrentFile>`, `<Window value="ByName"/>` + `<Name>`). `require_rename`
    (id 124) requires exactly one `<Rename>` calc → `<NewName>`; ids 121/123 forbid `<Rename>` (the emitter
    would silently ignore it). Calc TEXT is content. Unknown selection type, calculated-without-Name, current-
    with-Name, or a misplaced/duplicate Rename refuses."""
    params, reason = _base_params(step, fam)
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "WindowReference":
        return ("capability_unaccounted_shape", f"{fam} accounts for exactly one WindowReference parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the parameter is not a bare type=\"WindowReference\"")
    wrefs = p.findall("WindowReference")
    if len(list(p)) != 1 or len(wrefs) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <WindowReference> node")
    wref = wrefs[0]
    if set(wref.attrib):
        return ("capability_unaccounted_shape", f"{fam}: <WindowReference> carries unexpected attribute(s)")
    extra = sorted({c.tag for c in wref if c.tag not in ("Select", "Rename")})
    if extra:
        return ("capability_unaccounted_shape", f"{fam}: unexpected <WindowReference> child(ren) {extra}")
    sels = wref.findall("Select")
    renames = wref.findall("Rename")
    if len(sels) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <Select>")
    r = _window_select_reason(sels[0], fam)
    if r is not None:
        return r
    if require_rename:
        if len(renames) != 1:
            return ("capability_unaccounted_shape",
                    f"{fam}: Set Window Title requires exactly one <Rename> calculation (its <NewName> target)")
        r = _calc_subtree_reason(renames[0], fam, "the rename calculation")
        if r is not None:
            return r
    elif renames:
        return ("capability_unaccounted_shape",
                f"{fam}: a <Rename> is only consumed by Set Window Title (124); here it would be silently "
                "ignored, so it refuses")
    return None


def _cap_window_named(step) -> "tuple[str, str] | None":
    """ids 121 (Close Window) + 123 (Select Window) — current or calculated-by-name selection, no Rename."""
    return _window_reference_reason(step, "Close/Select Window", require_rename=False)


def _cap_set_window_title(step) -> "tuple[str, str] | None":
    """id 124 (Set Window Title) — selection + a required Rename calculation → <NewName>."""
    return _window_reference_reason(step, "Set Window Title", require_rename=True)


# ── D — FieldReference family (17/154) ──

# Sort direction is an INDEPENDENT explicit source→target map (bounded to the two matched pairs), NOT a
# `"Sort" + name` synthesis: an unknown direction refuses rather than emitting a guessed `Sort<X>`.
_SORT_BY_FIELD_DIRECTIONS = {"Ascending": "SortAscending", "Descending": "SortDescending"}


def _field_ref_node_reason(fr, fam, *, require_anchor=False) -> "tuple[str, str] | None":
    """A `<FieldReference>` NODE (id/name required content; UUID dropped) with an OPTIONAL
    `<TableOccurrenceReference>` anchor (name required — → target `<Field table>`; its id/UUID dropped) and an
    OPTIONAL `<repetition>` calc (packet 1108; node extracted for reuse by 76/130/61/77/203 in packet 1109).
    `require_anchor` (130/61, whose `_emit_field_ref` always writes a `table` attr) refuses a no-anchor ref
    rather than emitting an unproven empty table. A duplicate anchor/repetition, a non-empty/nameless anchor,
    a missing id/name, or an unexpected child refuses. Anchor + repetition PRESENCE are topology; field
    identity + repetition text are content."""
    if set(fr.attrib) - {"id", "name", "UUID"}:
        return ("capability_unaccounted_shape",
                f"{fam}: <FieldReference> unexpected attribute(s) {sorted(fr.attrib)}")
    if fr.get("id") is None or fr.get("name") is None:
        return ("capability_unaccounted_shape", f"{fam}: <FieldReference> must carry id and name")
    extra = sorted({c.tag for c in fr if c.tag not in ("TableOccurrenceReference", "repetition")})
    if extra:
        return ("capability_unaccounted_shape", f"{fam}: <FieldReference> unexpected child(ren) {extra}")
    tos = fr.findall("TableOccurrenceReference")
    reps = fr.findall("repetition")
    if len(tos) > 1:
        return ("capability_unaccounted_shape", f"{fam}: at most one <TableOccurrenceReference> anchor")
    if len(reps) > 1:
        return ("capability_unaccounted_shape", f"{fam}: at most one <repetition>")
    if require_anchor and not tos:
        return ("capability_unaccounted_shape",
                f"{fam}: a FieldReference target without a TableOccurrenceReference anchor is unaccounted (the "
                "emitter would write an empty table); refused")
    if tos:
        to = tos[0]
        if (set(to.attrib) - {"id", "name", "UUID"}) or len(to):
            return ("capability_unaccounted_shape",
                    f"{fam}: <TableOccurrenceReference> unexpected attrs/children ({sorted(to.attrib)})")
        if to.get("name") is None:
            return ("capability_unaccounted_shape", f"{fam}: <TableOccurrenceReference> must carry a name")
    if reps:
        if set(reps[0].attrib):
            return ("capability_unaccounted_shape", f"{fam}: <repetition> carries unexpected attribute(s)")
        r = _calc_subtree_reason(reps[0], fam, "the repetition calculation")
        if r is not None:
            return r
    return None


def _field_reference_reason(param, fam, *, require_anchor=False) -> "tuple[str, str] | None":
    """A bare `<Parameter type="FieldReference">` wrapping exactly one `<FieldReference>` node (packet 1108);
    delegates the node grammar to `_field_ref_node_reason`."""
    if (set(param.attrib) - {"type"}) or (param.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the parameter is not a bare type=\"FieldReference\"")
    frs = param.findall("FieldReference")
    if len(list(param)) != 1 or len(frs) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <FieldReference> node")
    return _field_ref_node_reason(frs[0], fam, require_anchor=require_anchor)


def _cap_goto_field(step) -> "tuple[str, str] | None":
    """id 17 (Go to Field) — a bounded `Select/perform` Boolean → `<SelectAll @state>` + a FieldReference
    (packet 1108). Both Boolean values map directly (captured False/True both verified)."""
    params, reason = _base_params(step, "Go to Field")
    if reason is not None:
        return reason
    if len(params) not in (1, 2):
        return ("capability_unaccounted_shape",
                "Go to Field accounts for a 'Select/perform' Boolean + an OPTIONAL FieldReference")
    r = _bare_boolean_reason(params[0], "Select/perform", "Go to Field", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    if len(params) == 1:                       # packet 1129 — the no-field (Select-only) form
        return None
    if params[1].get("type") != "FieldReference":
        return ("capability_unaccounted_shape", "Go to Field: the second parameter is not a FieldReference")
    return _field_reference_reason(params[1], "Go to Field")


def _cap_install_ontimer(step) -> "tuple[str, str] | None":
    """id 148 (Install OnTimer Script) — packet 1129. The clear form (bare / optional-Collapsed, verified `()`),
    OR a current-file `<ScriptReference>` (id/name content, UUID + empty repetition dropped) + a required
    interval `<Calculation>`. A By-name/external (DataSourceReference) target, a missing interval, or a
    duplicate refuses; script id/name are content, the ScriptReference PRESENCE is the shape."""
    bare = _cap_clean_bare(step)
    if bare is None:
        return None
    params, reason = _base_params(step, "Install OnTimer Script")
    if reason is not None:
        return bare
    srs = [p for p in params if p.get("type") == "ScriptReference"]
    calcs = [p for p in params if p.get("type") == "Calculation"]
    if len(params) != 2 or len(srs) != 1 or len(calcs) != 1:
        return bare
    sp = srs[0]
    if (set(sp.attrib) - {"type"}) or (sp.text or "").strip():
        return ("capability_unaccounted_shape", "Install OnTimer Script: the parameter is not a bare type=\"ScriptReference\"")
    refs = sp.findall("ScriptReference")
    if len(list(sp)) != 1 or len(refs) != 1:
        return ("capability_unaccounted_shape", "Install OnTimer Script: exactly one <ScriptReference> node")
    ref = refs[0]
    if (set(ref.attrib) - {"id", "name", "UUID"}) or sorted(c.tag for c in ref) not in ([], ["repetition"]):
        return ("capability_unaccounted_shape", "Install OnTimer Script: <ScriptReference> unexpected attrs/children")
    cp = calcs[0]
    if (set(cp.attrib) - {"type"}) or (cp.text or "").strip():
        return ("capability_unaccounted_shape", "Install OnTimer Script: the interval parameter is not a bare type=\"Calculation\"")
    cs = cp.findall("Calculation")
    if len(list(cp)) != 1 or len(cs) != 1:
        return ("capability_unaccounted_shape", "Install OnTimer Script: exactly one interval calculation")
    if set(cs[0].attrib) - {"datatype", "position"}:
        return ("capability_unaccounted_shape", "Install OnTimer Script: the interval calculation carries unexpected attribute(s)")
    return _wrapped_calc_reason(cs[0], "Install OnTimer Script", "the interval calculation")


def _cap_perform_quick_find(step) -> "tuple[str, str] | None":
    """id 150 (Perform Quick Find) — packet 1129. The bare / optional-Collapsed base shape (verified `()`), OR
    exactly one bare `<Parameter type="Calculation">` holding the search-term calculation. Search TEXT is
    content; the calc PRESENCE distinguishes the two shapes (an id-scoped signature token). A malformed calc,
    a duplicate, or any other parameter refuses."""
    bare = _cap_clean_bare(step)
    if bare is None:
        return None
    params, reason = _base_params(step, "Perform Quick Find")
    if reason is not None or len(params) != 1 or params[0].get("type") != "Calculation":
        return bare
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Perform Quick Find: the parameter is not a bare type=\"Calculation\"")
    cs = p.findall("Calculation")
    if len(list(p)) != 1 or len(cs) != 1:
        return ("capability_unaccounted_shape", "Perform Quick Find: exactly one search calculation")
    if set(cs[0].attrib) - {"datatype", "position"}:
        return ("capability_unaccounted_shape", "Perform Quick Find: the search calculation carries unexpected attribute(s)")
    return _wrapped_calc_reason(cs[0], "Perform Quick Find", "the search calculation")


def _cap_sort_by_field(step) -> "tuple[str, str] | None":
    """id 154 (Sort Records by Field) — a bounded sort-direction List (`_SORT_BY_FIELD_DIRECTIONS`) + a
    FieldReference (packet 1108). An unknown direction refuses by name rather than emitting a guessed
    `Sort<X>`."""
    params, reason = _base_params(step, "Sort Records by Field")
    if reason is not None:
        return reason
    if len(params) not in (1, 2):
        return ("capability_unaccounted_shape",
                "Sort Records by Field accounts for a sort-direction List + an OPTIONAL FieldReference")
    if params[0].get("type") != "List":
        return ("capability_unaccounted_shape", "Sort Records by Field: the first parameter is not the sort List")
    val, reason = _selector_list_value(params[0], fam="Sort Records by Field")
    if reason is not None:
        return reason
    if val not in _SORT_BY_FIELD_DIRECTIONS:
        return ("sort_direction_unmapped",
                f"Sort Records by Field: direction {val!r} is not a matched sort mapping "
                f"{sorted(_SORT_BY_FIELD_DIRECTIONS)} — refused rather than emitting a synthesized Sort<X>")
    if len(params) == 1:                       # packet 1129 — the no-field (direction-only) form
        return None
    if params[1].get("type") != "FieldReference":
        return ("capability_unaccounted_shape", "Sort Records by Field: the second parameter is not a FieldReference")
    return _field_reference_reason(params[1], "Sort Records by Field")


# ── E — current-file references (33/34) ──

def _data_source_current_reason(p, fam) -> "tuple[str, str] | None":
    """One `<DataSourceReference>` whose proven current-file identity is `id="0"` (name is content) with no
    children (packet 1108). A NAMED/external reference (`id != "0"`) refuses by a stable external-file hazard —
    the clip would need a FileReference/UniversalPathList path this emitter/source subtree does not supply, so
    it is NEVER emitted as a misleading current-file clip and never borrowed from another step."""
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the parameter is not a bare type=\"DataSourceReference\"")
    dsrs = p.findall("DataSourceReference")
    if len(list(p)) != 1 or len(dsrs) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <DataSourceReference> node")
    d = dsrs[0]
    # UUID is DDR modification-tracking provenance (dropped) — tolerated so the id="0" current-file form
    # AND the id!=0 external form both parse; the current-file committed shapes carry no UUID, so this
    # widening is a superset and leaves them byte-identical (packet 1118). No children in either form.
    if (set(d.attrib) - {"id", "name", "UUID"}) or len(d):
        return ("capability_unaccounted_shape",
                f"{fam}: <DataSourceReference> unexpected attrs/children ({sorted(d.attrib)})")
    if d.get("id") != "0":
        return ("external_file_reference_unsupported",
                f"{fam}: <DataSourceReference id={d.get('id')!r}> is a NAMED/external file target; the clip needs "
                "a FileReference/path fact this emitter and source subtree do not supply, so it is refused (never "
                "a misleading current-file clip, never a borrowed path). Only the current-file id=\"0\" emits")
    return None


def _cap_open_file(step) -> "tuple[str, str] | None":
    """id 33 (Open File) — a bounded `Open hidden` Boolean → `<Option @state>` + a current-file
    DataSourceReference (packet 1108). Both Boolean values map directly; an external target refuses."""
    params, reason = _base_params(step, "Open File")
    if reason is not None:
        return reason
    if len(params) != 2:
        return ("capability_unaccounted_shape",
                "Open File accounts for an 'Open hidden' Boolean + a current-file DataSourceReference")
    r = _bare_boolean_reason(params[0], "Open hidden", "Open File", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    if params[1].get("type") != "DataSourceReference":
        return ("capability_unaccounted_shape", "Open File: the second parameter is not a DataSourceReference")
    return _data_source_current_reason(params[1], "Open File")


def _cap_close_file(step) -> "tuple[str, str] | None":
    """id 34 (Close File) — exactly one current-file DataSourceReference → the bare current-file target
    (packet 1108). An external target refuses; no file/path element is invented."""
    params, reason = _base_params(step, "Close File")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "DataSourceReference":
        return ("capability_unaccounted_shape", "Close File accounts for exactly one DataSourceReference")
    return _data_source_current_reason(params[0], "Close File")


# ── packet 1109 — the calculation and direct-content primitives (18 ids) ──
#
# 18 already-emitting ids whose target is determined by bounded calculations or direct source content. NOT
# universal calculation capability — each id gets its COMPLETE bounded source grammar, and calculation text is
# content ONLY after topology/cardinality is proven. Script/layout references, account/credential, external
# file resolution, PDF/AI/email, and Rich Replace Field Contents stay out of scope + refuse.
#
# Two content-vs-shape rules run throughout: (1) calculation/name/path/URL TEXT and canonicalised function
# spelling are CONTENT (never signature); (2) these topology facts are SHAPE — absent vs present, present-empty
# vs present-populated where FileMaker emits different structure, required vs optional, nested position (0/1),
# repetition present vs absent, field-target vs variable-target, anchor kind, and action/mode selector.
#
# Many of these DDR steps carry the SaveAsXML provenance bundle (hash/index attrs + <UUID>/<SourceUUID>/
# <Options>/<DDRREF> children) ALONGSIDE <ParameterValues>. The emitters and `_step_signature` already ignore
# it, so capability must TOLERATE it (validating each as the known target-absent metadata) or these ids would
# newly refuse a provenance-bearing form the old code emitted. `_step_body` is that shared, non-wildcard
# front-end.
_PROVENANCE_TAGS = frozenset({"UUID", "SourceUUID", "OwnerID", "Options", "DDRREF"})


def _step_body(step, fam) -> "tuple[list, tuple[str, str] | None]":
    """(params, None) or ([], reason). The shared calc/content front-end: a clean shell whose attrs ⊆
    _TARGET_ABSENT_STEP_ATTRS ({id,name,enable,hash,index,breakpoint}), enable/breakpoint bounded, no loose
    text; top-level children are AT MOST one
    <ParameterValues> plus any subset of the target-absent provenance tags (each validated leaf/known — NOT a
    wildcard strip); the <ParameterValues> holds only <Parameter> children. Returns the parameter list (empty
    when there is no <ParameterValues> — e.g. a no-result Exit Script)."""
    if set(step.attrib) - _TARGET_ABSENT_STEP_ATTRS:
        return [], ("capability_unaccounted_shape", f"{fam}: unexpected Step attribute(s) {sorted(step.attrib)}")
    r = _step_shell_bool_reason(step, fam)
    if r is not None:
        return [], r
    if (step.text or "").strip():
        return [], ("capability_unaccounted_shape", f"{fam}: loose direct text under <Step>")
    others = sorted({c.tag for c in step if c.tag != "ParameterValues" and c.tag not in _PROVENANCE_TAGS})
    if others:
        return [], ("capability_unaccounted_shape", f"{fam}: unexpected top-level child element(s) {others}")
    for c in step:
        if c.tag == "DDRREF":
            if (set(c.attrib) - {"kind", "hash"}) or len(c):
                return [], ("capability_unaccounted_shape", f"{fam}: <DDRREF> unexpected attrs/children")
        elif c.tag in _PROVENANCE_TAGS:
            if set(c.attrib) or len(c):
                return [], ("capability_unaccounted_shape", f"{fam}: <{c.tag}> unexpected attrs/children")
    pvs = step.findall("ParameterValues")
    if len(pvs) > 1:
        return [], ("capability_unaccounted_shape", f"{fam}: {len(pvs)} <ParameterValues> blocks (at most one)")
    if pvs and any(c.tag != "Parameter" for c in pvs[0]):
        return [], ("capability_unaccounted_shape", f"{fam}: a non-Parameter child under <ParameterValues>")
    return (pvs[0].findall("Parameter") if pvs else []), None


def _typed_calc_param_reason(p, fam, label) -> "tuple[str, str] | None":
    """A <Parameter type=…>/<Name>/<FunctionRef> (only a `type` attr) directly wrapping the standard calc
    subtree. The nested position is metadata (varies) — validated only where it is target-driving (id 147)."""
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: {label} parameter carries unexpected attrs/text")
    return _calc_subtree_reason(p, fam, label)


_TARGET_SIG_IDS = frozenset({"77", "203", "160",   # 1115 adds 160 (Insert from URL): same _append_result_target
                             # packet 1126 — the Data File family's Target (field vs variable branch) drives
                             # <Field table…/> vs <Text/><Field>$var</Field>, so a field target on an id
                             # captured only for a variable must fence, not inherit its verdict.
                             "188", "189", "191", "192", "193", "194"})


def _target_sig_token(param) -> str:
    """The target-driving Target topology for 77/203: field-branch vs variable-branch, and the anchor/
    repetition presence that `_append_result_target` projects into <Field @table>/<Repetition>. Field identity
    and calc text stay content."""
    fr = param.find("FieldReference")
    var = param.find("Variable")
    if fr is not None:
        a = fr.find("TableOccurrenceReference") is not None
        r = fr.find("repetition") is not None
        return f"Target:field:{'anchor+rep' if a and r else 'anchor' if a else 'rep' if r else 'bare'}"
    if var is not None:
        return "Target:var+rep" if var.find("repetition") is not None else "Target:var"
    return "Target"


def _target_branch_reason(t, fam) -> "tuple[str, str] | None":
    """A <Parameter type="Target"> holds EXACTLY ONE FieldReference OR one Variable branch (both/neither/
    duplicate refuse). The field branch reuses the FieldReference node authority; the variable branch is a
    `<Variable value=…>` (the $name, content) with an optional repetition calc."""
    if (set(t.attrib) - {"type"}) or (t.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the parameter is not a bare type=\"Target\"")
    frs = t.findall("FieldReference")
    vars_ = t.findall("Variable")
    if len(list(t)) != 1 or (len(frs) + len(vars_)) != 1:
        return ("capability_unaccounted_shape",
                f"{fam}: Target must hold exactly one FieldReference OR one Variable branch (both/neither refuse)")
    if frs:
        return _field_ref_node_reason(frs[0], fam)
    v = vars_[0]
    if (set(v.attrib) - {"value"}) or (v.text or "").strip() or v.get("value") is None:
        return ("capability_unaccounted_shape", f"{fam}: <Variable> must carry a value ($name) and no loose text")
    reps = v.findall("repetition")
    extra = sorted({c.tag for c in v if c.tag != "repetition"})
    if extra:
        return ("capability_unaccounted_shape", f"{fam}: <Variable> unexpected child(ren) {extra}")
    if len(reps) > 1:
        return ("capability_unaccounted_shape", f"{fam}: <Variable> at most one repetition")
    if reps:
        if set(reps[0].attrib):
            return ("capability_unaccounted_shape", f"{fam}: <Variable> repetition unexpected attrs")
        return _calc_subtree_reason(reps[0], fam, "the variable repetition calculation")
    return None


# ── A — control flow + Comment (68/69/72/89/103/125) ──

def _cap_condition_calc(step, fam) -> "tuple[str, str] | None":
    """ids 68 (If), 72 (Exit Loop If), 125 (Else If) — exactly one required condition Calculation (the exact
    nested calc subtree) plus at most one Collapsed Boolean. Present-Collapsed → verified, absent → the
    Calculation-only signature (experimental for 68/125). Calc TEXT (incl. empty) is content — a present-empty
    condition emits `<Calculation></Calculation>`, the same target STRUCTURE as populated (packet 1109)."""
    params, reason = _step_body(step, fam)
    if reason is not None:
        return reason
    calcs = [p for p in params if p.get("type") == "Calculation"]
    bools = [p for p in params if p.get("type") == "Boolean"]
    if len(calcs) != 1:
        return ("capability_unaccounted_shape", f"{fam} requires exactly one condition Calculation; got {len(calcs)}")
    if len(bools) > 1 or len(params) != len(calcs) + len(bools):
        return ("capability_unaccounted_shape", f"{fam}: only one condition Calculation + an optional Collapsed")
    if bools:
        r = _bare_boolean_reason(bools[0], "Collapsed", fam, values=_DIRECT_BOOLEAN_VALUES)
        if r is not None:
            return r
    return _typed_calc_param_reason(calcs[0], fam, "the condition calculation")


def _cap_if(step) -> "tuple[str, str] | None":
    return _cap_condition_calc(step, "If")


def _cap_exit_loop_if(step) -> "tuple[str, str] | None":
    return _cap_condition_calc(step, "Exit Loop If")


def _cap_else_if(step) -> "tuple[str, str] | None":
    return _cap_condition_calc(step, "Else If")


def _cap_exit_script(step) -> "tuple[str, str] | None":
    """id 103 (Exit Script) — an OPTIONAL result Calculation (absent → no `<Calculation>`; present → the calc
    subtree). Both branches are evidenced (packet 1109)."""
    params, reason = _step_body(step, "Exit Script")
    if reason is not None:
        return reason
    calcs = [p for p in params if p.get("type") == "Calculation"]
    if len(calcs) != len(params):
        return ("capability_unaccounted_shape", "Exit Script accounts only for an optional result Calculation")
    if len(calcs) > 1:
        return ("capability_unaccounted_shape", "Exit Script: at most one result Calculation")
    return _typed_calc_param_reason(calcs[0], "Exit Script", "the result calculation") if calcs else None


def _cap_else(step) -> "tuple[str, str] | None":
    """id 69 (Else) — EXACTLY two Collapsed Boolean parameters (the unusual duplicate block-marker state the
    committed pair carries), nothing else; the fixed `<Restore state="False">` is an explicit projection fact
    (packet 1109). Not generalised through `_cap_clean_bare`."""
    params, reason = _step_body(step, "Else")
    if reason is not None:
        return reason
    if len(params) != 2:
        return ("capability_unaccounted_shape",
                f"Else accounts for exactly two Collapsed Boolean parameters; got {len(params)}")
    for p in params:
        r = _bare_boolean_reason(p, "Collapsed", "Else", values=_DIRECT_BOOLEAN_VALUES)
        if r is not None:
            return r
    return None


def _cap_comment(step) -> "tuple[str, str] | None":
    """id 89 (# comment) — exactly one `<Comment>` node. A `value` ATTRIBUTE present → a target `<Text>` child
    (its text is content, incl. empty); ABSENT → no `<Text>`. That value-present/absent split is target-driving
    topology and is signature-distinguished (`Comment:set`/`Comment:bare`) so a bare comment cannot inherit the
    populated verified shape (packet 1109)."""
    params, reason = _step_body(step, "# (comment)")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "Comment":
        return ("capability_unaccounted_shape", "# (comment) accounts for exactly one Comment parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "# (comment): the parameter is not a bare type=\"Comment\"")
    comments = p.findall("Comment")
    if len(list(p)) != 1 or len(comments) != 1:
        return ("capability_unaccounted_shape", "# (comment): exactly one <Comment> node")
    c = comments[0]
    if (set(c.attrib) - {"value"}) or len(c) or (c.text or "").strip():
        return ("capability_unaccounted_shape", f"# (comment): <Comment> unexpected attrs/children ({sorted(c.attrib)})")
    return None


# ── B — variable / field / result calculations (76/77/141/147/203) ──

def _cap_set_variable(step) -> "tuple[str, str] | None":
    """id 141 (Set Variable) — exactly one `<Variable>` parameter holding one value calc, one `<Name value=…>`
    (the $name, content), and one repetition calc (packet 1109). Missing/duplicate/reordered/unknown children
    or loose text refuse before the emitter's first-match `.find`s."""
    params, reason = _step_body(step, "Set Variable")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "Variable":
        return ("capability_unaccounted_shape", "Set Variable accounts for exactly one Variable parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Set Variable: the parameter is not a bare type=\"Variable\"")
    values = p.findall("value")
    names = p.findall("Name")
    reps = p.findall("repetition")
    extra = sorted({c.tag for c in p if c.tag not in ("value", "Name", "repetition")})
    if extra:
        return ("capability_unaccounted_shape", f"Set Variable: unexpected Variable child(ren) {extra}")
    if len(values) != 1 or len(names) != 1 or len(reps) != 1:
        return ("capability_unaccounted_shape", "Set Variable requires exactly one value, one Name, one repetition")
    v = values[0]                              # packet 1129 — an EMPTY <value/> (no calc) is the placeholder form
    if len(v) or (v.text or "").strip():
        r = _calc_subtree_reason(v, "Set Variable", "the value calculation")
        if r is not None:
            return r
    r = _calc_subtree_reason(reps[0], "Set Variable", "the repetition calculation")
    if r is not None:
        return r
    nm = names[0]
    if (set(nm.attrib) - {"value"}) or len(nm) or (nm.text or "").strip() or nm.get("value") is None:
        return ("capability_unaccounted_shape", "Set Variable: <Name> must be a bare value attribute (the $name)")
    return None


def _cap_set_field(step) -> "tuple[str, str] | None":
    """id 76 (Set Field) — exactly one target FieldReference (id/name/table content; anchor + repetition are
    topology) + one value Calculation (packet 1109). Reuses the FieldReference node authority; membership in
    `_FIELDREF_SIG_IDS` supplies the anchor/rep signature discrimination but is NOT itself permission."""
    params, reason = _step_body(step, "Set Field")
    if reason is not None:
        return reason
    frs = [p for p in params if p.get("type") == "FieldReference"]
    calcs = [p for p in params if p.get("type") == "Calculation"]
    if len(frs) != 1 or len(calcs) != 1 or len(params) != 2:
        return ("capability_unaccounted_shape",
                "Set Field accounts for exactly one target FieldReference + one value Calculation")
    r = _field_reference_reason(frs[0], "Set Field")
    if r is not None:
        return r
    return _typed_calc_param_reason(calcs[0], "Set Field", "the value calculation")


def _cap_calc_into_target(step, fam) -> "tuple[str, str] | None":
    """ids 77 (Insert Calculated Result) + 203 (Execute FileMaker Data API) — a `Select` Boolean, a value
    Calculation, and EXACTLY one Target branch (field OR variable; both/neither/duplicate refuse) (packet
    1109). The captured branch is verified; the implemented-but-uncaptured branch/topology is experimental
    (`Target` is signature-split field:anchor/rep vs var+rep)."""
    params, reason = _step_body(step, fam)
    if reason is not None:
        return reason
    bools = [p for p in params if p.get("type") == "Boolean"]
    targets = [p for p in params if p.get("type") == "Target"]
    calcs = [p for p in params if p.get("type") == "Calculation"]
    if len(bools) != 1 or len(targets) != 1 or len(calcs) != 1 or len(params) != 3:
        return ("capability_unaccounted_shape",
                f"{fam} accounts for a Select Boolean, one Target, and one value Calculation")
    r = _bare_boolean_reason(bools[0], "Select", fam, values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    r = _typed_calc_param_reason(calcs[0], fam, "the value calculation")
    if r is not None:
        return r
    return _target_branch_reason(targets[0], fam)


def _cap_insert_calc_result(step) -> "tuple[str, str] | None":
    return _cap_calc_into_target(step, "Insert Calculated Result")


def _cap_execute_data_api(step) -> "tuple[str, str] | None":
    return _cap_calc_into_target(step, "Execute FileMaker Data API")


def _cap_set_field_by_name(step) -> "tuple[str, str] | None":
    """id 147 (Set Field By Name) — a `Specify target field` Boolean plus EXACTLY two Calculation parameters
    whose nested positions are 0 (Result) and 1 (TargetName). The POSITION assignment is shape (both formula
    texts are content); duplicate/missing/unknown positions or extra calcs refuse before the emitter's
    `next(...)` position searches (packet 1109)."""
    params, reason = _step_body(step, "Set Field By Name")
    if reason is not None:
        return reason
    bools = [p for p in params if p.get("type") == "Boolean"]
    calcs = [p for p in params if p.get("type") == "Calculation"]
    if len(bools) != 1 or len(calcs) != 2 or len(params) != 3:
        return ("capability_unaccounted_shape",
                "Set Field By Name accounts for a 'Specify target field' Boolean + two positioned Calculations")
    r = _bare_boolean_reason(bools[0], "Specify target field", "Set Field By Name", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    positions = []
    for c in calcs:
        r = _typed_calc_param_reason(c, "Set Field By Name", "a formula")
        if r is not None:
            return r
        positions.append(c.find("Calculation").get("position"))
    if sorted(positions) != ["0", "1"]:
        return ("set_field_by_name_position",
                f"Set Field By Name requires exactly nested positions 0 (Result) and 1 (TargetName); got "
                f"{sorted(positions)} — a duplicate/missing/unknown position refuses")
    return None


# ── C — Insert Text (61) + Set Selection (130) ──

def _cap_insert_text(step) -> "tuple[str, str] | None":
    """id 61 (Insert Text) — a `Select` Boolean, an optional Target (a FieldReference, anchor REQUIRED since
    `_emit_field_ref` always writes a table), and exactly one `<Text>` payload whose `value` attribute present/
    absent is the packet-1082 set/empty topology (packet 1109). A filled Text can never be admitted by the
    empty shape or vice versa; text is content."""
    params, reason = _step_body(step, "Insert Text")
    if reason is not None:
        return reason
    bools = [p for p in params if p.get("type") == "Boolean"]
    targets = [p for p in params if p.get("type") == "Target"]
    texts = [p for p in params if p.get("type") == "Text"]
    if len(bools) != 1 or len(texts) != 1 or len(targets) > 1 or len(params) != len(bools) + len(texts) + len(targets):
        return ("capability_unaccounted_shape",
                "Insert Text accounts for a Select Boolean, one Text payload, and an optional Target")
    r = _bare_boolean_reason(bools[0], "Select", "Insert Text", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    tp = texts[0]
    tnodes = tp.findall("Text")
    if (set(tp.attrib) - {"type"}) or len(list(tp)) != 1 or len(tnodes) != 1:
        return ("capability_unaccounted_shape", "Insert Text: the Text parameter must hold exactly one <Text> node")
    if (set(tnodes[0].attrib) - {"value"}) or len(tnodes[0]):
        return ("capability_unaccounted_shape", "Insert Text: <Text> node unexpected attrs/children")
    # A Target requires a filled Text (an empty Text couples to NO Target — the packet-1082/1069 guard). A
    # filled Text WITHOUT a Target is the real "insert into the active field" form (packet 1129). The Target
    # is a field (FieldReference, anchor required) OR a variable (packet 1129 → <Field>$var</Field>).
    text_set = bool(tnodes[0].get("value"))
    if targets and not text_set:
        return ("capability_unaccounted_shape",
                "Insert Text: a Target with an empty Text is not an implemented branch")
    if targets:
        t = targets[0]
        frs = t.findall("FieldReference")
        vars = t.findall("Variable")
        if (set(t.attrib) - {"type"}) or len(list(t)) != 1 or (len(frs) + len(vars)) != 1:
            return ("capability_unaccounted_shape",
                    "Insert Text: Target must hold exactly one FieldReference or Variable")
        if frs:
            return _field_ref_node_reason(frs[0], "Insert Text", require_anchor=True)
        v = vars[0]                            # a variable target: $name (value attr) + an optional dropped repetition
        if (set(v.attrib) - {"value"}) or not (v.get("value") or "").strip():
            return ("capability_unaccounted_shape", "Insert Text: the variable Target must carry a $name value")
        reps = v.findall("repetition")
        if sorted(c.tag for c in v) not in ([], ["repetition"]) or len(reps) > 1:
            return ("capability_unaccounted_shape", "Insert Text: the variable Target has an unexpected child")
    return None


def _cap_set_selection(step) -> "tuple[str, str] | None":
    """id 130 (Set Selection) — one `<Select>` container with `<Start>`/`<End>` BOTH-or-NEITHER carrying a
    calc (a lone bound refuses), plus an optional FieldReference target (anchor REQUIRED; its repetition is
    dropped) (packet 1109). Start/end + target presence are topology (the packet-1082 empty/set split); their
    calc text is content. Both/neither/duplicate bounds, a duplicate target, or unknown child/attr refuse."""
    params, reason = _step_body(step, "Set Selection")
    if reason is not None:
        return reason
    selects = [p for p in params if p.get("type") == "Select"]
    frs = [p for p in params if p.get("type") == "FieldReference"]
    if len(selects) != 1 or len(frs) > 1 or len(params) != len(selects) + len(frs):
        return ("capability_unaccounted_shape", "Set Selection accounts for one Select + an optional FieldReference")
    sel = selects[0]
    if (set(sel.attrib) - {"type"}) or (sel.text or "").strip():
        return ("capability_unaccounted_shape", "Set Selection: the parameter is not a bare type=\"Select\"")
    starts = sel.findall("Start")
    ends = sel.findall("End")
    extra = sorted({c.tag for c in sel if c.tag not in ("Start", "End")})
    if extra:
        return ("capability_unaccounted_shape", f"Set Selection: unexpected Select child(ren) {extra}")
    if len(starts) != 1 or len(ends) != 1:
        return ("capability_unaccounted_shape", "Set Selection: exactly one <Start> and one <End>")
    set_flags = []
    for node, label in ((starts[0], "Start"), (ends[0], "End")):
        if set(node.attrib):
            return ("capability_unaccounted_shape", f"Set Selection: <{label}> unexpected attribute(s)")
        if len(node):
            r = _calc_subtree_reason(node, "Set Selection", f"the {label} calculation")
            if r is not None:
                return r
            set_flags.append(True)
        else:
            set_flags.append(False)
    # packet 1129 — a lone bound (Start set / End empty, or vice-versa) emits only that <StartPosition>/
    # <EndPosition>; the emitter already writes exactly the set bound, so no both-or-neither coupling is needed.
    if frs:
        t = frs[0]
        fr_nodes = t.findall("FieldReference")
        if (set(t.attrib) - {"type"}) or len(list(t)) != 1 or len(fr_nodes) != 1:
            return ("capability_unaccounted_shape", "Set Selection: FieldReference param must hold one FieldReference")
        return _field_ref_node_reason(fr_nodes[0], "Set Selection", require_anchor=True)
    return None


# ── D — URL / Web Viewer / JavaScript (111/146/175) ──

def _cap_open_url(step) -> "tuple[str, str] | None":
    """id 111 (Open URL) — EXACTLY two Booleans in the observed order (`In external browser`, `With dialog`)
    plus a `<URL>` calculation (packet 1109). Both Boolean polarities map directly (In-external→Option, With-
    dialog→NoInteract). The URL `autoEncode` attr is metadata this step ignores; URL text is content."""
    params, reason = _step_body(step, "Open URL")
    if reason is not None:
        return reason
    if len(params) != 3:
        return ("capability_unaccounted_shape", "Open URL accounts for two Booleans + a URL calculation")
    r = _bare_boolean_reason(params[0], "In external browser", "Open URL", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    r = _bare_boolean_reason(params[1], "With dialog", "Open URL", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    u = params[2]
    if u.get("type") != "URL" or (set(u.attrib) - {"type"}) or (u.text or "").strip():
        return ("capability_unaccounted_shape", "Open URL: the third parameter is not a bare type=\"URL\"")
    unodes = u.findall("URL")
    if len(list(u)) != 1 or len(unodes) != 1 or (set(unodes[0].attrib) - {"autoEncode"}):
        return ("capability_unaccounted_shape", "Open URL: exactly one <URL> node (only autoEncode metadata)")
    return _calc_subtree_reason(unodes[0], "Open URL", "the URL calculation")


def _cap_set_web_viewer(step) -> "tuple[str, str] | None":
    """id 146 (Set Web Viewer) — an ObjectName Calculation + an `action` whose `<List name>` is a mapped mode
    in the independent `_WEBVIEWER_ACTION` authority, carrying the URL calculation (packet 1109). An unknown/
    case-variant action refuses BEFORE the emitter's dict lookup; no raw pass-through."""
    params, reason = _step_body(step, "Set Web Viewer")
    if reason is not None:
        return reason
    calcs = [p for p in params if p.get("type") == "Calculation"]
    actions = [p for p in params if p.get("type") == "action"]
    if len(calcs) != 1 or len(actions) != 1 or len(params) != 2:
        return ("capability_unaccounted_shape", "Set Web Viewer accounts for an ObjectName Calculation + an action")
    r = _typed_calc_param_reason(calcs[0], "Set Web Viewer", "the object-name calculation")
    if r is not None:
        return r
    a = actions[0]
    if (set(a.attrib) - {"type"}) or (a.text or "").strip():
        return ("capability_unaccounted_shape", "Set Web Viewer: the action is not a bare type=\"action\"")
    lists = a.findall("List")
    if len(list(a)) != 1 or len(lists) != 1 or (set(lists[0].attrib) - {"name", "value"}):
        return ("capability_unaccounted_shape", "Set Web Viewer: exactly one <List> action selector")
    if lists[0].get("name") not in _WEBVIEWER_ACTION:
        return ("webviewer_action_unmapped",
                f"Set Web Viewer: action {lists[0].get('name')!r} is not in the capability map "
                f"{sorted(_WEBVIEWER_ACTION)} — refused before the emitter's dict lookup, never passed through")
    return _calc_subtree_reason(lists[0], "Set Web Viewer", "the URL calculation")


def _cap_perform_js(step) -> "tuple[str, str] | None":
    """id 175 (Perform JavaScript in Web Viewer) — EXACTLY an ObjectName (`Name`) + a FunctionName
    (`FunctionRef`) calculation, the evidenced ZERO-argument shape (packet 1109). The fixed target
    `<Parameters Count="0"/>` is valid only here; any argument list/parameter refuses, never silently dropped."""
    params, reason = _step_body(step, "Perform JavaScript in Web Viewer")
    if reason is not None:
        return reason
    names = [p for p in params if p.get("type") == "Name"]
    funcs = [p for p in params if p.get("type") == "FunctionRef"]
    argps = [p for p in params if p.get("type") == "Parameter"]
    if len(names) != 1 or len(funcs) != 1 or len(argps) > 1 or len(params) != 2 + len(argps):
        return ("capability_unaccounted_shape",
                "Perform JavaScript accounts for a Name + a FunctionRef calculation and an OPTIONAL argument "
                "Parameter (each a calculation); an unexpected parameter is unaccounted, not silently dropped")
    r = _typed_calc_param_reason(names[0], "Perform JavaScript in Web Viewer", "the object-name calculation")
    if r is not None:
        return r
    r = _typed_calc_param_reason(funcs[0], "Perform JavaScript in Web Viewer", "the function-name calculation")
    if r is not None:
        return r
    if argps:                                  # packet 1129 — one or more JS argument calculations
        ap = argps[0]
        if (set(ap.attrib) - {"type"}) or (ap.text or "").strip():
            return ("capability_unaccounted_shape", "Perform JavaScript: the argument parameter is not a bare type=\"Parameter\"")
        calcs = ap.findall("Calculation")
        if not calcs or len(list(ap)) != len(calcs):
            return ("capability_unaccounted_shape", "Perform JavaScript: the argument parameter holds one or more calculations only")
        for c in calcs:
            if set(c.attrib) - {"datatype", "position"}:
                return ("capability_unaccounted_shape", "Perform JavaScript: an argument calculation carries unexpected attribute(s)")
            r = _wrapped_calc_reason(c, "Perform JavaScript in Web Viewer", "a JS argument calculation")
            if r is not None:
                return r
    return None


# ── E — duration + direct path (62/197) ──

_PAUSE_RESUME_MODES = frozenset({"Duration (seconds): "})   # the ONLY evidenced Pause/Resume mode


def _cap_pause_resume(step) -> "tuple[str, str] | None":
    """id 62 (Pause/Resume Script) — exactly one `<Options>` whose `type` is the evidenced duration mode
    (`_PAUSE_RESUME_MODES`) carrying its seconds calculation (packet 1109). An unknown mode refuses; a MISSING
    duration calc refuses (distinct from `_inner_text` coincidence), a present one (empty or populated text) is
    content."""
    params, reason = _step_body(step, "Pause/Resume Script")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "Options":
        return ("capability_unaccounted_shape", "Pause/Resume Script accounts for exactly one Options duration parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Pause/Resume Script: the parameter is not a bare type=\"Options\"")
    opts = p.findall("Options")
    if len(list(p)) != 1 or len(opts) != 1:
        return ("capability_unaccounted_shape", "Pause/Resume Script: exactly one <Options> node")
    o = opts[0]
    if set(o.attrib) - {"type"}:
        return ("capability_unaccounted_shape", f"Pause/Resume Script: <Options> unexpected attrs {sorted(o.attrib)}")
    if o.get("type") not in _PAUSE_RESUME_MODES:
        return ("pause_resume_mode_unmapped",
                f"Pause/Resume Script: mode {o.get('type')!r} is not the evidenced duration mode "
                f"{sorted(_PAUSE_RESUME_MODES)} — refused rather than guessing another pause mode's target")
    return _calc_subtree_reason(o, "Pause/Resume Script", "the duration calculation")


def _cap_delete_file(step) -> "tuple[str, str] | None":
    """id 197 (Delete File) — exactly one `<UniversalPathList>` → `<ObjectList>` → exactly one `<Location>`
    path (its text is content) (packet 1109). Multiple/empty/unrecognised locations, extra path options,
    unknown attrs/children, or an external DataSourceReference refuse; no path normalisation is inferred."""
    params, reason = _step_body(step, "Delete File")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "UniversalPathList":
        return ("capability_unaccounted_shape", "Delete File accounts for exactly one UniversalPathList parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Delete File: the parameter is not a bare type=\"UniversalPathList\"")
    upls = p.findall("UniversalPathList")
    if len(list(p)) != 1 or len(upls) != 1 or (set(upls[0].attrib) - {"membercount"}):
        return ("capability_unaccounted_shape", "Delete File: exactly one <UniversalPathList> node")
    ols = upls[0].findall("ObjectList")
    if len(list(upls[0])) != 1 or len(ols) != 1 or set(ols[0].attrib):
        return ("capability_unaccounted_shape", "Delete File: exactly one bare <ObjectList>")
    locs = ols[0].findall("Location")
    if len(list(ols[0])) != 1 or len(locs) != 1:
        return ("capability_unaccounted_shape",
                "Delete File: exactly one <Location> path (multiple/empty/unrecognised locations refuse)")
    if set(locs[0].attrib) or len(locs[0]):
        return ("capability_unaccounted_shape", "Delete File: <Location> must be a plain text path node")
    return None


# ── packet 1126 — the Data File I/O family (9 ids) ──────────────────────────────
#
# One bounded family grammar, separate per-step projections. Each rule validates the FULL attr/child grammar
# fail-loud before evidence, consumes every target-driving source fact, and accounts the target-absent clip
# drops (Encoding @name, the Target repetition, Read <size>, Set Position <position>) explicitly. The path
# grammar mirrors Delete File; the Target reuses _target_branch_reason (field OR variable branch); the file-id/
# byte-count/position calcs reuse _typed_calc_param_reason. Nothing is inferred from a neighbouring step. The
# empty/default Read from Data File is a RECORDED FileMaker clipboard-serializer failure and refuses by name.

def _datafile_location_reason(p, fam) -> "tuple[str, str] | None":
    """Exactly one <UniversalPathList> param → one <UniversalPathList> → one bare <ObjectList> → one plain
    <Location> path (text is content). Same grammar Delete File validates; multiple/empty/attributed nodes
    refuse. Kept standalone (not shared with _cap_delete_file) so each step's projection stays explicit."""
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the parameter is not a bare type=\"UniversalPathList\"")
    upls = p.findall("UniversalPathList")
    if len(list(p)) != 1 or len(upls) != 1 or (set(upls[0].attrib) - {"membercount"}):
        return ("capability_unaccounted_shape", f"{fam}: exactly one <UniversalPathList> node")
    ols = upls[0].findall("ObjectList")
    if len(list(upls[0])) != 1 or len(ols) != 1 or set(ols[0].attrib):
        return ("capability_unaccounted_shape", f"{fam}: exactly one bare <ObjectList>")
    locs = ols[0].findall("Location")
    if len(list(ols[0])) != 1 or len(locs) != 1 or set(locs[0].attrib) or len(locs[0]):
        return ("capability_unaccounted_shape", f"{fam}: exactly one plain <Location> path node")
    return None


def _datafile_rw_body(step, fam) -> "tuple[list, object, tuple[str, str] | None]":
    """(params, encoding, reason). Write/Read to Data File uniquely carry ONE <Encoding> sibling (type +
    optional name) ALONGSIDE the <Parameter>s under <ParameterValues>, so _step_body (which rejects a
    non-Parameter child) cannot be reused. Validates the same clean shell, then splits Parameters from the
    single required <Encoding> whose @type drives <DataSourceType>."""
    if set(step.attrib) - _TARGET_ABSENT_STEP_ATTRS:
        return [], None, ("capability_unaccounted_shape", f"{fam}: unexpected Step attribute(s) {sorted(step.attrib)}")
    r = _step_shell_bool_reason(step, fam)
    if r is not None:
        return [], None, r
    if (step.text or "").strip():
        return [], None, ("capability_unaccounted_shape", f"{fam}: loose direct text under <Step>")
    others = sorted({c.tag for c in step if c.tag != "ParameterValues" and c.tag not in _PROVENANCE_TAGS})
    if others:
        return [], None, ("capability_unaccounted_shape", f"{fam}: unexpected top-level child element(s) {others}")
    for c in step:
        if c.tag == "DDRREF":
            if (set(c.attrib) - {"kind", "hash"}) or len(c):
                return [], None, ("capability_unaccounted_shape", f"{fam}: <DDRREF> unexpected attrs/children")
        elif c.tag in _PROVENANCE_TAGS:
            if set(c.attrib) or len(c):
                return [], None, ("capability_unaccounted_shape", f"{fam}: <{c.tag}> unexpected attrs/children")
    pvs = step.findall("ParameterValues")
    if len(pvs) != 1:
        return [], None, ("capability_unaccounted_shape", f"{fam}: exactly one <ParameterValues>")
    encs = pvs[0].findall("Encoding")
    if len(encs) != 1:
        return [], None, ("capability_unaccounted_shape", f"{fam}: exactly one <Encoding> child")
    enc = encs[0]
    if (set(enc.attrib) - {"type", "name"}) or enc.get("type") is None or len(enc):
        return [], None, ("capability_unaccounted_shape", f"{fam}: <Encoding> must carry @type (+optional @name), no children")
    bad = sorted({c.tag for c in pvs[0] if c.tag not in ("Parameter", "Encoding")})
    if bad:
        return [], None, ("capability_unaccounted_shape", f"{fam}: unexpected <ParameterValues> child(ren) {bad}")
    return pvs[0].findall("Parameter"), enc, None


def _cap_datafile_path_target(step, fam) -> "tuple[str, str] | None":
    """188/189/191 — the bare base shape, OR exactly a path + a Target (field or variable). A path-only,
    target-only, or extra-parameter shape refuses (no clip evidence)."""
    params, reason = _step_body(step, fam)
    if reason is not None:
        return reason
    if not params:
        return None                                       # base (empty) shape — verified ()
    if len(params) != 2 or params[0].get("type") != "UniversalPathList" or params[1].get("type") != "Target":
        return ("capability_unaccounted_shape", f"{fam}: a path + Target, or the bare base shape")
    r = _datafile_location_reason(params[0], fam)
    if r is not None:
        return r
    return _target_branch_reason(params[1], fam)


def _cap_get_file_exists(step): return _cap_datafile_path_target(step, "Get File Exists")
def _cap_get_file_size(step):   return _cap_datafile_path_target(step, "Get File Size")
def _cap_open_data_file(step):  return _cap_datafile_path_target(step, "Open Data File")


def _cap_create_data_file(step) -> "tuple[str, str] | None":
    """190 — one 'Create folders' Boolean (base), OR a path + that Boolean (configured). The clip carries
    <CreateDirectories @state> from the Boolean; the path is <UniversalPathList> when present."""
    params, reason = _step_body(step, "Create Data File")
    if reason is not None:
        return reason
    bools = [p for p in params if p.get("type") == "Boolean"]
    paths = [p for p in params if p.get("type") == "UniversalPathList"]
    if len(bools) != 1 or len(paths) > 1 or len(paths) + len(bools) != len(params):
        return ("capability_unaccounted_shape",
                "Create Data File: one 'Create folders' Boolean, optionally preceded by a path")
    if paths:
        r = _datafile_location_reason(paths[0], "Create Data File")
        if r is not None:
            return r
    return _bare_boolean_reason(bools[0], "Create folders", "Create Data File", values=_DIRECT_BOOLEAN_VALUES)


def _cap_write_data_file(step) -> "tuple[str, str] | None":
    """192 — one 'Append line feed' Boolean + a data-source <Encoding> (required) + an OPTIONAL file-id
    Calculation + an OPTIONAL Target (field/variable). The clip drops the Encoding @name and the Target
    repetition; nothing else is admitted."""
    params, enc, reason = _datafile_rw_body(step, "Write to Data File")
    if reason is not None:
        return reason
    ids = [p for p in params if p.get("type") == "id"]
    tgts = [p for p in params if p.get("type") == "Target"]
    bools = [p for p in params if p.get("type") == "Boolean"]
    if len(bools) != 1 or len(ids) > 1 or len(tgts) > 1 or len(ids) + len(tgts) + len(bools) != len(params):
        return ("capability_unaccounted_shape",
                "Write to Data File: one 'Append line feed' Boolean + optional file-id Calculation + optional Target")
    r = _bare_boolean_reason(bools[0], "Append line feed", "Write to Data File", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    if ids:
        r = _typed_calc_param_reason(ids[0], "Write to Data File", "the file-id calculation")
        if r is not None:
            return r
    if tgts:
        return _target_branch_reason(tgts[0], "Write to Data File")
    return None


def _cap_read_data_file(step) -> "tuple[str, str] | None":
    """193 — a data-source <Encoding> (required) + OPTIONAL file-id / Target. The safe shape carries NO byte
    <size> (paste-proven idempotent, packet 1127 Stage B/D).

    Two named hazards refuse fail-closed rather than emit a materially changed step (packet 1127 Stage E):
      · no <Encoding> (empty/default form)  → recorded FileMaker clipboard-serializer crash;
      · a present source <size> (Amount)    → MATERIALLY UNREPRESENTABLE. FileMaker's native XML clipboard
        exposes ONE calculation slot for this step and omits the Amount; a captured-clip roundtrip returns
        no size, and a repeated <Calculation> overwrites the File ID rather than adding it (twice measured
        live). Emitting would silently change the read's operational meaning, so it refuses whole-script."""
    if step.find("ParameterValues/Encoding") is None:
        return ("read_from_data_file_empty_form_filemaker_failure",
                "Read from Data File: the empty/default form (no data-source Encoding) is a recorded FileMaker "
                "clipboard-serializer crash and is never generated")
    params, enc, reason = _datafile_rw_body(step, "Read from Data File")
    if reason is not None:
        return reason
    if any(p.get("type") == "size" for p in params):
        return ("read_data_file_amount_not_representable",
                "Read from Data File: the source specifies an Amount (byte count), but FileMaker's native XML "
                "clipboard has only one calculation slot for this step and omits the Amount — a captured clip "
                "drops it, a pasted generated clip returns without it, and a repeated Calculation overwrites the "
                "File ID rather than representing it. This source shape cannot be generated without silently "
                "changing the read's operational meaning, so the whole script is withheld (not a missing capture).")
    ids = [p for p in params if p.get("type") == "id"]
    tgts = [p for p in params if p.get("type") == "Target"]
    if len(ids) > 1 or len(tgts) > 1 or len(ids) + len(tgts) != len(params):
        return ("capability_unaccounted_shape",
                "Read from Data File: optional file-id / Target alongside the data-source Encoding (no Amount)")
    if ids:
        r = _typed_calc_param_reason(ids[0], "Read from Data File", "the file-id calculation")
        if r is not None:
            return r
    if tgts:
        return _target_branch_reason(tgts[0], "Read from Data File")
    return None


def _cap_get_data_file_position(step) -> "tuple[str, str] | None":
    """194 — the bare base shape, OR a file-id Calculation + a Target."""
    params, reason = _step_body(step, "Get Data File Position")
    if reason is not None:
        return reason
    if not params:
        return None
    ids = [p for p in params if p.get("type") == "id"]
    tgts = [p for p in params if p.get("type") == "Target"]
    if len(ids) != 1 or len(tgts) != 1 or len(params) != 2:
        return ("capability_unaccounted_shape",
                "Get Data File Position: a file-id Calculation + Target, or the bare base shape")
    r = _typed_calc_param_reason(ids[0], "Get Data File Position", "the file-id calculation")
    if r is not None:
        return r
    return _target_branch_reason(tgts[0], "Get Data File Position")


def _cap_set_data_file_position(step) -> "tuple[str, str] | None":
    """195 — the bare base shape, OR a file-id Calculation (no New position).

    A present source New position (`Parameter type="position"`) is MATERIALLY UNREPRESENTABLE and refuses
    fail-closed by a named hazard (packet 1127 Stage E): FileMaker's native XML clipboard has ONE calculation
    slot for this step and omits the New position — a captured clip drops it, a pasted generated clip returns
    without it, and a repeated <Calculation> overwrites the File ID rather than adding it (measured live).
    Emitting would silently change the seek's operational meaning, so the whole script is withheld."""
    params, reason = _step_body(step, "Set Data File Position")
    if reason is not None:
        return reason
    if any(p.get("type") == "position" for p in params):
        return ("set_data_file_position_not_representable",
                "Set Data File Position: the source specifies a New position, but FileMaker's native XML "
                "clipboard has only one calculation slot for this step and omits it — a captured clip drops it, "
                "a pasted generated clip returns without it, and a repeated Calculation overwrites the File ID "
                "rather than representing it. This source shape cannot be generated without silently changing "
                "the seek's operational meaning, so the whole script is withheld (not a missing capture).")
    if not params:
        return None
    if len(params) != 1 or params[0].get("type") != "id":
        return ("capability_unaccounted_shape",
                "Set Data File Position: the bare base shape or a lone file-id Calculation (no New position)")
    return _typed_calc_param_reason(params[0], "Set Data File Position", "the file-id calculation")


def _cap_close_data_file(step) -> "tuple[str, str] | None":
    """196 — the bare base shape, OR one file-id Calculation."""
    params, reason = _step_body(step, "Close Data File")
    if reason is not None:
        return reason
    if not params:
        return None
    if len(params) != 1 or params[0].get("type") != "id":
        return ("capability_unaccounted_shape", "Close Data File: one file-id Calculation, or the bare base shape")
    return _typed_calc_param_reason(params[0], "Close Data File", "the file-id calculation")


# ── packet 1110 — the bounded layout/window emitters (5 ids) ──
#
# Five already-emitting layout/window ids (Go to Layout 6, Go to Related Record 74, Move/Resize Window 119,
# New Window 122, Go to List of Records 228). Each carries a rich nested topology (LayoutReferenceContainer
# destination, layout reference/calculation, animation, WindowReference bounds/name/style/options, related
# table, new-window dispatch), so this is a five-id wave, NOT a generic reference sweep. The shared authorities
# below are independent explicit maps derived from the matched pairs — not `_VERIFIED_SIGS` slices, not
# prose→CamelCase synthesis, not arbitrary Style pass-through. Content (layout/TO names, ids, calc/name TEXT,
# bound values) is copied; TOPOLOGY (destination/payload kind, animation mode, selection/current flag, Name-
# calc presence, per-bound presence, new-window presence, style/option values) is signature-repaired so an
# uncaptured topology can never inherit a verified verdict. `VERIFIED_STEP_IDS` and the pair fixtures are
# unchanged; the three collapsed tokens (119/122 WindowReference, 74 Related) are re-spelled from the SAME
# committed pairs.

# LayoutReferenceContainer authority (ids 6/74/122). value → (clip LayoutDestination spelling, payload kind).
# 'none' = original layout, no <LayoutReference>/<Calculation> (a <Label> is source-only, ignored); 'calc' =
# name/number by calculation, exactly one calc subtree; 'reference' = selected layout, exactly one
# <LayoutReference>. The spelling MUST agree with the emitter's _GOTO_LAYOUT_DEST (guarded). Id 228 does NOT
# share this map — its value "1" maps to CurrentLayout (a DIFFERENT spelling), via _GOTO_LIST_DEST.
_LAYOUT_DEST_SPECS = {
    "1": ("OriginalLayout", "none"),
    "3": ("LayoutNameByCalc", "calc"),
    "4": ("LayoutNumberByCalc", "calc"),
    "5": ("SelectedLayout", "reference"),
}
_BOUNDS_DIMS = ("height", "width", "top", "left")
# Evidenced window-style name→Styles value (New Window / GTRR new window). An arbitrary style refuses — a
# Dialog/Floating window is a genuine capability gap (window_style_unmapped), never copied through blindly.
_WINDOW_STYLE_VALUES = {"Card": "3222274064", "Document": "1076299266"}
# packet 1129 — the evidenced New Window / GTRR-new-window style NAMES (independent of the fence). The clip
# echoes the numeric Style @value verbatim, so the name is the bounded enum and the value is content.
_WINDOW_STYLE_NAMES = frozenset({"Document", "Card", "Dialog"})
_NEWWND_OPTION_TAGS = ("Close", "Minimize", "Maximize", "Resize", "MenuBar", "Toolbar", "DimParentWindow")


def _layout_dest_reason(lrc, fam, allowed) -> "tuple[str, str] | None":
    """One `<LayoutReferenceContainer value=…>` validated against `allowed` (⊆ _LAYOUT_DEST_SPECS keys). The
    value's spec fixes the payload — 'none' carries neither ref nor calc (a <Label> is ignored), 'calc' exactly
    one calc subtree, 'reference' exactly one `<LayoutReference id name [UUID]>` (UUID dropped). Layout
    id/name/calc TEXT are content; the mode↔payload coupling is topology. A wrong/both/missing payload, a
    duplicate ref/calc, an unknown value, or an unexpected child refuses BEFORE the emitter's _GOTO_LAYOUT_DEST
    lookup (which would KeyError / silently drop)."""
    if set(lrc.attrib) - {"value"}:
        return ("capability_unaccounted_shape", f"{fam}: <LayoutReferenceContainer> unexpected attribute(s)")
    val = lrc.get("value")
    if val not in allowed:
        return ("layout_destination_unmapped",
                f"{fam}: layout destination value {val!r} is not an allowed mode {sorted(allowed)} — refused "
                "rather than inventing a destination")
    kind = _LAYOUT_DEST_SPECS[val][1]
    refs = lrc.findall("LayoutReference")
    calcs = lrc.findall("Calculation")
    extra = sorted({c.tag for c in lrc if c.tag not in ("LayoutReference", "Calculation", "Label")})
    if extra:
        return ("capability_unaccounted_shape", f"{fam}: unexpected LayoutReferenceContainer child(ren) {extra}")
    if kind == "reference":
        # A selected-layout destination carries AT MOST one <LayoutReference> (an EMPTY container — an
        # unresolved layout — is evidenced for GTRR and emits SelectedLayout with no <Layout>). No Calculation.
        if [c.tag for c in lrc] not in ([], ["LayoutReference"]):
            return ("capability_unaccounted_shape",
                    f"{fam}: a selected-layout destination carries at most one <LayoutReference> and no other child")
        if refs:
            ref = refs[0]
            if (set(ref.attrib) - {"id", "name", "UUID"}) or ref.get("id") is None or ref.get("name") is None or len(ref):
                return ("capability_unaccounted_shape",
                        f"{fam}: <LayoutReference> must carry id and name (UUID optional, dropped) and no children")
    elif kind == "calc":
        if len(refs) or len(calcs) != 1:
            return ("capability_unaccounted_shape",
                    f"{fam}: a by-calculation destination requires exactly one <Calculation> and no <LayoutReference>")
        r = _calc_subtree_reason(lrc, fam, "the layout-by-calculation")
        if r is not None:
            return r
    else:  # none
        if refs or calcs:
            return ("capability_unaccounted_shape",
                    f"{fam}: an original/current-layout destination carries neither <LayoutReference> nor "
                    "<Calculation> (its payload would be silently dropped)")
    return None


def _animation_node_reason(a, fam, *, ignored) -> "tuple[str, str] | None":
    """One `<Animation name=… value=…>` element (no children). `name` is bounded to "None" (→ no <Animation>
    element) ∪ _ANIMATION (each a PROVEN clip spelling — no prose→CamelCase guess); the numeric `value` is
    source provenance (ignored). `ignored=True` (ids 74/228, whose emitters never read the animation)
    additionally requires name="None" — a real transition would be silently dropped, so it refuses."""
    if (set(a.attrib) - {"name", "value"}) or len(a):
        return ("capability_unaccounted_shape", f"{fam}: <Animation> unexpected attrs/children")
    nm = a.get("name")
    if nm != "None" and nm not in _ANIMATION:
        return ("animation_unmapped",
                f"{fam}: animation {nm!r} has no proven clip spelling ({sorted(_ANIMATION)}) — refused rather "
                "than guessing a CamelCase target")
    if ignored and nm != "None":
        return ("capability_unaccounted_shape",
                f"{fam}: this step's emitter carries no animation, so only name=\"None\" is accounted for (got "
                f"{nm!r}) — refused rather than silently dropping the transition")
    return None


def _animation_reason(param, fam, *, ignored=False) -> "tuple[str, str] | None":
    """A bare `<Parameter type="Animation">` (ids 6/228) holding exactly one `<Animation>` node → the shared
    `_animation_node_reason`. Id 74's Animation is a direct `<Animation>` child of `Related` and validates the
    node directly."""
    if (set(param.attrib) - {"type"}) or (param.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the Animation parameter is not a bare type=\"Animation\"")
    nodes = param.findall("Animation")
    if len(list(param)) != 1 or len(nodes) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <Animation> node")
    return _animation_node_reason(nodes[0], fam, ignored=ignored)


def _bounds_reason(bounds, fam) -> "tuple[str, str] | None":
    """A `<Bounds>` node with children EXACTLY [height, width, top, left] in order; each is empty (`<height/>`
    → the dimension is omitted from the clip) or one standard calc subtree (→ the mapped <Height>/<Width>/
    <DistanceFromTop>/<DistanceFromLeft>). Calc TEXT is content; per-dimension PRESENCE is topology
    (signature-encoded). Missing/reordered/duplicate dimensions or an unexpected child/attr refuses; an empty
    dimension is accepted only as absence, never conflated with a populated one."""
    if set(bounds.attrib):
        return ("capability_unaccounted_shape", f"{fam}: <Bounds> carries unexpected attribute(s)")
    kids = list(bounds)
    if [k.tag for k in kids] != list(_BOUNDS_DIMS):
        return ("capability_unaccounted_shape",
                f"{fam}: <Bounds> must hold exactly [height, width, top, left] in order")
    for k in kids:
        if set(k.attrib):
            return ("capability_unaccounted_shape", f"{fam}: <{k.tag}> bound carries unexpected attribute(s)")
        if len(list(k)) == 0 and not (k.text or "").strip():
            continue                       # empty dimension → omitted from the clip (absence)
        r = _calc_subtree_reason(k, fam, f"the {k.tag} bound")
        if r is not None:
            return r
    return None


def _bounds_presence(bounds) -> str:
    """4-char present/absent map of [height, width, top, left] — the target-driving bound topology, matching
    `_append_bounds`'s non-empty test exactly. Content (the calc text) stays out of the signature."""
    if bounds is None:
        return "----"
    return "".join("1" if _inner_text(bounds.find(d)) != "" else "0" for d in _BOUNDS_DIMS)


def _newwnd_reason(wref, fam) -> "tuple[str, str] | None":
    """A new-window WindowReference's <Style> + <Options> → <NewWndStyles> (ids 122/74-window). Exactly one
    `<Style name=… value=…>` whose (name, value) is an EVIDENCED pair in _WINDOW_STYLE_VALUES (no arbitrary
    style pass-through), and exactly one `<Options value=…>` holding EXACTLY the seven option booleans (each
    text bounded True/False → Yes/No). The Options @value mirrors the Style value (source provenance, ignored;
    the emitter takes Styles from the Style node). Style name/value + the seven booleans are target-driving and
    signature-fingerprinted so an uncaptured combination stays experimental, not verified."""
    styles = wref.findall("Style")
    if len(styles) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <Style>")
    st = styles[0]
    if (set(st.attrib) - {"name", "value"}) or len(st):
        return ("capability_unaccounted_shape", f"{fam}: <Style> unexpected attrs/children")
    nm, vl = st.get("name"), st.get("value")
    if nm not in _WINDOW_STYLE_NAMES:
        return ("window_style_unmapped",
                f"{fam}: window style {nm!r} is not an evidenced style name {sorted(_WINDOW_STYLE_NAMES)} — refused "
                "rather than copying an arbitrary style through")
    # packet 1129 — the numeric Style @value is a packed window bitmask the clip ECHOES VERBATIM (proven across
    # four captured New Window pairs: Document/Card at two distinct values + Dialog), so it is content, not a
    # pinned enum; only its presence is required (the seven <Options> booleans below stay target-driving).
    if not (vl or "").strip().isdigit():
        return ("window_style_unmapped", f"{fam}: window style {nm!r} value {vl!r} is not a numeric bitmask")
    opts = wref.findall("Options")
    if len(opts) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <Options>")
    o = opts[0]
    if set(o.attrib) - {"value"}:
        return ("capability_unaccounted_shape", f"{fam}: <Options> unexpected attribute(s)")
    if sorted(c.tag for c in o) != sorted(_NEWWND_OPTION_TAGS):
        return ("capability_unaccounted_shape",
                f"{fam}: <Options> must hold exactly the seven window options {sorted(_NEWWND_OPTION_TAGS)}")
    for c in o:
        if set(c.attrib) or len(c) or (c.text or "").strip() not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape",
                    f"{fam}: window option <{c.tag}> must be a bare True/False flag")
    return None


def _newwnd_fingerprint(wref) -> str:
    """The target-driving NewWndStyles fingerprint: style name + the seven option-boolean states. Defensive
    (used by the signature, computed before capability validates), so a partial tree yields a stable string."""
    st = wref.find("Style")
    o = wref.find("Options")
    style = st.get("name") if st is not None else "?"

    def _flag(t):
        e = o.find(t) if o is not None else None
        return "1" if (e is not None and (e.text or "").strip() == "True") else "0"
    return f"style={style},opts={''.join(_flag(t) for t in _NEWWND_OPTION_TAGS)}"


# ── A — Go to Layout (6) ──

def _cap_goto_layout(step) -> "tuple[str, str] | None":
    """id 6 (Go to Layout) — exactly one LayoutReferenceContainer (modes 1/3/4/5, payload-coupled) + exactly
    one Animation parameter, plus an OPTIONAL Collapsed Boolean (packet 1110). Emits DisableStepCollapsed,
    LayoutDestination, optional Layout, optional Animation. A mode↔payload mismatch, unknown mode/animation, or
    a duplicate/extra parameter refuses. Captured destination/animation tuples are verified; implemented
    uncaptured cross-combinations (and any Collapsed-bearing shape) are experimental."""
    params, reason = _step_body(step, "Go to Layout")
    if reason is not None:
        return reason
    lrcs = [p for p in params if p.get("type") == "LayoutReferenceContainer"]
    anims = [p for p in params if p.get("type") == "Animation"]
    rest = [p for p in params if p.get("type") not in ("LayoutReferenceContainer", "Animation")]
    if len(lrcs) != 1 or len(anims) != 1:
        return ("capability_unaccounted_shape",
                "Go to Layout accounts for exactly one LayoutReferenceContainer and one Animation parameter")
    if len(rest) > 1:
        return ("capability_unaccounted_shape", "Go to Layout: the only optional extra parameter is a Collapsed Boolean")
    if rest:
        r = _bare_boolean_reason(rest[0], "Collapsed", "Go to Layout", values=_DIRECT_BOOLEAN_VALUES)
        if r is not None:
            return r
    p = lrcs[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Go to Layout: the LRC parameter is not a bare type=\"LayoutReferenceContainer\"")
    containers = p.findall("LayoutReferenceContainer")
    if len(list(p)) != 1 or len(containers) != 1:
        return ("capability_unaccounted_shape", "Go to Layout: exactly one <LayoutReferenceContainer>")
    r = _layout_dest_reason(containers[0], "Go to Layout", _LAYOUT_DEST_SPECS)
    if r is not None:
        return r
    return _animation_reason(anims[0], "Go to Layout")


# ── B — Go to Related Record (74) ──

def _gtrr_window_reason(wref, fam) -> "tuple[str, str] | None":
    """The GTRR new-window WindowReference: <Style>+<Options> → NewWndStyles and <Bounds> → dimensions (both
    consumed by the emitter), plus a residual <Name> and nested <LayoutReferenceContainer> that FileMaker
    regenerates and the GTRR clip does NOT carry (validated for well-formedness, then ignored — they are not
    driving facts for this step's projection). Anything else refuses (packet 1110)."""
    if set(wref.attrib):
        return ("capability_unaccounted_shape", f"{fam}: new-window <WindowReference> unexpected attribute(s)")
    extra = sorted({c.tag for c in wref if c.tag not in ("Style", "Name", "LayoutReferenceContainer", "Bounds", "Options")})
    if extra:
        return ("capability_unaccounted_shape", f"{fam}: new-window <WindowReference> unexpected child(ren) {extra}")
    boundsn = wref.findall("Bounds")
    if len(boundsn) != 1:
        return ("capability_unaccounted_shape", f"{fam}: the new window must carry exactly one <Bounds>")
    r = _bounds_reason(boundsn[0], fam)
    if r is not None:
        return r
    r = _newwnd_reason(wref, fam)
    if r is not None:
        return r
    if len(wref.findall("Name")) > 1:
        return ("capability_unaccounted_shape", f"{fam}: at most one residual window <Name>")
    nested = wref.findall("LayoutReferenceContainer")
    if len(nested) > 1:
        return ("capability_unaccounted_shape", f"{fam}: at most one residual window <LayoutReferenceContainer>")
    if nested:                             # residual, ignored — validate grammar only
        r = _layout_dest_reason(nested[0], fam, _LAYOUT_DEST_SPECS)
        if r is not None:
            return r
    return None


def _cap_goto_related(step) -> "tuple[str, str] | None":
    """id 74 (Go to Related Record) — exactly one `Related` parameter (packet 1110). Subtree: optional
    <TableOccurrenceReference> (id/name content, UUID dropped → target <Table>; absent → id 0); exactly one
    top-level <LayoutReferenceContainer> (modes 1/3/4/5, payload-coupled); optional <Animation> (ignored → must
    be None); optional <WindowReference> = the new-window branch (Style/Options → NewWndStyles, Bounds →
    dimensions; absent → FileMaker's fixed default NewWndStyles); exactly one <Options matchFoundSet=…
    ShowRelated=…> (matchFoundSet → MatchAllRecords). Target order: Option, MatchAllRecords, ShowInNewWindow,
    DisableStepCollapsed, Restore, LayoutDestination, optional Bounds, NewWndStyles, Table, optional Layout.
    Related TO id/name + layout identity/calc are content; new-window presence, destination/payload, bound
    presence, and style/options are topology. An unknown relationship kind, malformed window payload, or a
    destination/payload mismatch refuses."""
    params, reason = _step_body(step, "Go to Related Record")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "Related":
        return ("capability_unaccounted_shape", "Go to Related Record accounts for exactly one Related parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Go to Related Record: the parameter is not a bare type=\"Related\"")
    allowed = {"TableOccurrenceReference", "LayoutReferenceContainer", "Animation", "WindowReference", "Options"}
    extra = sorted({c.tag for c in p if c.tag not in allowed})
    if extra:
        return ("capability_unaccounted_shape", f"Go to Related Record: unexpected Related child(ren) {extra}")
    tos, lrcs = p.findall("TableOccurrenceReference"), p.findall("LayoutReferenceContainer")
    anims, wrefs, opts = p.findall("Animation"), p.findall("WindowReference"), p.findall("Options")
    if len(tos) > 1 or len(lrcs) != 1 or len(anims) > 1 or len(wrefs) > 1 or len(opts) != 1:
        return ("capability_unaccounted_shape",
                "Go to Related Record: optional TO, one LayoutReferenceContainer, optional Animation, optional "
                "WindowReference, one Options")
    if tos:
        to = tos[0]
        if (set(to.attrib) - {"id", "name", "UUID"}) or to.get("id") is None or to.get("name") is None or len(to):
            return ("capability_unaccounted_shape",
                    "Go to Related Record: <TableOccurrenceReference> must carry id + name (UUID dropped), no children")
    r = _layout_dest_reason(lrcs[0], "Go to Related Record", _LAYOUT_DEST_SPECS)
    if r is not None:
        return r
    if anims:
        r = _animation_node_reason(anims[0], "Go to Related Record", ignored=True)
        if r is not None:
            return r
    o = opts[0]
    if (set(o.attrib) - {"matchFoundSet", "ShowRelated"}) or len(o):
        return ("capability_unaccounted_shape", "Go to Related Record: <Options> unexpected attrs/children")
    mfs = o.get("matchFoundSet")
    if mfs is not None and mfs not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape",
                f"Go to Related Record: matchFoundSet={mfs!r} outside the FileMaker Boolean vocabulary")
    if wrefs:
        return _gtrr_window_reason(wrefs[0], "Go to Related Record")
    return None


# ── C — Move/Resize Window (119) ──

def _cap_move_resize_window(step) -> "tuple[str, str] | None":
    """id 119 (Move/Resize Window) — packet-1108's WindowReference SELECTION grammar (current or calculated-
    by-name, via `_window_select_reason` by composition — 121/123/124 unchanged) PLUS this id's <Bounds>.
    Exactly one WindowReference holding one <Select> and one <Bounds> (four optional dimensions); NO Style/
    Options/LayoutReferenceContainer/Rename/Name (the emitter consumes none of them). Window name + bound calc
    TEXT are content; selection mode, current flag, and per-dimension presence are topology (packet 1110)."""
    params, reason = _step_body(step, "Move/Resize Window")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "WindowReference":
        return ("capability_unaccounted_shape", "Move/Resize Window accounts for exactly one WindowReference parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Move/Resize Window: the parameter is not a bare type=\"WindowReference\"")
    wrefs = p.findall("WindowReference")
    if len(list(p)) != 1 or len(wrefs) != 1:
        return ("capability_unaccounted_shape", "Move/Resize Window: exactly one <WindowReference>")
    wref = wrefs[0]
    if set(wref.attrib):
        return ("capability_unaccounted_shape", "Move/Resize Window: <WindowReference> unexpected attribute(s)")
    extra = sorted({c.tag for c in wref if c.tag not in ("Select", "Bounds")})
    if extra:
        return ("capability_unaccounted_shape",
                f"Move/Resize Window: <WindowReference> unexpected child(ren) {extra} (only Select + Bounds; "
                "Style/Options/LayoutReferenceContainer/Rename are not consumed)")
    sels, boundsn = wref.findall("Select"), wref.findall("Bounds")
    if len(sels) != 1:
        return ("capability_unaccounted_shape", "Move/Resize Window: exactly one <Select>")
    r = _window_select_reason(sels[0], "Move/Resize Window")
    if r is not None:
        return r
    if len(boundsn) != 1:
        return ("capability_unaccounted_shape", "Move/Resize Window: exactly one <Bounds>")
    return _bounds_reason(boundsn[0], "Move/Resize Window")


# ── D — New Window (122) ──

def _cap_new_window(step) -> "tuple[str, str] | None":
    """id 122 (New Window) — exactly one WindowReference holding: one <Style> + <Options> (complete
    NewWndStyles grammar), one <Bounds> (four optional dims), one <LayoutReferenceContainer> (modes 1/3/4/5,
    payload-coupled), and an OPTIONAL <Name> whose present-with-<Calculation> form emits <Name> (an empty
    `<Name/>` without a calc is absent — distinguished). Emits DisableStepCollapsed, LayoutDestination, optional
    Name, Bounds, NewWndStyles, optional Layout. Name calc TEXT is content; Name-calc presence, destination/
    payload, per-dimension bound presence, and the style/options values are topology. Unknown/incomplete
    style/options, duplicate bounds/name/layout, an unsupported layout mode, or a Select/Rename child refuses
    (packet 1110)."""
    params, reason = _step_body(step, "New Window")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "WindowReference":
        return ("capability_unaccounted_shape", "New Window accounts for exactly one WindowReference parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "New Window: the parameter is not a bare type=\"WindowReference\"")
    wrefs = p.findall("WindowReference")
    if len(list(p)) != 1 or len(wrefs) != 1:
        return ("capability_unaccounted_shape", "New Window: exactly one <WindowReference>")
    wref = wrefs[0]
    if set(wref.attrib):
        return ("capability_unaccounted_shape", "New Window: <WindowReference> unexpected attribute(s)")
    extra = sorted({c.tag for c in wref if c.tag not in ("Style", "Name", "LayoutReferenceContainer", "Bounds", "Options")})
    if extra:
        return ("capability_unaccounted_shape",
                f"New Window: <WindowReference> unexpected child(ren) {extra} (a Select/Rename is not a New Window shape)")
    lrcs, boundsn, names = wref.findall("LayoutReferenceContainer"), wref.findall("Bounds"), wref.findall("Name")
    if len(lrcs) != 1:
        return ("capability_unaccounted_shape", "New Window: exactly one <LayoutReferenceContainer>")
    if len(boundsn) != 1:
        return ("capability_unaccounted_shape", "New Window: exactly one <Bounds>")
    if len(names) > 1:
        return ("capability_unaccounted_shape", "New Window: at most one <Name>")
    r = _layout_dest_reason(lrcs[0], "New Window", _LAYOUT_DEST_SPECS)
    if r is not None:
        return r
    r = _bounds_reason(boundsn[0], "New Window")
    if r is not None:
        return r
    r = _newwnd_reason(wref, "New Window")
    if r is not None:
        return r
    if names:
        nm = names[0]
        if set(nm.attrib):
            return ("capability_unaccounted_shape", "New Window: <Name> carries unexpected attribute(s)")
        if len(list(nm)) or (nm.text or "").strip():   # non-empty → must be the calc that emits <Name>
            r = _calc_subtree_reason(nm, "New Window", "the window-name calculation")
            if r is not None:
                return r
    return None


# ── E — Go to List of Records (228) ──

def _cap_goto_list(step) -> "tuple[str, str] | None":
    """id 228 (Go to List of Records) — its OWN narrow grammar (NOT id 6/122's): exactly one
    LayoutReferenceContainer whose value maps via _GOTO_LIST_DEST (only CurrentLayout, value "1") with NO layout
    payload, plus one Animation parameter that must be None (the emitter drops it). Emits ShowInNewWindow=False,
    DisableStepCollapsed, LayoutDestination=CurrentLayout, default NewWndStyles. Any layout reference/calc,
    other destination mode, WindowReference, bounds, style, or extra parameter refuses — it never receives the
    fixed defaults (packet 1110)."""
    params, reason = _step_body(step, "Go to List of Records")
    if reason is not None:
        return reason
    lrcs = [p for p in params if p.get("type") == "LayoutReferenceContainer"]
    anims = [p for p in params if p.get("type") == "Animation"]
    if len(params) != 2 or len(lrcs) != 1 or len(anims) != 1:
        return ("capability_unaccounted_shape",
                "Go to List of Records accounts for exactly one LayoutReferenceContainer and one Animation")
    p = lrcs[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Go to List of Records: the LRC parameter is not a bare type")
    containers = p.findall("LayoutReferenceContainer")
    if len(list(p)) != 1 or len(containers) != 1:
        return ("capability_unaccounted_shape", "Go to List of Records: exactly one <LayoutReferenceContainer>")
    lrc = containers[0]
    if set(lrc.attrib) - {"value"}:
        return ("capability_unaccounted_shape", "Go to List of Records: <LayoutReferenceContainer> unexpected attrs")
    if lrc.get("value") not in _GOTO_LIST_DEST:
        return ("layout_destination_unmapped",
                f"Go to List of Records: destination value {lrc.get('value')!r} is not the evidenced current-"
                f"layout mode {sorted(_GOTO_LIST_DEST)} — refused (it does NOT inherit id 6/122 modes)")
    if lrc.find("LayoutReference") is not None or lrc.find("Calculation") is not None:
        return ("capability_unaccounted_shape",
                "Go to List of Records: the current-layout destination carries no layout reference/calculation "
                "(the emitter emits no <Layout>) — a payload would be silently dropped, so it refuses")
    extra = sorted({c.tag for c in lrc if c.tag != "Label"})
    if extra:
        return ("capability_unaccounted_shape", f"Go to List of Records: unexpected LRC child(ren) {extra}")
    return _animation_reason(anims[0], "Go to List of Records", ignored=True)


# ── Signature tokens (topology repair for 119/122/74; 6/228 keep the existing LRC/Animation tokens) ──

def _move_resize_sig_token(param) -> str:
    """id 119 target-driving topology: WindowReference selection (current vs calculated-by-name + current flag)
    and per-bound presence. Window name + bound calc TEXT stay content."""
    wref = param.find("WindowReference")
    if wref is None:
        return "WindowReference"
    sel = wref.find("Select")
    if sel is None:
        base = "?"
    elif sel.get("type") == "current":
        base = "current"
    elif sel.get("type") == "Calculated":
        nm = sel.find("Name")
        base = f"byname(current={nm.get('current') if nm is not None else '?'})"
    else:
        base = f"sel={sel.get('type')}"
    return f"MoveResize:{base}|bounds={_bounds_presence(wref.find('Bounds'))}"


def _new_window_sig_token(param) -> str:
    """id 122 target-driving topology: layout destination, Name-calc presence, per-bound presence, and the
    NewWndStyles fingerprint (style + option states). Name calc TEXT + layout identity stay content."""
    wref = param.find("WindowReference")
    if wref is None:
        return "WindowReference"
    lrc = wref.find("LayoutReferenceContainer")
    dest = lrc.get("value") if lrc is not None else "?"
    nm = wref.find("Name")
    name = "calc" if (nm is not None and nm.find("Calculation") is not None) else "none"
    return (f"NewWindow:dest={dest}|name={name}|bounds={_bounds_presence(wref.find('Bounds'))}"
            f"|{_newwnd_fingerprint(wref)}")


def _goto_related_sig_token(param) -> str:
    """id 74 target-driving topology: matchFoundSet, new-window presence, layout destination, and (when a new
    window) per-bound presence + the NewWndStyles fingerprint. Related TO id/name + layout identity/calc are
    content. The first direct-child LayoutReferenceContainer is the top-level (emitter-consumed) one."""
    o = param.find("Options")
    mfs = o.get("matchFoundSet") if o is not None else None
    lrc = param.find("LayoutReferenceContainer")
    dest = lrc.get("value") if lrc is not None else "?"
    wref = param.find("WindowReference")
    base = f"GTRR:match={mfs or 'False'}|window={'present' if wref is not None else 'absent'}|dest={dest}"
    if wref is not None:
        base += f"|bounds={_bounds_presence(wref.find('Bounds'))}|{_newwnd_fingerprint(wref)}"
    return base


# ── packet 1111 — the bounded record/query/state emitters (9 ids) ──
#
# Nine already-emitting ids: record/find/sort/portal navigation (16/22/28/39/99) and control/state options
# (71/75/80/205). Two of them (28 Perform Find, 39 Sort Records) consume VARIABLE-LENGTH request/sort
# collections — iteration is not capability, so every request/criterion/sort node is validated fail-loud before
# any Query/SortList is trusted. Explicit source→target maps replace every emitter fallback (`_GOTO_RECORD_LOC`,
# `_LOOP_FLUSH`'s `.get(nm,nm)`, Perform Find's `else "Omit"`). Content (field id/name, TO name, criterion text,
# formulas) is copied; TOPOLOGY (mode, request/criteria/sort count + action/direction sequence, anchor presence,
# named-Boolean values, Restore/option source states) is signature-repaired where it collapsed.

_GOTO_RECORD_SPECS = {                              # mode → (RowPageLocation, calc-required, allowed option bools)
    "First": ("First", False, frozenset()),
    "Next": ("Next", False, frozenset({"Exit after last"})),
    "By Calculation…": ("ByCalculation", True, frozenset({"With dialog"})),
}
_FIND_REQUEST_ACTIONS = {"find": "Include", "omit": "Omit"}   # explicit — no `else Omit` fallback (find verified,
                                                             # omit capability-complete/experimental)
_SORT_DIRECTIONS = frozenset({"Ascending", "Descending"})    # a Custom/value-list sort is a different topology
_LOOP_FLUSH_MODES = {"Always": "Always", "Defer": "Defer", "Minimum": "Min"}   # identity entries EXPLICIT
_GOTO_PORTAL_MODE = "By Calculation…"               # the only evidenced Go to Portal Row mode


def _wrapped_calc_reason(cnode, fam, label) -> "tuple[str, str] | None":
    """A `<Calculation datatype position>` wrapper (attrs are metadata) holding exactly one inner
    `<Calculation>` whose children are an optional `<DDRREF>` + exactly one `<Text>` — the grammar `_inner_text`
    reads unambiguously. Used for the calc that rides INSIDE a Records/Portal List (so the outer container is
    not the calc's sole parent, unlike `_calc_subtree_reason`). Calc TEXT is content."""
    inner = cnode.findall("Calculation")
    if len(list(cnode)) != 1 or len(inner) != 1:
        return ("capability_unaccounted_shape", f"{fam}: {label} must wrap exactly one inner <Calculation>")
    other = [c.tag for c in inner[0] if c.tag not in ("DDRREF", "Text")]
    if other:
        return ("capability_unaccounted_shape", f"{fam}: {label} inner calc has unexpected child(ren) {other}")
    if len(inner[0].findall("Text")) != 1:
        return ("capability_unaccounted_shape", f"{fam}: {label} inner calc must hold exactly one <Text>")
    return None


def _find_sort_fieldref_reason(fr, fam) -> "tuple[str, str] | None":
    """A find-criterion / sort `<FieldReference>` NODE: attrs ⊆ {id, name, UUID, repetition} (id + name required
    content; UUID + repetition are source-only — the clip Criteria/PrimaryField `<Field>` carries neither),
    children an OPTIONAL `<TableOccurrenceReference>` (name → target `table`; id/UUID dropped). Anchor PRESENCE
    is topology (signature-encoded); field identity is content. A missing id/name, a duplicate/nameless anchor,
    or an unexpected child/attr refuses. (Distinct from packet 1108's `_field_ref_node_reason`, which forbids a
    `repetition` ATTRIBUTE and validates a `<repetition>` CHILD — find/sort use the attribute form.)"""
    if set(fr.attrib) - {"id", "name", "UUID", "repetition"}:
        return ("capability_unaccounted_shape", f"{fam}: <FieldReference> unexpected attribute(s) {sorted(fr.attrib)}")
    if fr.get("id") is None or fr.get("name") is None:
        return ("capability_unaccounted_shape", f"{fam}: <FieldReference> must carry id and name")
    extra = sorted({c.tag for c in fr if c.tag != "TableOccurrenceReference"})
    if extra:
        return ("capability_unaccounted_shape", f"{fam}: <FieldReference> unexpected child(ren) {extra}")
    tos = fr.findall("TableOccurrenceReference")
    if len(tos) > 1:
        return ("capability_unaccounted_shape", f"{fam}: at most one <TableOccurrenceReference> anchor")
    if tos:
        to = tos[0]
        if (set(to.attrib) - {"id", "name", "UUID"}) or to.get("name") is None or len(to):
            return ("capability_unaccounted_shape",
                    f"{fam}: <TableOccurrenceReference> must carry a name (id/UUID dropped) and no children")
    return None


def _named_booleans_reason(params, fam, required_types, *, collapsed_ok=False) -> "tuple[str, str] | None":
    """`params` must be exactly one bare bounded Boolean per type in `required_types` (a set — the emitter reads
    each by name, so ORDER is EVIDENCE, not capability; the positional signature fences a reordered shape as
    experimental), plus an optional Collapsed Boolean when `collapsed_ok`. Each value is bounded {True,False}.
    A missing/duplicate/extra/unknown Boolean, a non-Boolean parameter, or an out-of-vocabulary value refuses —
    never defaulted through `_bool_state` merely because the helper would."""
    seen = {}
    for p in params:
        if p.get("type") != "Boolean":
            return ("capability_unaccounted_shape",
                    f"{fam}: only bounded Boolean options are accounted for (got a {p.get('type')!r} parameter)")
        if (set(p.attrib) - {"type"}) or (p.text or "").strip():
            return ("capability_unaccounted_shape", f"{fam}: a Boolean parameter is not a bare type=\"Boolean\"")
        b = p.find("Boolean")
        if b is None or len(list(p)) != 1:
            return ("capability_unaccounted_shape", f"{fam}: a Boolean parameter must hold exactly one <Boolean>")
        bt = b.get("type")
        if (set(b.attrib) - {"type", "value", "id", "position"}) or len(b) or (b.text or "").strip():
            return ("capability_unaccounted_shape", f"{fam}: <Boolean type={bt!r}> carries unexpected attrs/children")
        if b.get("value") not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape",
                    f"{fam}: <Boolean type={bt!r}> value {b.get('value')!r} is outside the FileMaker vocabulary")
        if bt in seen:
            return ("capability_unaccounted_shape", f"{fam}: duplicate Boolean option {bt!r}")
        seen[bt] = b
    allowed = set(required_types) | ({"Collapsed"} if collapsed_ok else set())
    unknown = sorted(set(seen) - allowed)
    if unknown:
        return ("capability_unaccounted_shape", f"{fam}: unexpected Boolean option(s) {unknown}")
    missing = sorted(set(required_types) - set(seen))
    if missing:
        return ("capability_unaccounted_shape", f"{fam}: missing required Boolean option(s) {missing}")
    return None


# ── A — Go to Record (16) ──

def _cap_goto_record(step) -> "tuple[str, str] | None":
    """id 16 (Go to Record/Request/Page) — one `Records` parameter holding one `<List name=mode value=…>` whose
    mode maps via `_GOTO_RECORD_SPECS` (First / Next / By Calculation…). Per mode: First carries no children;
    Next allows the optional bounded `Exit after last` Boolean; By Calculation… REQUIRES exactly one calculation
    and allows the optional bounded `With dialog` Boolean. NoInteract mirrors `With dialog` (packet 1111). A
    calculation is required only for By Calculation…; formula TEXT is content, calc PRESENCE is topology. An
    unknown/case-variant mode, a mode/child mismatch, an option valid only for another mode, a duplicate
    Boolean/calc, or an extra child refuses (never a naming-convention target)."""
    params, reason = _step_body(step, "Go to Record/Request/Page")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "Records":
        return ("capability_unaccounted_shape", "Go to Record accounts for exactly one Records parameter")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Go to Record: the parameter is not a bare type=\"Records\"")
    lists = p.findall("List")
    if len(list(p)) != 1 or len(lists) != 1:
        return ("capability_unaccounted_shape", "Go to Record: exactly one <List>")
    l = lists[0]
    if set(l.attrib) - {"name", "value"}:
        return ("capability_unaccounted_shape", "Go to Record: <List> unexpected attribute(s)")
    mode = l.get("name")
    if mode not in _GOTO_RECORD_SPECS:
        return ("goto_record_mode_unmapped",
                f"Go to Record: mode {mode!r} is not an evidenced RowPageLocation {sorted(_GOTO_RECORD_SPECS)} — "
                "refused rather than forming a target by naming convention")
    _target, calc_required, allowed_bools = _GOTO_RECORD_SPECS[mode]
    extra = sorted({c.tag for c in l if c.tag not in ("Boolean", "Calculation")})
    if extra:
        return ("capability_unaccounted_shape", f"Go to Record: unexpected <List> child(ren) {extra}")
    bools, calcs = l.findall("Boolean"), l.findall("Calculation")
    seen = set()
    for b in bools:
        bt = b.get("type")
        if bt not in allowed_bools:
            return ("capability_unaccounted_shape",
                    f"Go to Record ({mode}): Boolean {bt!r} is not valid for this mode (allowed {sorted(allowed_bools)})")
        if (set(b.attrib) - {"type", "value", "id", "position"}) or len(b) or b.get("value") not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape", f"Go to Record: <Boolean type={bt!r}> malformed or out of vocabulary")
        if bt in seen:
            return ("capability_unaccounted_shape", f"Go to Record: duplicate Boolean {bt!r}")
        seen.add(bt)
    if calc_required:
        if len(calcs) != 1:
            return ("capability_unaccounted_shape", f"Go to Record ({mode}): requires exactly one calculation")
        if set(calcs[0].attrib) - {"datatype", "position"}:
            return ("capability_unaccounted_shape", "Go to Record: the calculation carries unexpected attribute(s)")
        r = _wrapped_calc_reason(calcs[0], "Go to Record", "the record calculation")
        if r is not None:
            return r
    elif calcs:
        return ("capability_unaccounted_shape", f"Go to Record ({mode}): a calculation is valid only for By Calculation…")
    return None


# ── B — Enter Find Mode (22) ──

def _cap_enter_find_mode(step) -> "tuple[str, str] | None":
    """id 22 (Enter Find Mode) — exactly one bounded `Pause` Boolean plus the optional Collapsed grammar (packet
    1111). Restore=False is a fixed target fact, not a source option. Both Pause values are capability-complete
    (captured stays verified, uncaptured recombinations experimental). A restored-request / FindRequest / Restore
    structure belongs to Perform Find and refuses here (it is not a Boolean)."""
    params, reason = _step_body(step, "Enter Find Mode")
    if reason is not None:
        return reason
    return _named_booleans_reason(params, "Enter Find Mode", {"Pause"}, collapsed_ok=True)


# ── C — Perform Find (28) ──

def _cap_perform_find(step) -> "tuple[str, str] | None":
    """id 28 (Perform Find) — TWO branches (packet 1111): no FindRequest parameter → Restore=False, no Query; one
    FindRequest parameter holding one `<FindRequestSet>` of ordered `<FindRequest action=…>` → Restore=True +
    Query. Every node is validated before any Query is trusted: FindRequestSet/FindRequest cardinality (≥1,
    never empty); each request `action` via the explicit `_FIND_REQUEST_ACTIONS` map (no fallback); ≥1 criterion
    per request, each criterion tag == the request action ({find,omit} coupling); exactly one `<FieldReference>`
    per criterion (bounded optional TO anchor); the `criteria` attribute PRESENT (its text is content). Request/
    criterion count, action sequence, criterion kind, and anchor topology are shape. An empty request set, a
    request with zero criteria, an absent `criteria` attribute, an unknown action, or a malformed reference
    refuses (iteration alone is not capability)."""
    params, reason = _step_body(step, "Perform Find")
    if reason is not None:
        return reason
    if not params:                                  # no stored requests → Restore=False, no Query
        return None
    if len(params) != 1 or params[0].get("type") != "FindRequest":
        return ("capability_unaccounted_shape", "Perform Find accounts for a single FindRequest parameter (or none)")
    p = params[0]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Perform Find: the parameter is not a bare type=\"FindRequest\"")
    sets = p.findall("FindRequestSet")
    if len(list(p)) != 1 or len(sets) != 1:
        return ("capability_unaccounted_shape", "Perform Find: exactly one <FindRequestSet>")
    frs = sets[0]
    if set(frs.attrib) - {"membercount"}:
        return ("capability_unaccounted_shape", "Perform Find: <FindRequestSet> unexpected attribute(s)")
    reqs = frs.findall("FindRequest")
    if len(list(frs)) != len(reqs) or not reqs:
        return ("capability_unaccounted_shape",
                "Perform Find: <FindRequestSet> must hold one or more <FindRequest> (an empty set is unproven)")
    for req in reqs:
        if set(req.attrib) - {"membercount", "action", "index"}:
            return ("capability_unaccounted_shape", "Perform Find: <FindRequest> unexpected attribute(s)")
        action = req.get("action")
        if action not in _FIND_REQUEST_ACTIONS:
            return ("find_request_action_unmapped",
                    f"Perform Find: request action {action!r} has no proven Query operation "
                    f"({sorted(_FIND_REQUEST_ACTIONS)}) — refused rather than falling back to Omit")
        crits = list(req)
        if not crits:
            return ("capability_unaccounted_shape",
                    "Perform Find: a request with zero criteria is unproven — refused")
        for c in crits:
            if c.tag != action:
                return ("capability_unaccounted_shape",
                        f"Perform Find: criterion <{c.tag}> does not match its request action {action!r} "
                        "(find/omit coupling) — refused")
            if set(c.attrib) - {"criteria"}:
                return ("capability_unaccounted_shape", f"Perform Find: <{c.tag}> unexpected attribute(s)")
            if "criteria" not in c.attrib:
                return ("capability_unaccounted_shape",
                        f"Perform Find: <{c.tag}> has no `criteria` attribute — the target text is unproven, refused")
            frefs = c.findall("FieldReference")
            if len(list(c)) != 1 or len(frefs) != 1:
                return ("capability_unaccounted_shape", f"Perform Find: <{c.tag}> must hold exactly one <FieldReference>")
            r = _find_sort_fieldref_reason(frefs[0], "Perform Find")
            if r is not None:
                return r
    return None


# ── D — Sort Records (39) ──

def _sort_spec_reason(param, fam) -> "tuple[str, str] | None":
    """A `<Parameter type="SortSpecification">` holding one `<SortSpecification value blanksLast maintain>` (each
    attr bounded {True,False} → the clip <SortList value/BlanksLast/Maintain>) with one `<SortList>` of ordered
    `<Sort type=direction>` entries (packet 1111). Each direction ∈ `_SORT_DIRECTIONS`; each Sort holds exactly
    one `<PrimaryField>` → one `<FieldReference>` (bounded optional TO anchor). Sort count/direction/anchor are
    topology (source order preserved byte-exactly); field identity is content. An empty SortList, an unknown
    direction, a Sort without exactly one field, or a malformed anchor refuses."""
    if (set(param.attrib) - {"type"}) or (param.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the SortSpecification parameter is not a bare type")
    ss = param.findall("SortSpecification")
    if len(list(param)) != 1 or len(ss) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <SortSpecification>")
    ssn = ss[0]
    if set(ssn.attrib) - {"value", "blanksLast", "maintain"}:
        return ("capability_unaccounted_shape", f"{fam}: <SortSpecification> unexpected attribute(s)")
    for a in ("value", "blanksLast", "maintain"):
        v = ssn.get(a)
        if v is not None and v not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape", f"{fam}: <SortSpecification {a}={v!r}> outside the Boolean vocabulary")
    sls = ssn.findall("SortList")
    if len(list(ssn)) != 1 or len(sls) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <SortList>")
    sl = sls[0]
    if set(sl.attrib) - {"membercount"}:
        return ("capability_unaccounted_shape", f"{fam}: <SortList> unexpected attribute(s)")
    sorts = sl.findall("Sort")
    if len(list(sl)) != len(sorts) or not sorts:
        return ("capability_unaccounted_shape", f"{fam}: <SortList> must hold one or more <Sort> (empty is unproven)")
    for srt in sorts:
        if set(srt.attrib) - {"type"}:
            return ("capability_unaccounted_shape", f"{fam}: <Sort> unexpected attribute(s)")
        if srt.get("type") not in _SORT_DIRECTIONS:
            return ("sort_direction_unmapped",
                    f"{fam}: sort direction {srt.get('type')!r} is not an evidenced direction "
                    f"{sorted(_SORT_DIRECTIONS)} — refused (a custom/value-list sort is a different topology)")
        pfs = srt.findall("PrimaryField")
        if len(list(srt)) != 1 or len(pfs) != 1:
            return ("capability_unaccounted_shape", f"{fam}: a <Sort> must hold exactly one <PrimaryField>")
        if set(pfs[0].attrib):
            return ("capability_unaccounted_shape", f"{fam}: <PrimaryField> carries unexpected attribute(s)")
        frefs = pfs[0].findall("FieldReference")
        if len(list(pfs[0])) != 1 or len(frefs) != 1:
            return ("capability_unaccounted_shape", f"{fam}: <PrimaryField> must hold exactly one <FieldReference>")
        r = _find_sort_fieldref_reason(frefs[0], fam)
        if r is not None:
            return r
    return None


def _cap_sort_records(step) -> "tuple[str, str] | None":
    """id 39 (Sort Records) — one bounded `With dialog` Boolean + one `<Restore value=…>` (bounded) + an OPTIONAL
    SortSpecification (packet 1111). No SortSpecification → clear-sort (NoInteract + Restore, no SortList); one
    SortSpecification → a validated ordered SortList. Restore VALUE and sort count/direction/anchor are topology
    (signature-encoded); field identity is content. A duplicate/missing With-dialog or Restore, an extra
    parameter, or a malformed sort refuses."""
    params, reason = _step_body(step, "Sort Records")
    if reason is not None:
        return reason
    bools = [p for p in params if p.get("type") == "Boolean"]
    restores = [p for p in params if p.get("type") == "Restore"]
    specs = [p for p in params if p.get("type") == "SortSpecification"]
    others = [p for p in params if p.get("type") not in ("Boolean", "Restore", "SortSpecification")]
    if others:
        return ("capability_unaccounted_shape",
                f"Sort Records: unexpected parameter type(s) {sorted({p.get('type') for p in others})}")
    if len(restores) != 1 or len(specs) > 1:
        return ("capability_unaccounted_shape",
                "Sort Records: exactly one Restore, at most one SortSpecification")
    r = _named_booleans_reason(bools, "Sort Records", {"With dialog"})
    if r is not None:
        return r
    rp = restores[0]
    if (set(rp.attrib) - {"type"}) or (rp.text or "").strip():
        return ("capability_unaccounted_shape", "Sort Records: the Restore parameter is not a bare type")
    rnodes = rp.findall("Restore")
    if len(list(rp)) != 1 or len(rnodes) != 1 or (set(rnodes[0].attrib) - {"value"}) or len(rnodes[0]):
        return ("capability_unaccounted_shape", "Sort Records: exactly one bare <Restore value=…>")
    if rnodes[0].get("value") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape", "Sort Records: <Restore value> outside the Boolean vocabulary")
    if specs:
        return _sort_spec_reason(specs[0], "Sort Records")
    return None


# ── E — Loop (71) ──

def _cap_loop(step) -> "tuple[str, str] | None":
    """id 71 (Loop) — one bounded `Collapsed` Boolean + one `<List name=mode>` whose mode maps via the explicit
    `_LOOP_FLUSH_MODES` (Always / Defer / Minimum→Min; identity entries EXPLICIT). Restore=False is a fixed
    target fact (packet 1111). An unknown/case-variant flush mode refuses `loop_flush_mode_unmapped` BEFORE the
    emitter's `.get(nm, nm)` pass-through could admit it."""
    params, reason = _step_body(step, "Loop")
    if reason is not None:
        return reason
    bools = [p for p in params if p.get("type") == "Boolean"]
    lists = [p for p in params if p.get("type") == "List"]
    if len(params) != 2 or len(bools) != 1 or len(lists) != 1:
        return ("capability_unaccounted_shape", "Loop accounts for exactly one Collapsed Boolean and one flush List")
    r = _bare_boolean_reason(bools[0], "Collapsed", "Loop", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    name, reason = _selector_list_value(lists[0], fam="Loop")
    if reason is not None:
        return reason
    if name not in _LOOP_FLUSH_MODES:
        return ("loop_flush_mode_unmapped",
                f"Loop: flush mode {name!r} is not an evidenced mode {sorted(_LOOP_FLUSH_MODES)} — refused "
                "rather than passing an unknown mode straight through")
    return None


# ── F — Go to Portal Row (99) ──

def _cap_goto_portal_row(step) -> "tuple[str, str] | None":
    """id 99 (Go to Portal Row) — the evidenced By-Calculation mode only (packet 1111): one bounded top-level
    `Select` Boolean → `<SelectAll>`, an optional Collapsed Boolean, and one `Portal` parameter whose `<List>` is
    the mapped `By Calculation…` selector holding a bounded `With dialog` Boolean (→ NoInteract) + exactly one
    required calculation. RowPageLocation is the fixed ByCalculation; calc TEXT is content. Any other portal
    mode, an absent/duplicate calculation, a misplaced Boolean, or an unknown selector refuses rather than
    receiving the fixed target."""
    params, reason = _step_body(step, "Go to Portal Row")
    if reason is not None:
        return reason
    bools = [p for p in params if p.get("type") == "Boolean"]
    portals = [p for p in params if p.get("type") == "Portal"]
    others = [p for p in params if p.get("type") not in ("Boolean", "Portal")]
    if others or len(portals) != 1:
        return ("capability_unaccounted_shape", "Go to Portal Row accounts for a Select/Collapsed Boolean and one Portal")
    # top-level Booleans: exactly one Select (required), optional Collapsed
    seen = {}
    for b in bools:
        bn = b.find("Boolean")
        if (set(b.attrib) - {"type"}) or (b.text or "").strip() or bn is None or len(list(b)) != 1:
            return ("capability_unaccounted_shape", "Go to Portal Row: a top-level Boolean is not a bare type")
        bt = bn.get("type")
        if bt not in ("Select", "Collapsed") or bt in seen or bn.get("value") not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape", f"Go to Portal Row: unexpected/duplicate top-level Boolean {bt!r}")
        seen[bt] = bn
    if "Select" not in seen:
        return ("capability_unaccounted_shape", "Go to Portal Row: the top-level Select Boolean is required")
    pl = portals[0]
    if (set(pl.attrib) - {"type"}) or (pl.text or "").strip():
        return ("capability_unaccounted_shape", "Go to Portal Row: the Portal parameter is not a bare type")
    lists = pl.findall("List")
    if len(list(pl)) != 1 or len(lists) != 1:
        return ("capability_unaccounted_shape", "Go to Portal Row: exactly one portal <List>")
    l = lists[0]
    if set(l.attrib) - {"name", "value"}:
        return ("capability_unaccounted_shape", "Go to Portal Row: portal <List> unexpected attribute(s)")
    mode = l.get("name")
    if mode in _GOTO_PORTAL_SIMPLE:            # packet 1129 — direct nav (First/Last/Next/Previous)
        extra = sorted({c.tag for c in l if c.tag != "Boolean"})
        if extra:
            return ("capability_unaccounted_shape",
                    f"Go to Portal Row ({mode}): direct nav has no calculation; unexpected child(ren) {extra}")
        exits = l.findall("Boolean")
        if mode in _GOTO_PORTAL_EXIT_MODES:
            if len(exits) > 1 or (exits and exits[0].get("type") != "Exit after last"):
                return ("capability_unaccounted_shape",
                        f"Go to Portal Row ({mode}): at most one 'Exit after last' Boolean")
            if exits and ((set(exits[0].attrib) - {"type", "value", "id", "position"})
                          or exits[0].get("value") not in _DIRECT_BOOLEAN_VALUES):
                return ("capability_unaccounted_shape", "Go to Portal Row: the 'Exit after last' Boolean is malformed")
        elif exits:
            return ("capability_unaccounted_shape", f"Go to Portal Row ({mode}): no Boolean is valid for this mode")
        return None
    if mode != _GOTO_PORTAL_MODE:
        return ("goto_portal_mode_unmapped",
                f"Go to Portal Row: portal mode {mode!r} is not an evidenced mode "
                f"{sorted(list(_GOTO_PORTAL_SIMPLE) + [_GOTO_PORTAL_MODE])}")
    extra = sorted({c.tag for c in l if c.tag not in ("Boolean", "Calculation")})
    if extra:
        return ("capability_unaccounted_shape", f"Go to Portal Row: unexpected portal <List> child(ren) {extra}")
    wds = l.findall("Boolean")
    if len(wds) != 1 or wds[0].get("type") != "With dialog":
        return ("capability_unaccounted_shape", "Go to Portal Row: the portal List holds exactly one 'With dialog' Boolean")
    if (set(wds[0].attrib) - {"type", "value", "id", "position"}) or wds[0].get("value") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape", "Go to Portal Row: the portal 'With dialog' Boolean is malformed")
    calcs = l.findall("Calculation")
    if len(calcs) != 1:
        return ("capability_unaccounted_shape", "Go to Portal Row: exactly one required portal calculation")
    if set(calcs[0].attrib) - {"datatype", "position"}:
        return ("capability_unaccounted_shape", "Go to Portal Row: the portal calculation carries unexpected attribute(s)")
    return _wrapped_calc_reason(calcs[0], "Go to Portal Row", "the portal calculation")


# ── G — Commit / Refresh / Open Transaction (75/80/205) ──

def _cap_commit_records(step) -> "tuple[str, str] | None":
    """id 75 (Commit Records/Requests) — exactly the three bounded named Booleans `With dialog` (→ NoInteract),
    `Skip data entry validation` (→ Option), `Force Commit` (→ ESSForceCommit) (packet 1111). Each required and
    bounded; a missing/duplicate/extra/unknown option refuses (never defaulted through `_bool_state`)."""
    params, reason = _step_body(step, "Commit Records/Requests")
    if reason is not None:
        return reason
    return _named_booleans_reason(params, "Commit Records/Requests",
                                  {"With dialog", "Skip data entry validation", "Force Commit"})


def _cap_refresh_window(step) -> "tuple[str, str] | None":
    """id 80 (Refresh Window) — exactly the two bounded named Booleans `Flush cached join results` (→ Option) and
    `Flush cached external data` (→ FlushSQLData) (packet 1111)."""
    params, reason = _step_body(step, "Refresh Window")
    if reason is not None:
        return reason
    return _named_booleans_reason(params, "Refresh Window",
                                  {"Flush cached join results", "Flush cached external data"})


def _cap_open_transaction(step) -> "tuple[str, str] | None":
    """id 205 (Open Transaction) — the three bounded named Booleans `Skip data entry validation` (→ Option),
    `Override ESS locking conflicts` (→ ESSForceCommit), `Skip auto-enter options` (→ SkipAutoEntry), plus the
    optional Collapsed grammar; Restore=False is a fixed target fact (packet 1111)."""
    params, reason = _step_body(step, "Open Transaction")
    if reason is not None:
        return reason
    return _named_booleans_reason(params, "Open Transaction",
                                  {"Skip data entry validation", "Override ESS locking conflicts",
                                   "Skip auto-enter options"}, collapsed_ok=True)


# ── Signature tokens (topology repair for 28/39/99; scoped in `_step_signature`) ──

def _perform_find_sig_token(param) -> str:
    """id 28 target-driving topology: per-request action + per-criterion anchor presence (which drives the clip
    `<Field table>`), in source order. Field identity + criterion text stay content."""
    frs = param.find("FindRequestSet")
    reqs = frs.findall("FindRequest") if frs is not None else []
    parts = []
    for r in reqs:
        flags = "".join("A" if c.find("FieldReference/TableOccurrenceReference") is not None else "n"
                        for c in r if c.tag in ("find", "omit"))
        parts.append(f"{r.get('action')}:{flags}")
    return "Find:" + ",".join(parts)


def _sort_spec_sig_token(param) -> str:
    """id 39 target-driving topology: the effective SortList option attrs (value/blanksLast/maintain, defaults
    applied to match the emitter) + per-sort direction and anchor presence, in source order. Field identity
    stays content."""
    ss = param.find("SortSpecification")
    if ss is None:
        return "SortSpec:"
    opts = f"{ss.get('value') or 'True'},{ss.get('blanksLast') or 'False'},{ss.get('maintain') or 'False'}"
    sl = ss.find("SortList")
    sorts = sl.findall("Sort") if sl is not None else []
    seq = ",".join((s.get("type") or "?")
                   + ("@A" if s.find(".//FieldReference/TableOccurrenceReference") is not None else "@n")
                   + (":VL" if s.find(".//ValueListReference") is not None else "")
                   for s in sorts)
    return f"SortSpec:{opts}|{seq}"


def _portal_sig_token(param) -> str:
    """id 99 target-driving topology: the portal mode + the inner `With dialog` value (→ NoInteract). Calc TEXT
    stays content."""
    l = param.find("List")
    if l is None:
        return "Portal:?"
    wd = l.find("Boolean[@type='With dialog']")
    return f"Portal:{l.get('name')}[With dialog={wd.get('value') if wd is not None else 'None'}]"


# ── packet 1112 — the bounded Print/PDF emitters (7 ids) ──
#
# Print Setup 42, Print 43, Save Records as PDF 144, Create PDF 243, Append PDF 244, Close PDF 245, Open PDF
# 246. These are rich option grammars, NOT permission-by-iteration: every Document/Pages/Security/View node
# and every path/password/create-folder node is validated fail-loud before any clip is trusted. The epoch's
# THREE questions stay independent (packet governing distinction): capability (does the emitter consume this
# grammar?), evidence (a committed pair?), and PROJECTION COMPLETENESS (does the source hold everything the
# target needs?). Print Setup's populated shape stays registered SOURCE-INCOMPLETE (generated_static_valid) —
# a capability rule accepting its grammar does NOT make it experimental or verified (the assessment order
# checks _VERIFIED_SIGS then _SOURCE_INCOMPLETE_SIGS then experimental). Explicit value authorities replace
# every emitter lookup/fallback: _PRINT_TYPE, the _PDF_* enum maps, _PDF_SOURCE, _PDF_SAVE_TYPE, plus the two
# below. Paths, names, formula/metadata/password TEXT, and field identity are CONTENT; destination branch,
# option/security/view enums, password presence, page/all topology, and completeness state are SHAPE.

_PDF_FILE_SOURCE = frozenset({"File"})              # Open/Append (From) + Close (SaveTo): only File is implemented
_PAGE_ORIENTATION = frozenset({"Portrait", "Landscape"})   # PageSetup orientation (42/43)


def _pagesetup_node(ps_param, fam):
    """(ps_node | None, reason | None). The `<Parameter type="PageSetup">` holds ZERO or ONE `<PageSetup>`: a
    missing or childless node is the EMPTY (fully reproducible, no <PageFormat>) case → (None, None); a
    populated node → (node, None) for the caller to validate; anything else → (None, reason) (packet 1112)."""
    if (set(ps_param.attrib) - {"type"}) or (ps_param.text or "").strip():
        return None, ("capability_unaccounted_shape", f"{fam}: the PageSetup parameter is not a bare type")
    nodes = ps_param.findall("PageSetup")
    if len(list(ps_param)) != len(nodes) or len(nodes) > 1:
        return None, ("capability_unaccounted_shape", f"{fam}: at most one <PageSetup> node")
    if not nodes:
        return None, None
    ps = nodes[0]
    if len(ps) == 0 and not (ps.text or "").strip():
        if set(ps.attrib):
            return None, ("capability_unaccounted_shape", f"{fam}: an empty <PageSetup> carries no attributes")
        return None, None
    return ps, None


def _page_setup_reason(ps, fam) -> "tuple[str, str] | None":
    """A POPULATED `<PageSetup>` — exactly `<Orientation name value/>` (name ∈ _PAGE_ORIENTATION), one
    `<size height width/>` (source-HELD-but-unimplemented — present, not emitted), one `<scale value/>` (the
    percent → ScaleFactor, content). No other attrs/children (packet 1112). An unknown orientation, a missing
    node, or an unexpected child refuses rather than being flattened."""
    if set(ps.attrib):
        return ("capability_unaccounted_shape", f"{fam}: <PageSetup> carries unexpected attribute(s)")
    if sorted(c.tag for c in ps) != ["Orientation", "scale", "size"]:
        return ("capability_unaccounted_shape",
                f"{fam}: a populated <PageSetup> is exactly [Orientation, size, scale]")
    o = ps.find("Orientation")
    if (set(o.attrib) - {"name", "value"}) or len(o):
        return ("capability_unaccounted_shape", f"{fam}: <Orientation> unexpected attrs/children")
    if o.get("name") not in _PAGE_ORIENTATION:
        return ("page_setup_orientation_unmapped",
                f"{fam}: page orientation {o.get('name')!r} is not an evidenced orientation "
                f"{sorted(_PAGE_ORIENTATION)} — refused")
    sz = ps.find("size")
    if (set(sz.attrib) - {"height", "width"}) or len(sz):
        return ("capability_unaccounted_shape", f"{fam}: <size> unexpected attrs/children")
    sc = ps.find("scale")
    if (set(sc.attrib) - {"value"}) or len(sc):
        return ("capability_unaccounted_shape", f"{fam}: <scale> unexpected attrs/children")
    return None


def _pdf_pathlist_reason(param, fam) -> "tuple[str, str] | None":
    """A `<Parameter type="UniversalPathList">` → one `<UniversalPathList>` (its `AutoOpen`/`CreateMail` attrs
    are 144-File options the emitter reads) → one `<ObjectList>` → exactly one `<Location>` plain-text path
    (content) (packet 1112). Multiple/ambiguous locations, missing nodes, loose text, or unknown attrs/children
    refuse — the emitter first-matches the Location, so every node it relies on is required here."""
    if (set(param.attrib) - {"type"}) or (param.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the UniversalPathList parameter is not a bare type")
    upls = param.findall("UniversalPathList")
    if len(list(param)) != 1 or len(upls) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <UniversalPathList> node")
    upl = upls[0]
    if set(upl.attrib) - {"membercount", "AutoOpen", "CreateMail"}:
        return ("capability_unaccounted_shape", f"{fam}: <UniversalPathList> unexpected attribute(s)")
    ols = upl.findall("ObjectList")
    if len(list(upl)) != 1 or len(ols) != 1 or set(ols[0].attrib):
        return ("capability_unaccounted_shape", f"{fam}: exactly one bare <ObjectList>")
    locs = ols[0].findall("Location")
    if len(list(ols[0])) != 1 or len(locs) != 1:
        return ("capability_unaccounted_shape",
                f"{fam}: exactly one <Location> path (multiple/ambiguous locations refuse)")
    if set(locs[0].attrib) or len(locs[0]):
        return ("capability_unaccounted_shape", f"{fam}: <Location> must be a plain text path node")
    return None


def _pdf_security_reason(sec, fam) -> "tuple[str, str] | None":
    """A `<Security>` subtree — EXACTLY the six children Open/Control/Print/Edit/EnableCopying/AllowScreenReader
    (packet 1112). Open/Control: a bounded `value` (→ requireOpen/ControlPassword) COUPLED to a Password calc
    (value=True requires exactly one `<Parameter type="Password">`, value=False forbids it). Print/Edit map by
    NAME via _PDF_CONTROL_PRINTING/_PDF_CONTROL_EDITING (an unmapped name refuses). EnableCopying/AllowScreenReader
    are bounded values. Password TEXT is content."""
    if set(sec.attrib):
        return ("capability_unaccounted_shape", f"{fam}: <Security> carries unexpected attribute(s)")
    if sorted(c.tag for c in sec) != ["AllowScreenReader", "Control", "Edit", "EnableCopying", "Open", "Print"]:
        return ("capability_unaccounted_shape",
                f"{fam}: <Security> must hold exactly Open/Control/Print/Edit/EnableCopying/AllowScreenReader")
    for tag in ("Open", "Control"):
        node = sec.find(tag)
        if set(node.attrib) - {"value"} or node.get("value") not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape", f"{fam}: <{tag}> must carry a bounded value")
        pw = node.findall("Parameter")
        if len(list(node)) != len(pw):
            return ("capability_unaccounted_shape", f"{fam}: <{tag}> may hold only a <Parameter type=\"Password\">")
        if node.get("value") == "True":
            if len(pw) != 1 or pw[0].get("type") != "Password":
                return ("pdf_security_password_coupling",
                        f"{fam}: <{tag} value=\"True\"> requires exactly one Password calculation")
            r = _typed_calc_param_reason(pw[0], fam, f"the {tag} password")
            if r is not None:
                return r
        elif pw:
            return ("pdf_security_password_coupling",
                    f"{fam}: <{tag} value=\"False\"> must carry no Password (the coupling is source-driven)")
    for tag, mp, code in (("Print", _PDF_CONTROL_PRINTING, "pdf_control_printing_unmapped"),
                          ("Edit", _PDF_CONTROL_EDITING, "pdf_control_editing_unmapped")):
        node = sec.find(tag)
        if (set(node.attrib) - {"name", "value"}) or len(node):
            return ("capability_unaccounted_shape", f"{fam}: <{tag}> unexpected attrs/children")
        if node.get("name") not in mp:
            return (code, f"{fam}: {tag} permission {node.get('name')!r} is not an evidenced value "
                          f"{sorted(mp)} — refused rather than a lookup miss")
    for tag in ("EnableCopying", "AllowScreenReader"):
        node = sec.find(tag)
        if (set(node.attrib) - {"value"}) or len(node) or node.get("value") not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape", f"{fam}: <{tag}> must be a bounded value flag")
    return None


def _pdf_view_reason(view, fam) -> "tuple[str, str] | None":
    """A `<View>` subtree — EXACTLY show/Layout/Magnification, each mapped by NAME via _PDF_VIEW_SHOW/
    _PDF_VIEW_LAYOUT/_PDF_VIEW_MAGNIFICATION (an unmapped value refuses, never a lookup miss) (packet 1112)."""
    if set(view.attrib):
        return ("capability_unaccounted_shape", f"{fam}: <View> carries unexpected attribute(s)")
    if sorted(c.tag for c in view) != ["Layout", "Magnification", "show"]:
        return ("capability_unaccounted_shape", f"{fam}: <View> must hold exactly show/Layout/Magnification")
    for tag, mp, code in (("show", _PDF_VIEW_SHOW, "pdf_view_show_unmapped"),
                          ("Layout", _PDF_VIEW_LAYOUT, "pdf_view_layout_unmapped"),
                          ("Magnification", _PDF_VIEW_MAGNIFICATION, "pdf_view_magnification_unmapped")):
        node = view.find(tag)
        if (set(node.attrib) - {"name", "value"}) or len(node):
            return ("capability_unaccounted_shape", f"{fam}: <{tag}> unexpected attrs/children")
        if node.get("name") not in mp:
            return (code, f"{fam}: view {tag} {node.get('name')!r} is not an evidenced value {sorted(mp)} — refused")
    return None


def _pdf_document_reason(doc, fam, *, allow_calcs) -> "tuple[str, str] | None":
    """A `<Document>` subtree — its children are `<Parameter type=…>` calcs with type ∈
    {Title, Subject, Author, Keywords} (243, `allow_calcs`); 144's Document is EMPTY (`allow_calcs` False)
    (packet 1112). Calc TEXT is content; a duplicate/unknown type, or any calc on 144's Document, refuses."""
    if set(doc.attrib):
        return ("capability_unaccounted_shape", f"{fam}: <Document> carries unexpected attribute(s)")
    ps = doc.findall("Parameter")
    if len(list(doc)) != len(ps):
        return ("capability_unaccounted_shape", f"{fam}: <Document> holds only <Parameter> children")
    if ps and not allow_calcs:
        return ("capability_unaccounted_shape", f"{fam}: this Document is empty in the implemented grammar")
    seen = set()
    for p in ps:
        t = p.get("type")
        if t not in ("Title", "Subject", "Author", "Keywords"):
            return ("capability_unaccounted_shape", f"{fam}: <Document> unexpected metadata type {t!r}")
        if t in seen:
            return ("capability_unaccounted_shape", f"{fam}: duplicate <Document> metadata {t!r}")
        seen.add(t)
        r = _typed_calc_param_reason(p, fam, f"the {t} calculation")
        if r is not None:
            return r
    return None


def _pdf_pages_reason(pages, fam) -> "tuple[str, str] | None":
    """144's `<Pages>` (a SIBLING of Document) — exactly one `<Parameter type="from">` calc (→ NumberFrom;
    text content) and one `<Include All=…>`. The emitter HARDCODES the clip's AllPages="True", so only
    `All="True"` is accounted for; a range (`All="False"`) would be silently emitted as all-pages and refuses
    (packet 1112)."""
    if set(pages.attrib):
        return ("capability_unaccounted_shape", f"{fam}: <Pages> carries unexpected attribute(s)")
    if sorted(c.tag for c in pages) != ["Include", "Parameter"]:
        return ("capability_unaccounted_shape", f"{fam}: <Pages> must hold exactly a from-<Parameter> and <Include>")
    frm = pages.find("Parameter")
    if frm.get("type") != "from":
        return ("capability_unaccounted_shape", f"{fam}: <Pages> Parameter must be type=\"from\"")
    r = _typed_calc_param_reason(frm, fam, "the page-from calculation")
    if r is not None:
        return r
    inc = pages.find("Include")
    if (set(inc.attrib) - {"All"}) or len(inc):
        return ("capability_unaccounted_shape", f"{fam}: <Include> unexpected attrs/children")
    if inc.get("All") != "True":
        return ("pdf_page_range_unsupported",
                f"{fam}: only Include All=\"True\" is implemented (the emitter hardcodes AllPages) — a page "
                "range would be silently emitted as all-pages, so it refuses")
    return None


def _restore_param_reason(params, fam):
    """(restore_param, None) or (None, reason) — exactly one `<Parameter type="Restore"><Restore value=…>` with
    a bounded value. The value flows through to the clip <Restore state>; its bare `Restore` sig token is left
    unchanged (single-valued in all Print/PDF evidence, and shared with 143 — kept byte-identical)."""
    restores = [p for p in params if p.get("type") == "Restore"]
    if len(restores) != 1:
        return None, ("capability_unaccounted_shape", f"{fam}: exactly one Restore parameter")
    rp = restores[0]
    rns = rp.findall("Restore")
    if (set(rp.attrib) - {"type"}) or (rp.text or "").strip() or len(list(rp)) != 1 or len(rns) != 1:
        return None, ("capability_unaccounted_shape", f"{fam}: the Restore parameter is malformed")
    if (set(rns[0].attrib) - {"value"}) or len(rns[0]) or rns[0].get("value") not in _DIRECT_BOOLEAN_VALUES:
        return None, ("capability_unaccounted_shape", f"{fam}: <Restore value> outside the Boolean vocabulary")
    return rp, None


# ── A — Print Setup (42) ──

def _cap_print_setup(step) -> "tuple[str, str] | None":
    """id 42 (Print Setup) — one Restore + one `With dialog` Boolean (+ optional Collapsed) + one PageSetup
    (packet 1112). EMPTY PageSetup → fully reproducible (verified/experimental by evidence). POPULATED PageSetup
    → source-incomplete: only the registered no-dialog shape is sanctioned (→ generated_static_valid via
    _SOURCE_INCOMPLETE_SIGS); a populated with-dialog shape is an UNREGISTERED source-incomplete form and
    refuses rather than emitting a clip that falsely implies correctness (it still lacks Paper*/PlatformData).
    Orientation/scale are emitted; paper size is source-held-unimplemented; printer geometry is source-absent —
    never inferred."""
    params, reason = _step_body(step, "Print Setup")
    if reason is not None:
        return reason
    _rp, r = _restore_param_reason(params, "Print Setup")
    if r is not None:
        return r
    bools = [p for p in params if p.get("type") == "Boolean"]
    pss = [p for p in params if p.get("type") == "PageSetup"]
    others = [p for p in params if p.get("type") not in ("Restore", "Boolean", "PageSetup")]
    if others or len(pss) != 1:
        return ("capability_unaccounted_shape", "Print Setup accounts for Restore, a With-dialog Boolean, and PageSetup")
    r = _named_booleans_reason(bools, "Print Setup", {"With dialog"}, collapsed_ok=True)
    if r is not None:
        return r
    ps, r = _pagesetup_node(pss[0], "Print Setup")
    if r is not None:
        return r
    if ps is None:
        return None                                    # empty → fully reproducible
    wd = next((b.find("Boolean") for b in bools if b.find("Boolean") is not None
               and b.find("Boolean").get("type") == "With dialog"), None)
    if wd is None or wd.get("value") != "False":
        return ("print_setup_populated_source_incomplete",
                "Print Setup: a populated Page Setup is source-incomplete (the clip's <PageFormat> needs "
                "Paper*/PlatformData the DDR never holds); only the registered no-dialog shape is sanctioned to "
                "generate its schema-held minimum. A with-dialog populated shape refuses rather than emitting a "
                "clip that would falsely imply correctness-by-construction.")
    return _page_setup_reason(ps, "Print Setup")


# ── B — Print (43) ──

def _cap_print(step) -> "tuple[str, str] | None":
    """id 43 (Print) — one Restore + one `With dialog` Boolean (+ optional Collapsed) + one Print + one
    PageSetup (packet 1112). The Print subtree: `name` ∈ _PRINT_TYPE, bounded `toFile`, exactly one `<Pages
    All=…/>` (bounded; a page RANGE — extra attrs/children — refuses, the emitter reads only @All), an optional
    `<Copies value/>` (a copied number → content). PageSetup is emitter-IGNORED residue (validated well-formed).
    Print type + toFile + Pages/@All are shape (signature-repaired); copies + calc text are content."""
    params, reason = _step_body(step, "Print")
    if reason is not None:
        return reason
    _rp, r = _restore_param_reason(params, "Print")
    if r is not None:
        return r
    bools = [p for p in params if p.get("type") == "Boolean"]
    prints = [p for p in params if p.get("type") == "Print"]
    pss = [p for p in params if p.get("type") == "PageSetup"]
    others = [p for p in params if p.get("type") not in ("Restore", "Boolean", "Print", "PageSetup")]
    if others or len(prints) != 1 or len(pss) != 1:
        return ("capability_unaccounted_shape", "Print accounts for Restore, a With-dialog Boolean, Print, and PageSetup")
    r = _named_booleans_reason(bools, "Print", {"With dialog"}, collapsed_ok=True)
    if r is not None:
        return r
    pr_param = prints[0]
    if (set(pr_param.attrib) - {"type"}) or (pr_param.text or "").strip():
        return ("capability_unaccounted_shape", "Print: the Print parameter is not a bare type")
    prs = pr_param.findall("Print")
    if len(list(pr_param)) != 1 or len(prs) != 1:
        return ("capability_unaccounted_shape", "Print: exactly one <Print> node")
    pr = prs[0]
    if set(pr.attrib) - {"name", "type", "toFile"}:
        return ("capability_unaccounted_shape", "Print: <Print> unexpected attribute(s)")
    if pr.get("name") not in _PRINT_TYPE:
        return ("print_type_unmapped",
                f"Print: print type {pr.get('name')!r} is not an evidenced type {sorted(_PRINT_TYPE)} — refused")
    if pr.get("toFile") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape", f"Print: toFile={pr.get('toFile')!r} outside the Boolean vocabulary")
    if sorted({c.tag for c in pr}) not in ([], ["Pages"], ["Copies", "Pages"]):
        return ("capability_unaccounted_shape", f"Print: unexpected <Print> child(ren) {sorted({c.tag for c in pr})}")
    pgs = pr.findall("Pages")
    if len(pgs) != 1:
        return ("capability_unaccounted_shape", "Print: exactly one <Pages>")
    pg = pgs[0]
    if (set(pg.attrib) - {"All"}) or len(pg):
        return ("pdf_page_range_unsupported",
                "Print: only <Pages All=…/> is implemented; a page range (from/to) is dropped by the emitter, so it refuses")
    if pg.get("All") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape", "Print: <Pages All> outside the Boolean vocabulary")
    cps = pr.findall("Copies")
    if len(cps) > 1 or (cps and ((set(cps[0].attrib) - {"value"}) or len(cps[0]))):
        return ("capability_unaccounted_shape", "Print: at most one <Copies value=…/>")
    # PageSetup is emitter-ignored residue — validate it is a well-formed empty/populated node
    ps, r = _pagesetup_node(pss[0], "Print")
    if r is not None:
        return r
    if ps is not None:
        return _page_setup_reason(ps, "Print")
    return None


# ── C — Open / Append / Close PDF (246/244/245) ──

def _cap_open_append_pdf(step) -> "tuple[str, str] | None":
    """ids 244 (Append PDF) + 246 (Open PDF) — the implemented File branch (packet 1112): an OPTIONAL
    `PDFPassword` calc (→ OpenPassword; text content), one `<UniversalPathList>` path, one bounded `Create
    folders` Boolean, and one `<From>` List whose mode ∈ _PDF_FILE_SOURCE (File only). A Target / other source
    has no usable path in the DDR and refuses `pdf_source_mode_unsupported` rather than borrowing the File
    target. Path/password text is content."""
    params, reason = _step_body(step, "Open/Append PDF")
    if reason is not None:
        return reason
    pws = [p for p in params if p.get("type") == "PDFPassword"]
    upls = [p for p in params if p.get("type") == "UniversalPathList"]
    bools = [p for p in params if p.get("type") == "Boolean"]
    froms = [p for p in params if p.get("type") == "From"]
    others = [p for p in params if p.get("type") not in ("PDFPassword", "UniversalPathList", "Boolean", "From")]
    if others or len(upls) != 1 or len(bools) != 1 or len(froms) != 1 or len(pws) > 1:
        return ("capability_unaccounted_shape",
                "Open/Append PDF accounts for optional PDFPassword, one path, one Create-folders Boolean, one From")
    name, r = _selector_list_value(froms[0], fam="Open/Append PDF")
    if r is not None:
        return r
    if name not in _PDF_FILE_SOURCE:
        return ("pdf_source_mode_unsupported",
                f"Open/Append PDF: source mode {name!r} is not the implemented File branch {sorted(_PDF_FILE_SOURCE)} — "
                "a Target/other source has no usable path in the DDR; refused (no invented path, no borrowed target)")
    r = _bare_boolean_reason(bools[0], "Create folders", "Open/Append PDF", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    r = _pdf_pathlist_reason(upls[0], "Open/Append PDF")
    if r is not None:
        return r
    if pws:
        r = _typed_calc_param_reason(pws[0], "Open/Append PDF", "the PDF password")
        if r is not None:
            return r
    return None


def _cap_close_pdf(step) -> "tuple[str, str] | None":
    """id 245 (Close PDF) — the implemented File branch (packet 1112): one `<UniversalPathList>` path, one
    bounded `Create folders` Boolean, and one `<SaveTo>` List whose mode ∈ _PDF_FILE_SOURCE (File only). A
    non-File save-to refuses `pdf_source_mode_unsupported`."""
    params, reason = _step_body(step, "Close PDF")
    if reason is not None:
        return reason
    upls = [p for p in params if p.get("type") == "UniversalPathList"]
    bools = [p for p in params if p.get("type") == "Boolean"]
    savetos = [p for p in params if p.get("type") == "SaveTo"]
    others = [p for p in params if p.get("type") not in ("UniversalPathList", "Boolean", "SaveTo")]
    if others or len(upls) != 1 or len(bools) != 1 or len(savetos) != 1:
        return ("capability_unaccounted_shape",
                "Close PDF accounts for one path, one Create-folders Boolean, and one SaveTo")
    name, r = _selector_list_value(savetos[0], fam="Close PDF")
    if r is not None:
        return r
    if name not in _PDF_FILE_SOURCE:
        return ("pdf_source_mode_unsupported",
                f"Close PDF: save-to mode {name!r} is not the implemented File branch {sorted(_PDF_FILE_SOURCE)} — refused")
    r = _bare_boolean_reason(bools[0], "Create folders", "Close PDF", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    return _pdf_pathlist_reason(upls[0], "Close PDF")


# ── D — Create PDF (243) and Save Records as PDF (144) ──

def _cap_create_pdf(step) -> "tuple[str, str] | None":
    """id 243 (Create PDF) — in-memory PDF: one Restore + one `<Options>` (NO type) holding EXACTLY
    Document(calcs) + Security(passwords) + View (packet 1112). The base/empty Options refuses by a named
    underdetermined hazard (its clip carries a full non-default config the DDR does not hold — no PDF defaults
    are synthesized). Title/Subject/Author/Keywords + passwords are content; the security/view enums are shape."""
    params, reason = _step_body(step, "Create PDF")
    if reason is not None:
        return reason
    _rp, r = _restore_param_reason(params, "Create PDF")
    if r is not None:
        return r
    opts = [p for p in params if p.get("type") == "Options"]
    others = [p for p in params if p.get("type") not in ("Restore", "Options")]
    if others or len(opts) != 1:
        return ("capability_unaccounted_shape", "Create PDF accounts for exactly Restore and one Options")
    op_param = opts[0]
    if (set(op_param.attrib) - {"type"}) or (op_param.text or "").strip():
        return ("capability_unaccounted_shape", "Create PDF: the Options parameter is not a bare type")
    onodes = op_param.findall("Options")
    if len(list(op_param)) != 1 or len(onodes) != 1:
        return ("capability_unaccounted_shape", "Create PDF: exactly one <Options> node")
    o = onodes[0]
    if set(o.attrib):
        return ("capability_unaccounted_shape", "Create PDF: the in-memory <Options> carries no attributes")
    if sorted(c.tag for c in o) != ["Document", "Security", "View"]:
        return ("pdf_options_underdetermined",
                "Create PDF: the Options must hold Document + Security + View; the base/empty form does not "
                "determine the configured clip (its non-default config is source-absent) — refused, no defaults synthesized")
    r = _pdf_document_reason(o.find("Document"), "Create PDF", allow_calcs=True)
    if r is not None:
        return r
    r = _pdf_security_reason(o.find("Security"), "Create PDF")
    if r is not None:
        return r
    return _pdf_view_reason(o.find("View"), "Create PDF")


def _cap_save_records_as_pdf(step) -> "tuple[str, str] | None":
    """id 144 (Save Records as PDF) — one Restore + one `<Options type=record-source>` (Document EMPTY + Pages
    sibling + Security(no pw) + View) + a `<SaveResult>` whose mode ∈ _PDF_SAVE_TYPE, dispatched to exactly one
    destination branch (packet 1112): File (UniversalPathList + With-dialog/Append/Create-folders Booleans),
    Target (a `<Target>` FieldReference, no Booleans/path), or Append/Currently-open-PDF (neither). The record
    source ∈ _PDF_SOURCE. A mixed/underdetermined destination payload, an unknown source, or a malformed option
    refuses; a File default is never generalized into Target/Append. Path/field identity/text is content."""
    params, reason = _step_body(step, "Save Records as PDF")
    if reason is not None:
        return reason
    _rp, r = _restore_param_reason(params, "Save Records as PDF")
    if r is not None:
        return r
    opts = [p for p in params if p.get("type") == "Options"]
    saveresults = [p for p in params if p.get("type") == "SaveResult"]
    upls = [p for p in params if p.get("type") == "UniversalPathList"]
    tgts = [p for p in params if p.get("type") == "Target"]
    bools = [p for p in params if p.get("type") == "Boolean"]
    others = [p for p in params if p.get("type") not in
              ("Restore", "Options", "SaveResult", "UniversalPathList", "Target", "Boolean")]
    if others or len(opts) != 1 or len(saveresults) != 1:
        return ("capability_unaccounted_shape", "Save Records as PDF accounts for Restore, Options, and SaveResult")
    sr_name, r = _selector_list_value(saveresults[0], fam="Save Records as PDF")
    if r is not None:
        return r
    if sr_name not in _PDF_SAVE_TYPE:
        return ("pdf_save_type_unmapped",
                f"Save Records as PDF: save type {sr_name!r} is not an evidenced type {sorted(_PDF_SAVE_TYPE)} — refused")
    op_param = opts[0]
    if (set(op_param.attrib) - {"type"}) or (op_param.text or "").strip():
        return ("capability_unaccounted_shape", "Save Records as PDF: the Options parameter is not a bare type")
    onodes = op_param.findall("Options")
    if len(list(op_param)) != 1 or len(onodes) != 1:
        return ("capability_unaccounted_shape", "Save Records as PDF: exactly one <Options> node")
    o = onodes[0]
    if set(o.attrib) - {"type", "value"}:
        return ("capability_unaccounted_shape", "Save Records as PDF: <Options> unexpected attribute(s)")
    if o.get("type") not in _PDF_SOURCE:
        return ("pdf_record_source_unmapped",
                f"Save Records as PDF: record source {o.get('type')!r} is not an evidenced source "
                f"{sorted(_PDF_SOURCE)} — refused")
    if sorted(c.tag for c in o) != ["Document", "Pages", "Security", "View"]:
        return ("pdf_options_underdetermined",
                "Save Records as PDF: the Options must hold Document + Pages + Security + View")
    r = _pdf_document_reason(o.find("Document"), "Save Records as PDF", allow_calcs=False)
    if r is not None:
        return r
    r = _pdf_pages_reason(o.find("Pages"), "Save Records as PDF")
    if r is not None:
        return r
    r = _pdf_security_reason(o.find("Security"), "Save Records as PDF")
    if r is not None:
        return r
    r = _pdf_view_reason(o.find("View"), "Save Records as PDF")
    if r is not None:
        return r
    save_type = _PDF_SAVE_TYPE[sr_name]
    if save_type == "File":
        if tgts or len(upls) != 1:
            return ("pdf_mixed_destination",
                    "Save Records as PDF (File): the File branch carries exactly one UniversalPathList and no Target")
        r = _named_booleans_reason(bools, "Save Records as PDF (File)",
                                   {"With dialog", "Append to existing PDF", "Create folders"})
        if r is not None:
            return r
        return _pdf_pathlist_reason(upls[0], "Save Records as PDF (File)")
    if save_type == "Target":
        if upls or bools or len(tgts) != 1:
            return ("pdf_mixed_destination",
                    "Save Records as PDF (Target): the Target branch carries exactly one Target field and no path/Booleans")
        tp = tgts[0]
        if (set(tp.attrib) - {"type"}) or (tp.text or "").strip():
            return ("capability_unaccounted_shape", "Save Records as PDF: the Target parameter is not a bare type")
        frefs = tp.findall("FieldReference")
        if len(list(tp)) != 1 or len(frefs) != 1:
            return ("capability_unaccounted_shape", "Save Records as PDF (Target): exactly one <FieldReference>")
        return _field_ref_node_reason(frefs[0], "Save Records as PDF (Target)")
    # Append / Currently open PDF — neither a path nor a target
    if upls or tgts or bools:
        return ("pdf_mixed_destination",
                "Save Records as PDF (Append): the currently-open-PDF branch carries no path, Target, or Booleans")
    return None


# ── packet 1113 — script invocation + account operations (8 ids) ──
#
# Eight already-emitting ids in two explicitly SEPARATE subfamilies. They share calc/reference validation
# infrastructure ONLY where the node grammar is genuinely identical (the standard calc subtree, a bare bounded
# Boolean, a current-file DataSourceReference); they share NO enum values, defaults, permission, or semantics.
#
# A — Perform Script (1) / Perform Script on Server (164): a shared script-selection validator
# (_script_selection_reason) enforces the two implemented modes with an EXPLICIT per-mode spec — From list =
# one <ScriptReference> (id/name content, UUID dropped), no calc; By name = one name <Calculation>, no
# reference. A <DataSourceReference> (external-file script) refuses; both/neither/duplicate refuse; a mode is
# never inferred from child presence. The optional Parameter block is audited independently
# (_script_parameter_reason → absent/empty/populated). PER-ID facts: id 1 emits CurrentScript=Pause and DROPS
# the by-name parameter (only the empty-param projection is proven), so a by-name POPULATED parameter refuses
# rather than silently discard it; id 164 keeps the parameter in BOTH modes and carries the bounded
# Wait-for-completion Boolean → <WaitForCompletion @state> (both values direct). The Parameter present-empty/
# present-populated topology is signature-repaired for 1/164 (a by-name empty step must not borrow the by-name
# populated verified tuple).
#
# B/C/D/E — account operations (83/134/135/136/137/138): narrowly-shared helpers for the exact repeated
# structures — the standard calc subtree (_typed_calc_param_reason), a privilege-set reference
# (_privilege_set_reason), the current-file DataSourceReference (_data_source_current_reason, packet 1108), and
# bounded Booleans. Each id has a DEDICATED predicate with its exact independent grammar; AccountType and the
# enable operation are INDEPENDENT literal maps (_ADD_ACCOUNT_TYPES, _ENABLE_ACCOUNT_OPERATIONS), never a
# Boolean/List @name raw pass-through and never a fence slice. An unknown account type, an operation name/value
# mismatch, an external Re-Login reference, or an out-of-vocabulary Boolean refuses by a NAMED reason. Account
# names, password formula text, and privilege/reference id/name are content (topology is constant). Credential
# values are NEVER logged/echoed — refusal messages name the STRUCTURE, not the secret.

_PERFORM_SCRIPT_SIG_IDS = frozenset({"1", "164"})
_SCRIPT_SELECTION = {"From list": ("1", "reference"), "By name": ("2", "calc")}


def _script_selection_reason(p, fam) -> "tuple[str, str] | None":
    """The shared bounded script-selection <Parameter type="List"> for Perform Script (1) / on Server (164):
    exactly one <List name value> whose name is an implemented mode (_SCRIPT_SELECTION), value coupled to the
    mode. From list → exactly one <ScriptReference id name [UUID]> (id/name content, UUID dropped), no calc;
    By name → exactly one wrapped name <Calculation>, no reference. A <DataSourceReference> (external-file
    script target) refuses by a stable external-file reason; both/neither/duplicate/misplaced refuse."""
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the selection parameter is not a bare type=\"List\"")
    lists = p.findall("List")
    if len(list(p)) != 1 or len(lists) != 1:
        return ("capability_unaccounted_shape", f"{fam}: the selection parameter must hold exactly one <List>")
    l = lists[0]
    nm = l.get("name")
    spec = _SCRIPT_SELECTION.get(nm)
    if spec is None:
        return ("script_selection_mode_unmapped",
                f"{fam}: script-selection mode {nm!r} is not an implemented mode {sorted(_SCRIPT_SELECTION)} — "
                "refused rather than inferring a mode from child presence")
    exp_value, kind = spec
    if set(l.attrib) - {"name", "value"}:
        return ("capability_unaccounted_shape", f"{fam}: the <List> carries unexpected attribute(s) {sorted(l.attrib)}")
    if l.get("value") not in (None, exp_value):
        return ("capability_unaccounted_shape",
                f"{fam}: selection mode {nm!r} carries value {l.get('value')!r}, not the coupled {exp_value!r}")
    if l.findall("DataSourceReference"):
        return ("external_file_reference_unsupported",
                f"{fam}: the script selection carries a <DataSourceReference> (an external-file script target); the "
                "clip needs a file/path fact the DDR does not supply, so it refuses rather than inventing one")
    refs = l.findall("ScriptReference")
    calcs = l.findall("Calculation")
    if kind == "reference":
        if len(list(l)) != 1 or len(refs) != 1 or calcs:
            return ("capability_unaccounted_shape",
                    f"{fam}: From-list selection must hold exactly one <ScriptReference> (and no name Calculation)")
        r = refs[0]
        if (set(r.attrib) - {"id", "name", "UUID"}) or r.get("id") is None or r.get("name") is None or len(r):
            return ("capability_unaccounted_shape",
                    f"{fam}: <ScriptReference> must carry id + name (UUID dropped) and no children")
        return None
    if len(list(l)) != 1 or len(calcs) != 1 or refs:
        return ("capability_unaccounted_shape",
                f"{fam}: By-name selection must hold exactly one name <Calculation> (and no <ScriptReference>)")
    return _wrapped_calc_reason(calcs[0], fam, "script-name calculation")


def _script_parameter_reason(p, fam) -> "tuple[str, tuple[str, str] | None]":
    """(presence, reason) for the optional <Parameter type="Parameter"> block. presence ∈ {"empty","set"}: the
    inner <Parameter> is empty (no calc → the clip carries NO <Calculation>) or wraps exactly one script-
    parameter <Calculation> (→ the clip's <Calculation>). Validates the COMPLETE subtree before the emitter's
    _inner_text reads it. Formula text is content; parameter-element presence is shape (signature-repaired)."""
    if p.get("type") != "Parameter" or (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return "empty", ("capability_unaccounted_shape", f"{fam}: the parameter block is not a bare type=\"Parameter\"")
    inners = p.findall("Parameter")
    if len(list(p)) != 1 or len(inners) != 1:
        return "empty", ("capability_unaccounted_shape",
                         f"{fam}: the parameter block must hold exactly one inner <Parameter>")
    inner = inners[0]
    if set(inner.attrib) or (inner.text or "").strip():
        return "empty", ("capability_unaccounted_shape", f"{fam}: the inner <Parameter> carries unexpected attrs/text")
    calcs = inner.findall("Calculation")
    if not calcs:
        if len(list(inner)):
            return "empty", ("capability_unaccounted_shape",
                             f"{fam}: an empty script parameter must have no children")
        return "empty", None
    if len(list(inner)) != 1 or len(calcs) != 1:
        return "set", ("capability_unaccounted_shape",
                       f"{fam}: a populated script parameter holds exactly one <Calculation>")
    return "set", _wrapped_calc_reason(calcs[0], fam, "script parameter calculation")


def _perform_script_param_presence(p) -> str:
    inner = p.find("Parameter")
    return "set" if (inner is not None and inner.find("Calculation") is not None) else "empty"


def _cap_perform_script(step) -> "tuple[str, str] | None":
    """id 1 — a script-selection List + a Parameter block (CurrentScript=Pause is a fixed target fact). The
    by-name POPULATED parameter refuses: the emitter does not project a parameter in by-name mode and no matched
    pair proves FileMaker keeps it, so it is refused rather than silently dropped. Server-only wait behaviour is
    NOT transferred to this id."""
    params, reason = _step_body(step, "Perform Script")
    if reason is not None:
        return reason
    if len(params) != 2 or params[0].get("type") != "List" or params[1].get("type") != "Parameter":
        return ("capability_unaccounted_shape",
                "Perform Script accounts for a script-selection List + a Parameter block")
    r = _script_selection_reason(params[0], "Perform Script")
    if r is not None:
        return r
    presence, r = _script_parameter_reason(params[1], "Perform Script")
    if r is not None:
        return r
    if params[0].find("List").get("name") == "By name" and presence == "set":
        return ("perform_script_by_name_parameter_dropped",
                "Perform Script: by-name mode with a populated script parameter — this id's emitter does not "
                "project the parameter in by-name mode and no matched pair proves FileMaker keeps it, so the step "
                "refuses rather than silently discarding the parameter")
    return None


def _cap_perform_script_server(step) -> "tuple[str, str] | None":
    """id 164 — a script-selection List + a Parameter block (kept in BOTH modes) + a bounded Wait-for-completion
    Boolean → <WaitForCompletion @state> (both values map directly, established independently of fixture
    membership)."""
    params, reason = _step_body(step, "Perform Script on Server")
    if reason is not None:
        return reason
    if (len(params) != 3 or params[0].get("type") != "List" or params[1].get("type") != "Parameter"
            or params[2].get("type") != "Boolean"):
        return ("capability_unaccounted_shape",
                "Perform Script on Server accounts for a script-selection List + a Parameter block + a "
                "'Wait for completion' Boolean")
    r = _script_selection_reason(params[0], "Perform Script on Server")
    if r is not None:
        return r
    _, r = _script_parameter_reason(params[1], "Perform Script on Server")
    if r is not None:
        return r
    return _bare_boolean_reason(params[2], "Wait for completion", "Perform Script on Server",
                                values=_DIRECT_BOOLEAN_VALUES)


# ── B — shared account calc/reference nodes ──

def _privilege_set_reason(p, fam) -> "tuple[str, str] | None":
    """One <Parameter type="PrivilegeSetReference"> holding exactly one <PrivilegeSetReference id name> (no
    children). id/name are content; the DDR "<unknown>" name → the clip's empty name at THIS proven site only
    (_unknown_to_empty). A duplicate/extra structure or a missing id/name refuses."""
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the parameter is not a bare type=\"PrivilegeSetReference\"")
    refs = p.findall("PrivilegeSetReference")
    if len(list(p)) != 1 or len(refs) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <PrivilegeSetReference> node")
    r = refs[0]
    if (set(r.attrib) - {"id", "name"}) or len(r):
        return ("capability_unaccounted_shape",
                f"{fam}: <PrivilegeSetReference> unexpected attrs/children ({sorted(r.attrib)})")
    if r.get("id") is None or r.get("name") is None:
        return ("capability_unaccounted_shape", f"{fam}: <PrivilegeSetReference> must carry id and name")
    return None


# ── C — Change Password (83) ──

def _cap_change_password(step) -> "tuple[str, str] | None":
    """id 83 — exactly one Old calc, one New calc, one bounded With-dialog Boolean, in that order (the emitter
    reads OldPassword then NewPassword and maps With-dialog=False → NoInteract=True). A missing/duplicate/
    misordered Old or New, an extra account operand, or an unknown Boolean value refuses."""
    params, reason = _step_body(step, "Change Password")
    if reason is not None:
        return reason
    if len(params) != 3 or params[0].get("type") != "Old" or params[1].get("type") != "New":
        return ("capability_unaccounted_shape",
                "Change Password accounts for an Old calc + a New calc + a 'With dialog' Boolean, in that order")
    r = _typed_calc_param_reason(params[0], "Change Password", "Old-password calculation")
    if r is not None:
        return r
    r = _typed_calc_param_reason(params[1], "Change Password", "New-password calculation")
    if r is not None:
        return r
    return _bare_boolean_reason(params[2], "With dialog", "Change Password", values=_DIRECT_BOOLEAN_VALUES)


# ── D — Add / Delete / Reset / Enable Account (134–137) ──

# Explicit identity map (only FileMaker is proven); External/OAuth/… account types have no matched pair and
# refuse `add_account_type_unmapped`. Independent of the fence — never a `_VERIFIED_SIGS` slice.
_ADD_ACCOUNT_TYPES = {"FileMaker": "FileMaker"}

# (enable Boolean @name, @value) → clip AccountOperation, from BOTH captured enable states. The name↔value
# coupling is enforced so a mismatched pair refuses rather than passing @name through. Independent literal map.
_ENABLE_ACCOUNT_OPERATIONS = {("Activate", "True"): "Activate", ("Deactivate", "False"): "Deactivate"}


def _cap_add_account(step) -> "tuple[str, str] | None":
    """id 134 — AccountType (explicit _ADD_ACCOUNT_TYPES map) + Name calc + Password calc + one
    PrivilegeSetReference + a bounded 'Expire password' Boolean, in that order. An unknown account type refuses
    by name rather than passing the List @name through as an AccountType."""
    params, reason = _step_body(step, "Add Account")
    if reason is not None:
        return reason
    if (len(params) != 5 or params[0].get("type") != "AccountType" or params[1].get("type") != "Name"
            or params[2].get("type") != "Password" or params[3].get("type") != "PrivilegeSetReference"):
        return ("capability_unaccounted_shape",
                "Add Account accounts for AccountType + Name + Password + PrivilegeSetReference + a Boolean")
    at, r = _selector_list_value(params[0], fam="Add Account")
    if r is not None:
        return r
    if at not in _ADD_ACCOUNT_TYPES:
        return ("add_account_type_unmapped",
                f"Add Account: account type {at!r} is not a matched mapping {sorted(_ADD_ACCOUNT_TYPES)} — refused "
                "rather than passing the List @name through as an AccountType")
    r = _typed_calc_param_reason(params[1], "Add Account", "account-name calculation")
    if r is not None:
        return r
    r = _typed_calc_param_reason(params[2], "Add Account", "password calculation")
    if r is not None:
        return r
    r = _privilege_set_reason(params[3], "Add Account")
    if r is not None:
        return r
    return _bare_boolean_reason(params[4], "Expire password", "Add Account", values=_DIRECT_BOOLEAN_VALUES)


def _cap_delete_account(step) -> "tuple[str, str] | None":
    """id 135 — exactly one account-name Calculation (fixed no-Restore target). An extra account operand or
    Boolean refuses."""
    params, reason = _step_body(step, "Delete Account")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "Calculation":
        return ("capability_unaccounted_shape", "Delete Account accounts for exactly one account-name Calculation")
    return _typed_calc_param_reason(params[0], "Delete Account", "account-name calculation")


def _cap_reset_password(step) -> "tuple[str, str] | None":
    """id 136 — Name calc + Password calc + a bounded 'Password' (change-on-next-login) Boolean, in that order.
    No AddAccount / privilege structure."""
    params, reason = _step_body(step, "Reset Account Password")
    if reason is not None:
        return reason
    if len(params) != 3 or params[0].get("type") != "Name" or params[1].get("type") != "Password":
        return ("capability_unaccounted_shape",
                "Reset Account Password accounts for a Name calc + a Password calc + a 'Password' Boolean")
    r = _typed_calc_param_reason(params[0], "Reset Account Password", "account-name calculation")
    if r is not None:
        return r
    r = _typed_calc_param_reason(params[1], "Reset Account Password", "password calculation")
    if r is not None:
        return r
    return _bare_boolean_reason(params[2], "Password", "Reset Account Password", values=_DIRECT_BOOLEAN_VALUES)


def _cap_enable_account(step) -> "tuple[str, str] | None":
    """id 137 — one account-name Calculation + a bounded enable Boolean whose (name, value) is an EXPLICIT
    source→target operation (_ENABLE_ACCOUNT_OPERATIONS, both captured states). A mismatched name/value or an
    unknown operation refuses rather than passing the Boolean @name through as an AccountOperation."""
    params, reason = _step_body(step, "Enable Account")
    if reason is not None:
        return reason
    if len(params) != 2 or params[0].get("type") != "Calculation" or params[1].get("type") != "Boolean":
        return ("capability_unaccounted_shape",
                "Enable Account accounts for an account-name Calculation + an 'enable' Boolean")
    r = _typed_calc_param_reason(params[0], "Enable Account", "account-name calculation")
    if r is not None:
        return r
    p = params[1]
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", "Enable Account: the second parameter is not a bare type=\"Boolean\"")
    bs = p.findall("Boolean")
    if len(list(p)) != 1 or len(bs) != 1 or bs[0].get("type") != "enable":
        return ("capability_unaccounted_shape", "Enable Account: exactly one type=\"enable\" Boolean")
    b = bs[0]
    if (set(b.attrib) - {"type", "name", "value", "id"}) or len(b) or (b.text or "").strip():
        return ("capability_unaccounted_shape",
                f"Enable Account: the enable Boolean carries unexpected attrs/children ({sorted(b.attrib)})")
    key = (b.get("name"), b.get("value"))
    if key not in _ENABLE_ACCOUNT_OPERATIONS:
        return ("enable_account_operation_unmapped",
                f"Enable Account: enable (name={b.get('name')!r}, value={b.get('value')!r}) is not a matched "
                f"source→target operation {sorted(_ENABLE_ACCOUNT_OPERATIONS)} — refused rather than passing the "
                "Boolean @name through")
    return None


# ── E — Re-Login (138) ──

def _cap_relogin(step) -> "tuple[str, str] | None":
    """id 138 — the implemented CURRENT-FILE grammar: one current-file DataSourceReference (packet 1108's
    _data_source_current_reason; an external/unresolved reference refuses external_file_reference_unsupported) +
    a bounded With-dialog Boolean (→ NoInteract) + a Name calc + a Password calc, in that order."""
    params, reason = _step_body(step, "Re-Login")
    if reason is not None:
        return reason
    if (len(params) != 4 or params[0].get("type") != "DataSourceReference"
            or params[2].get("type") != "Name" or params[3].get("type") != "Password"):
        return ("capability_unaccounted_shape",
                "Re-Login accounts for a DataSourceReference + a 'With dialog' Boolean + a Name calc + a Password calc")
    r = _data_source_current_reason(params[0], "Re-Login")
    if r is not None:
        return r
    r = _bare_boolean_reason(params[1], "With dialog", "Re-Login", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    r = _typed_calc_param_reason(params[2], "Re-Login", "account-name calculation")
    if r is not None:
        return r
    return _typed_calc_param_reason(params[3], "Re-Login", "password calculation")


# ── packet 1114 — AI-service configuration + communication (5 ids) ──
#
# Five already-emitting service/communication ids. Configuration and message content may hold secrets/private
# data, but capability/reporting depends ONLY on structure + bounded enums — no secret value ever enters a
# reason string, feedback, log, test name, or fixture. Every nested branch is validated fail-loud BEFORE
# evidence; a verified `_email_fingerprint` / emitter loop / raw fallback is never proof of complete grammar.

# A — Configure Machine Learning Model (202). Explicit source→target operation map (replaces `.capitalize()`
# as permission); only `uninstall` (→ <Operation>Uninstall) has a fully implemented target structure. Other
# operations carry payloads the emitter does not consume → refuse.
_COREML_OPERATIONS = {"uninstall": "Uninstall"}


def _cap_configure_coreml(step) -> "tuple[str, str] | None":
    """id 202 — exactly one bounded operation selector (`_COREML_OPERATIONS`) + one required name Calculation,
    in that order. An unknown/case-variant operation refuses `coreml_operation_unmapped` (never `.capitalize()`);
    a missing/duplicate name or an operation-specific payload not consumed by the emitter refuses."""
    params, reason = _step_body(step, "Configure Machine Learning Model")
    if reason is not None:
        return reason
    if len(params) != 2 or params[0].get("type") != "operation" or params[1].get("type") != "name":
        return ("capability_unaccounted_shape",
                "Configure Machine Learning Model accounts for an operation selector + a name Calculation")
    op, r = _selector_list_value(params[0], fam="Configure Machine Learning Model")
    if r is not None:
        return r
    if op not in _COREML_OPERATIONS:
        return ("coreml_operation_unmapped",
                f"Configure Machine Learning Model: operation {op!r} is not a matched mapping "
                f"{sorted(_COREML_OPERATIONS)} — refused rather than emitting a `.capitalize()` guess or a "
                "shape whose operation-specific payload the emitter does not consume")
    return _typed_calc_param_reason(params[1], "Configure Machine Learning Model", "model-name calculation")


# B — Configure AI Account (212). Explicit provider map (_LLM_PROVIDER) + endpoint coupling
# (_LLM_ENDPOINT_PROVIDERS); SSL is orthogonal to provider (the Options-bit proof on _emit_configure_ai_account).

def _cap_configure_ai_account(step) -> "tuple[str, str] | None":
    """id 212 — a bounded Verify-SSL Boolean + a provider selector (`_LLM_PROVIDER`) + one API-key calc + (for
    the Custom branch ONLY) one endpoint calc + one account-name calc, in the evidenced order. SSL is
    orthogonal to provider (emit-if-True/omit-if-False). Endpoint is REQUIRED for Custom and FORBIDDEN
    otherwise. An unseen provider (`llm_provider_unmapped`), a stray/absent endpoint, an unknown Boolean value,
    or a mismatched order refuses before any raw pass-through."""
    params, reason = _step_body(step, "Configure AI Account")
    if reason is not None:
        return reason
    if len(params) not in (4, 5) or params[0].get("type") != "Boolean" or params[1].get("type") != "List":
        return ("capability_unaccounted_shape",
                "Configure AI Account accounts for a Verify-SSL Boolean + provider List + credential calcs")
    r = _bare_boolean_reason(params[0], "Verify SSL Certificates", "Configure AI Account",
                             values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    prov, r = _selector_list_value(params[1], fam="Configure AI Account")
    if r is not None:
        return r
    if prov not in _LLM_PROVIDER:
        return ("llm_provider_unmapped",
                f"Configure AI Account: provider {prov!r} is not a matched mapping {sorted(_LLM_PROVIDER)} — "
                "refused rather than passing the List @name through as an LLMType")
    wants_endpoint = prov in _LLM_ENDPOINT_PROVIDERS
    expected = (["LLMAPIKey", "LLMEndpoint", "LLMAccountName"] if wants_endpoint
                else ["LLMAPIKey", "LLMAccountName"])
    rest = params[2:]
    if [p.get("type") for p in rest] != expected:
        return ("capability_unaccounted_shape",
                f"Configure AI Account: provider {prov!r} requires credential params {expected} in order "
                "(endpoint is present exactly for the Custom branch and forbidden otherwise)")
    labels = {"LLMAPIKey": "API-key calculation", "LLMEndpoint": "endpoint calculation",
              "LLMAccountName": "account-name calculation"}
    for p in rest:
        r = _typed_calc_param_reason(p, "Configure AI Account", labels[p.get("type")])
        if r is not None:
            return r
    return None


# C — Configure RAG Account (227). Its OWN credential/SSL grammar — NOT the LLM provider structure.

def _cap_configure_rag_account(step) -> "tuple[str, str] | None":
    """id 227 — a bounded Verify-SSL Boolean (state emitted directly) + one RAG API-key calc + one RAG
    account-name calc, in that order. Rejects any provider/endpoint node from id 212, a missing/duplicate
    credential, an unknown Boolean, or an unconsumed RAG option."""
    params, reason = _step_body(step, "Configure RAG Account")
    if reason is not None:
        return reason
    if (len(params) != 3 or params[0].get("type") != "Boolean" or params[1].get("type") != "RAGAPIKey"
            or params[2].get("type") != "RAGAccountName"):
        return ("capability_unaccounted_shape",
                "Configure RAG Account accounts for a Verify-SSL Boolean + a RAG API-key calc + a RAG "
                "account-name calc (no provider/endpoint node)")
    r = _bare_boolean_reason(params[0], "Verify SSL Certificates", "Configure RAG Account",
                             values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    r = _typed_calc_param_reason(params[1], "Configure RAG Account", "RAG API-key calculation")
    if r is not None:
        return r
    return _typed_calc_param_reason(params[2], "Configure RAG Account", "RAG account-name calculation")


# D — Send Mail (63). A COMPLETE fail-loud validator for the whole Email subtree and its three modes; the
# existing `_email_fingerprint` is evidence discrimination, NOT capability authority. Explicit crypto/provider
# maps reuse `_SMTP_ENCRYPTION`/`_SMTP_AUTH`/`_OAUTH_PROVIDER` (the emitter's own authorities).
_MAIL_DIALOG_TYPES = frozenset({"With dialog", "No dialog"})
_MAIL_SMTP_TEXT_FIELDS = ("Name", "Email", "ReplyTo", "Server", "Port", "UserName", "Password")
_MAIL_OAUTH_EMPTY_FIELDS = ("Name", "Email", "ReplyTo", "PrivateKey", "UserID", "ServiceAccount")


def _mail_wrapped_calc_child_reason(node, fam, label) -> "tuple[str, str] | None":
    """A recipient/field node whose calc payload is a single `<Calculation datatype position>` wrapper (the
    emitter's emit-if-calc-present contract). `extra_ok` children are validated separately by the caller."""
    calcs = node.findall("Calculation")
    if len(calcs) != 1:
        return ("capability_unaccounted_shape", f"{fam}: {label} must hold exactly one <Calculation> wrapper")
    return _wrapped_calc_reason(calcs[0], fam, label)


def _mail_recipient_reason(node, fam, tag) -> "tuple[str, str] | None":
    """A <To>/<CC>/<BCC>: an OPTIONAL <CollectAddresses value> (bounded) + at most one <Calculation> wrapper;
    the clip emits the recipient only when the calc is present. No other child/text. Address text is content."""
    cas = node.findall("CollectAddresses")
    if len(cas) > 1:
        return ("capability_unaccounted_shape", f"{fam}: <{tag}> at most one <CollectAddresses>")
    if cas:
        ca = cas[0]
        if (set(ca.attrib) - {"value"}) or len(ca) or ca.get("value") not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape",
                    f"{fam}: <{tag}> <CollectAddresses> must carry a bounded value and no children")
    extra = sorted({c.tag for c in node if c.tag not in ("CollectAddresses", "Calculation")})
    if extra:
        return ("capability_unaccounted_shape", f"{fam}: <{tag}> unexpected child(ren) {extra}")
    if (node.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: <{tag}> carries loose text")
    if node.find("Calculation") is not None:
        return _mail_wrapped_calc_child_reason(node, fam, f"<{tag}> recipient")
    return None


def _mail_text_field_reason(node, fam, tag) -> "tuple[str, str] | None":
    """A <Subject>/<Message>/SMTP text field: at most one <Calculation> wrapper, no other child/text (the clip
    emits it only when the calc is present). Subject/body/field text is content."""
    extra = sorted({c.tag for c in node if c.tag != "Calculation"})
    if extra or (node.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: <{tag}> unexpected child(ren)/text")
    if node.find("Calculation") is not None:
        return _mail_wrapped_calc_child_reason(node, fam, f"<{tag}>")
    return None


def _mail_send_subtree_reason(send, fam) -> "tuple[str, str] | None":
    """The <Send SMTP OAuthAuthentication> subtree: bounded mode attrs, exactly one bounded <Multiple>, and the
    optional To/CC/BCC/Subject/Message nodes (each validated fail-loud). No other child."""
    if set(send.attrib) - {"SMTP", "OAuthAuthentication"}:
        return ("capability_unaccounted_shape", f"{fam}: <Send> unexpected attribute(s) {sorted(send.attrib)}")
    for a in ("SMTP", "OAuthAuthentication"):
        if send.get(a) not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape", f"{fam}: <Send @{a}> value {send.get(a)!r} is not bounded")
    mults = send.findall("Multiple")
    if len(mults) != 1 or (set(mults[0].attrib) - {"value"}) or len(mults[0]) \
            or mults[0].get("value") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape", f"{fam}: <Send> must hold exactly one bounded <Multiple>")
    counts = {}
    for c in send:
        counts[c.tag] = counts.get(c.tag, 0) + 1
    allowed = {"Multiple", "To", "CC", "BCC", "Subject", "Message"}
    unknown = sorted(set(counts) - allowed)
    if unknown:
        return ("capability_unaccounted_shape", f"{fam}: <Send> unexpected child(ren) {unknown}")
    for tag in ("To", "CC", "BCC", "Subject", "Message"):
        if counts.get(tag, 0) > 1:
            return ("capability_unaccounted_shape", f"{fam}: <Send> duplicate <{tag}>")
    for tag in ("To", "CC", "BCC"):
        node = send.find(tag)
        if node is not None:
            r = _mail_recipient_reason(node, fam, tag)
            if r is not None:
                return r
    for tag in ("Subject", "Message"):
        node = send.find(tag)
        if node is not None:
            r = _mail_text_field_reason(node, fam, tag)
            if r is not None:
                return r
    return None


def _mail_smtp_subtree_reason(smtp, fam) -> "tuple[str, str] | None":
    """The <SMTP> subtree (SMTP mode): optional Name/Email/ReplyTo/Server/Port/UserName/Password calc fields
    (emit-if-present) + exactly one bounded <Encryption> (`_SMTP_ENCRYPTION`) + one bounded <Authentication>
    (`_SMTP_AUTH`). An unmapped encryption/auth, an extra/duplicate node, or a malformed calc refuses."""
    counts = {}
    for c in smtp:
        counts[c.tag] = counts.get(c.tag, 0) + 1
    allowed = set(_MAIL_SMTP_TEXT_FIELDS) | {"Encryption", "Authentication"}
    unknown = sorted(set(counts) - allowed)
    if unknown:
        return ("capability_unaccounted_shape", f"{fam}: <SMTP> unexpected child(ren) {unknown}")
    for tag in _MAIL_SMTP_TEXT_FIELDS:
        if counts.get(tag, 0) > 1:
            return ("capability_unaccounted_shape", f"{fam}: <SMTP> duplicate <{tag}>")
        node = smtp.find(tag)
        if node is not None:
            r = _mail_text_field_reason(node, fam, f"SMTP {tag}")
            if r is not None:
                return r
    for tag, amap, code in (("Encryption", _SMTP_ENCRYPTION, "smtp_encryption_unmapped"),
                            ("Authentication", _SMTP_AUTH, "smtp_authentication_unmapped")):
        nodes = smtp.findall(tag)
        if len(nodes) != 1:
            return ("capability_unaccounted_shape", f"{fam}: <SMTP> must hold exactly one <{tag}>")
        n = nodes[0]
        if (set(n.attrib) - {"name", "value"}) or len(n):
            return ("capability_unaccounted_shape", f"{fam}: <SMTP> <{tag}> unexpected attrs/children")
        if n.get("name") not in amap:
            return (code, f"{fam}: SMTP {tag} {n.get('name')!r} is not a matched mapping {sorted(amap)} — "
                    "refused rather than a lookup-miss default")
    return None


def _mail_oauth_subtree_reason(oauth, fam) -> "tuple[str, str] | None":
    """The <OAuthAuthentication> subtree (OAuth mode): exactly one bounded <OAuthProvider> (`_OAUTH_PROVIDER`)
    + the empty Name/Email/ReplyTo/PrivateKey/UserID/ServiceAccount placeholders (a POPULATED placeholder the
    emitter would silently drop refuses). An unmapped provider refuses `oauth_provider_unmapped`."""
    provs = oauth.findall("OAuthProvider")
    if len(provs) != 1 or (set(provs[0].attrib) - {"name", "value"}) or len(provs[0]):
        return ("capability_unaccounted_shape", f"{fam}: <OAuthAuthentication> must hold exactly one <OAuthProvider>")
    if provs[0].get("name") not in _OAUTH_PROVIDER:
        return ("oauth_provider_unmapped",
                f"{fam}: OAuth provider {provs[0].get('name')!r} is not a matched mapping {sorted(_OAUTH_PROVIDER)}")
    allowed = set(_MAIL_OAUTH_EMPTY_FIELDS) | {"OAuthProvider"}
    unknown = sorted({c.tag for c in oauth} - allowed)
    if unknown:
        return ("capability_unaccounted_shape", f"{fam}: <OAuthAuthentication> unexpected child(ren) {unknown}")
    for tag in _MAIL_OAUTH_EMPTY_FIELDS:
        for n in oauth.findall(tag):
            if len(n) or (n.text or "").strip():
                return ("capability_unaccounted_shape",
                        f"{fam}: <OAuthAuthentication> <{tag}> carries content the emitter would silently drop")
    return None


def _mail_attachment_reason(upl, fam) -> "tuple[str, str] | None":
    """The optional attachment <UniversalPathList>: exactly one <ObjectList> holding exactly one <Location>
    (path text is content). Rejects a malformed/multi-entry path list the emitter would misread."""
    if set(upl.attrib) - {"membercount", "AutoOpen", "CreateMail"}:
        return ("capability_unaccounted_shape", f"{fam}: <UniversalPathList> unexpected attrs {sorted(upl.attrib)}")
    ols = upl.findall("ObjectList")
    if len(list(upl)) != 1 or len(ols) != 1:
        return ("capability_unaccounted_shape", f"{fam}: attachment must hold exactly one <ObjectList>")
    locs = ols[0].findall("Location")
    if len(list(ols[0])) != 1 or len(locs) != 1 or len(locs[0]):
        return ("capability_unaccounted_shape", f"{fam}: attachment <ObjectList> must hold exactly one <Location>")
    return None


def _cap_send_mail(step) -> "tuple[str, str] | None":
    """id 63 — the whole Email subtree in all three implemented modes (plain / SMTP / OAuth). Validates the
    dialog Boolean, the mode↔subtree coupling (SMTP subtree ⟺ Send@SMTP, OAuth subtree ⟺ Send@OAuthAuthentication,
    both-false ⟺ plain, both-true refuses), the Send subtree, the mode-specific subtree, and the optional
    attachment — every nested node fail-loud before emission. Recipients/subject/body/credentials/paths are
    content and NEVER enter a reason string; recipient/calc/attachment/mode presence is shape."""
    params, reason = _step_body(step, "Send Mail")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "Email":
        return ("capability_unaccounted_shape", "Send Mail accounts for exactly one Email parameter")
    email = params[0]
    if (set(email.attrib) - {"type"}) or (email.text or "").strip():
        return ("capability_unaccounted_shape", "Send Mail: the parameter is not a bare type=\"Email\"")
    counts = {}
    for c in email:
        counts[c.tag] = counts.get(c.tag, 0) + 1
    allowed = {"Boolean", "SMTP", "OAuthAuthentication", "Send", "UniversalPathList"}
    unknown = sorted(set(counts) - allowed)
    if unknown:
        return ("capability_unaccounted_shape", f"Send Mail: <Email> unexpected child(ren) {unknown}")
    if counts.get("Boolean", 0) != 1 or counts.get("Send", 0) != 1:
        return ("capability_unaccounted_shape", "Send Mail: <Email> needs exactly one dialog Boolean and one <Send>")
    if counts.get("SMTP", 0) > 1 or counts.get("OAuthAuthentication", 0) > 1 or counts.get("UniversalPathList", 0) > 1:
        return ("capability_unaccounted_shape", "Send Mail: duplicate SMTP/OAuth/attachment subtree")
    dlg = email.find("Boolean")
    if (set(dlg.attrib) - {"type", "position", "value", "id"}) or len(dlg) or (dlg.text or "").strip():
        return ("capability_unaccounted_shape", "Send Mail: the dialog Boolean carries unexpected attrs/children")
    if dlg.get("type") not in _MAIL_DIALOG_TYPES or dlg.get("value") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape",
                f"Send Mail: dialog Boolean {dlg.get('type')!r}={dlg.get('value')!r} outside the bounded vocabulary")
    smtp = email.find("SMTP")
    oauth = email.find("OAuthAuthentication")
    send = email.find("Send")
    if smtp is not None and oauth is not None:
        return ("mail_mixed_mode", "Send Mail: both SMTP and OAuth subtrees present — mixed mode is not implemented")
    if (smtp is not None) != (send.get("SMTP") == "True"):
        return ("mail_mode_mismatch", "Send Mail: <SMTP> subtree presence must match <Send @SMTP>")
    if (oauth is not None) != (send.get("OAuthAuthentication") == "True"):
        return ("mail_mode_mismatch",
                "Send Mail: <OAuthAuthentication> subtree presence must match <Send @OAuthAuthentication>")
    r = _mail_send_subtree_reason(send, "Send Mail")
    if r is not None:
        return r
    if smtp is not None:
        r = _mail_smtp_subtree_reason(smtp, "Send Mail")
        if r is not None:
            return r
    if oauth is not None:
        r = _mail_oauth_subtree_reason(oauth, "Send Mail")
        if r is not None:
            return r
    upl = email.find("UniversalPathList")
    if upl is not None:
        r = _mail_attachment_reason(upl, "Send Mail")
        if r is not None:
            return r
    return None


def _send_mail_sig_token(p) -> str:
    """The COMPLETE target-driving topology of a Send Mail Email param (packet 1114): send mode + crypto enums
    (`_email_fingerprint`) PLUS every fact the emitter varies on — NoInteract (dialog), Multiple, attachment
    presence, per-recipient presence+CollectAddresses, Subject/Message presence, and the SMTP text-field
    presence set. The bare `Email:{fingerprint}` collapsed all of these, so an uncaptured recipient/attachment/
    Multiple/dialog shape could borrow a verified tuple. Address/body/credential TEXT stays content."""
    send = p.find("Send")
    dlg = p.find("Boolean")
    no_dialog = "?"
    if dlg is not None:
        if dlg.get("type") == "With dialog":
            no_dialog = "True" if dlg.get("value") == "False" else "False"
        elif dlg.get("type") == "No dialog":
            no_dialog = "True" if dlg.get("value") == "True" else "False"
    mult = send.find("Multiple") if send is not None else None
    m = mult.get("value") if mult is not None else "_"
    att = "1" if p.find(".//UniversalPathList//Location") is not None else "0"
    rec = []
    for tag in ("To", "CC", "BCC"):
        node = send.find(tag) if send is not None else None
        if node is None or node.find(".//Calculation") is None:
            rec.append(f"{tag}0")
        else:
            ca = node.find("CollectAddresses")
            rec.append(f"{tag}1:{ca.get('value') if ca is not None else '_'}")

    def _present(container, tag):
        n = container.find(tag) if container is not None else None
        return "1" if (n is not None and n.find(".//Calculation") is not None) else "0"

    subj, msg = _present(send, "Subject"), _present(send, "Message")
    smtp = p.find("SMTP")
    smtp_fields = "".join(_present(smtp, t) for t in _MAIL_SMTP_TEXT_FIELDS) if smtp is not None else ""
    return (f"Email:{_email_fingerprint(p)}|dlg={no_dialog}|mult={m}|att={att}|"
            f"{'/'.join(rec)}|s{subj}m{msg}|smtp[{smtp_fields}]")


# E — Speak (66). Bounded base shape only (Voice + Wait → SpeechOptions, no spoken-text calc). A present
# spoken-text operand refuses `speak_text_unimplemented` rather than being silently dropped.

def _cap_speak(step) -> "tuple[str, str] | None":
    """id 66 — exactly one <Voice id value> + one bounded <Wait> Boolean, in that order → <SpeechOptions
    VoiceId WaitForCompletion>. The emitter carries NO spoken-text Calculation, so a spoken-text operand refuses
    `speak_text_unimplemented` (never a silent drop). Voice value + Wait value are effect-driving (signature)."""
    params, reason = _step_body(step, "Speak")
    if reason is not None:
        return reason
    if any(pp.find(".//Text") is not None or pp.find(".//Calculation") is not None for pp in params):
        return ("speak_text_unimplemented",
                "Speak: a spoken-text calculation is present, but the emitter produces only <SpeechOptions> and "
                "would silently drop it — refused rather than emitting a clip that omits the utterance")
    if len(params) != 2 or params[0].get("type") != "Voice" or params[1].get("type") != "Wait":
        return ("capability_unaccounted_shape", "Speak accounts for a Voice node + a Wait Boolean")
    vp = params[0]
    if (set(vp.attrib) - {"type"}) or (vp.text or "").strip():
        return ("capability_unaccounted_shape", "Speak: the Voice parameter is not a bare type=\"Voice\"")
    voices = vp.findall("Voice")
    if len(list(vp)) != 1 or len(voices) != 1:
        return ("capability_unaccounted_shape", "Speak: exactly one <Voice> node")
    v = voices[0]
    if (set(v.attrib) - {"id", "value"}) or len(v) or v.get("value") is None:
        return ("capability_unaccounted_shape", "Speak: <Voice> must carry a value (id is content) and no children")
    wp = params[1]
    if (set(wp.attrib) - {"type"}) or (wp.text or "").strip():
        return ("capability_unaccounted_shape", "Speak: the Wait parameter is not a bare type=\"Wait\"")
    bs = wp.findall("Boolean")
    if len(list(wp)) != 1 or len(bs) != 1 or bs[0].get("type") != "Wait":
        return ("capability_unaccounted_shape", "Speak: exactly one type=\"Wait\" Boolean")
    b = bs[0]
    if (set(b.attrib) - {"type", "value", "id"}) or len(b) or b.get("value") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape",
                f"Speak: the Wait Boolean value {b.get('value')!r} is outside the bounded vocabulary")
    return None


# ── packet 1115 — bounded file input and output (9 ids) ──
#
# Nine already-emitting file-I/O ids. These migrate ONLY the source grammars the emitters actually consume, and
# preserve NAMED refusals for configured export/save variants the emitters do not implement (36/143/225's
# format/worksheet/data-complete features, 131's projected-away dialog options). Paths, URLs, cURL options, file
# names, and field values may hold private data/credentials — capability reasons name only the STRUCTURAL
# blocker, never the value. Path/URL/cURL/calc TEXT and reference names/ids are content when topology is
# constant; destination kind, path/target/repetition presence, option mode, and every output-driving Boolean/enum
# are shape.

# Shared, per-id-gated UniversalPathList validator: the exact <UniversalPathList membercount?><ObjectList>
# <Location>path</Location> grammar the emitters first-match. AutoOpen/CreateMail are accepted ONLY where the id
# emits them (37 both, 132 AutoOpen) — elsewhere they would be a SILENT DROP and refuse.
def _file_pathlist_reason(param, fam, *, autoopen=False, createmail=False) -> "tuple[str, str] | None":
    if (set(param.attrib) - {"type"}) or (param.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the UniversalPathList parameter is not a bare type")
    upls = param.findall("UniversalPathList")
    if len(list(param)) != 1 or len(upls) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <UniversalPathList> node")
    upl = upls[0]
    allowed = {"membercount"} | ({"AutoOpen"} if autoopen else set()) | ({"CreateMail"} if createmail else set())
    stray = set(upl.attrib) - allowed
    if stray:
        return ("capability_unaccounted_shape",
                f"{fam}: <UniversalPathList> carries attribute(s) {sorted(stray)} the emitter does not consume "
                "(a silent drop)")
    for a in ("AutoOpen", "CreateMail"):
        if upl.get(a) is not None and upl.get(a) not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape", f"{fam}: <UniversalPathList @{a}> outside the Boolean vocabulary")
    ols = upl.findall("ObjectList")
    if len(list(upl)) != 1 or len(ols) != 1 or set(ols[0].attrib):
        return ("capability_unaccounted_shape", f"{fam}: exactly one bare <ObjectList>")
    locs = ols[0].findall("Location")
    if len(list(ols[0])) != 1 or len(locs) != 1 or set(locs[0].attrib) or len(locs[0]):
        return ("capability_unaccounted_shape", f"{fam}: exactly one plain-text <Location> path")
    return None


_FILE_UPL_SIG_IDS = frozenset({"37", "132"})       # UPL AutoOpen/CreateMail are target-driving for these ids
_URL_SIG_IDS = frozenset({"160"})                  # the URL autoEncode flag drives <DontEncodeURL @state>


def _file_upl_sig_token(param) -> str:
    """AutoOpen/CreateMail presence+value on a UPL param (37/132) — they drive <AutoOpen>/<CreateEmail> states,
    so an absent-vs-True UPL must not borrow a verified tuple. Path text stays content."""
    upl = param.find("UniversalPathList")
    if upl is None:
        return "UniversalPathList"
    return f"UniversalPathList:AO={upl.get('AutoOpen') or '_'},CM={upl.get('CreateMail') or '_'}"


def _url_sig_token(param) -> str:
    """The URL param's autoEncode flag (160) → <DontEncodeURL @state> (inverted). URL TEXT stays content."""
    u = param.find("URL")
    return f"URL:autoEncode={u.get('autoEncode') if u is not None else '?'}"


def _insert_file_target_sig_token(param) -> str:
    """id 131's Target field-vs-anchor topology. `_emit_field_ref` writes <Field table=…> from the TO anchor and
    DROPS the repetition, so anchor presence is target-driving but repetition is NOT. Field identity is content."""
    fr = param.find("FieldReference")
    if fr is None:
        return "Target"
    return "Target:anchor" if fr.find("TableOccurrenceReference") is not None else "Target:noanchor"


# ── packet 1116 — Show Custom Dialog (87) signature repair ──
_DIALOG_BUTTON_SLOTS = ("Button1", "Button2", "Button3")
_DIALOG_FIELD_SLOTS = ("Field1", "Field2", "Field3")
_DIALOG_GEOMETRY_SLOTS = ("height", "width", "top", "left")   # packet 1120 — DDR names → the four clip wrappers
_DIALOG_SIG_TYPES = frozenset(_DIALOG_BUTTON_SLOTS) | frozenset(_DIALOG_FIELD_SLOTS)


def _dialog_sig_token(param) -> str:
    """id 87's per-slot target-driving topology. A Button's Commit VALUE drives `<Button CommitState>` and its
    label SOURCE (packet 1120: legacy `value` attr → a quoted `<Calculation>`; a child `<Calculation>` → the
    calc verbatim; absent → no child) drives a different `<Calculation>` child; an input Field's target KIND
    (variable / field / empty) drives the `<Field>` form, its Password VALUE drives `<InputField
    UsePasswordCharacter>`, and its Label PRESENCE drives a `<Label>` — all collapsed by the bare
    `Button{i}`/`Field{i}` token, so an uncaptured commit/label-source/target/password/label arrangement could
    borrow a verified tuple. Geometry presence rides as its own `height`/`width`/`top`/`left` tokens in the
    tuple. Repetition is DROPPED by the emitter (target-absent) and is NOT in the token. Button/label/field
    TEXT stays content."""
    ty = param.get("type")
    if ty in _DIALOG_BUTTON_SLOTS:
        b = param.find("Boolean[@type='Commit']")
        commit = b.get("value") if b is not None else "?"
        if param.get("value") is not None:
            label = "attr"
        elif param.find("Calculation") is not None:
            label = "calc"
        else:
            label = "none"
        return f"{ty}:commit={commit}|label={label}"
    # input Field slot
    t = param.find("Parameter[@type='Target']")
    if t is None:
        kind = "empty"
    elif t.find("Variable") is not None:
        kind = "var"
    elif t.find("FieldReference") is not None:
        kind = "field"
    else:
        kind = "empty"
    pb = param.find("Boolean[@type='Password']")
    pwd = pb.get("value") if pb is not None else "False"
    lab = "set" if param.find("Parameter[@type='Label']") is not None else "none"
    return f"{ty}:{kind}|pwd={pwd}|label={lab}"


def _url_block_reason(param, fam) -> "tuple[str, str] | None":
    """A <Parameter type="URL"> → one <URL autoEncode> (bounded) wrapping one calc. autoEncode is shape; URL
    text is content and never echoed."""
    if (set(param.attrib) - {"type"}) or (param.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the URL parameter is not a bare type=\"URL\"")
    urls = param.findall("URL")
    if len(list(param)) != 1 or len(urls) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <URL> block")
    u = urls[0]
    if (set(u.attrib) - {"autoEncode"}) or u.get("autoEncode") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape", f"{fam}: <URL @autoEncode> outside the Boolean vocabulary")
    calcs = u.findall("Calculation")
    if len(list(u)) != 1 or len(calcs) != 1:
        return ("capability_unaccounted_shape", f"{fam}: <URL> must wrap exactly one calculation")
    return _wrapped_calc_reason(calcs[0], fam, "the URL calculation")


# A — Save a Copy as XML (3)

def _cap_save_as_xml(step) -> "tuple[str, str] | None":
    """id 3 — one options Calculation + one output UniversalPathList + the three exact named Booleans
    (`Include details for analysis tools` / binary-data / JSON options), in that order. Boolean values + path/calc
    presence are shape; text is content. A missing/duplicate/unknown Boolean, a malformed path/calc, or an extra
    export structure refuses before first-match emission."""
    params, reason = _step_body(step, "Save a Copy as XML")
    if reason is not None:
        return reason
    names = ["Include details for analysis tools", "Save each layout object's binary data under its node",
             "Specify options as JSON"]
    if (len(params) != 5 or params[0].get("type") != "Calculation"
            or params[1].get("type") != "UniversalPathList"):
        return ("capability_unaccounted_shape",
                "Save a Copy as XML accounts for a Calculation + a UniversalPathList + three named Booleans")
    r = _typed_calc_param_reason(params[0], "Save a Copy as XML", "the options calculation")
    if r is not None:
        return r
    r = _file_pathlist_reason(params[1], "Save a Copy as XML")
    if r is not None:
        return r
    for i, bt in enumerate(names):
        r = _bare_boolean_reason(params[2 + i], bt, "Save a Copy as XML", values=_DIRECT_BOOLEAN_VALUES)
        if r is not None:
            return r
    return None


# B — Save a Copy as (37). The rule and `_emit_save_a_copy_as` share ONE authority — the existing explicit
# `_SAVE_AS_TYPE` map (promoted to the capability authority; clone/compacted-copy unobserved → refuse).

def _cap_save_a_copy_as(step) -> "tuple[str, str] | None":
    """id 37 — an explicit `_SAVE_AS_TYPE` mode selector + a bounded Create-folders Boolean + an OPTIONAL output
    UniversalPathList (AutoOpen/CreateMail consumed), in the two evidenced orders (mode+bool, or path+mode+bool).
    An unmapped mode refuses `save_as_type_unmapped`; a stray path attr or duplicate location refuses."""
    params, reason = _step_body(step, "Save a Copy as")
    if reason is not None:
        return reason
    upls = [p for p in params if p.get("type") == "UniversalPathList"]
    lists = [p for p in params if p.get("type") == "List"]
    bools = [p for p in params if p.get("type") == "Boolean"]
    if len(lists) != 1 or len(bools) != 1 or len(upls) > 1 or len(params) != len(lists) + len(bools) + len(upls):
        return ("capability_unaccounted_shape",
                "Save a Copy as accounts for a mode List + a Create-folders Boolean + an optional path")
    mode, r = _selector_list_value(lists[0], fam="Save a Copy as")
    if r is not None:
        return r
    if mode not in _SAVE_AS_TYPE:
        return ("save_as_type_unmapped",
                f"Save a Copy as: save mode {mode!r} is not a matched mapping {sorted(_SAVE_AS_TYPE)} — refused "
                "rather than a dictionary KeyError or a naming guess")
    r = _bare_boolean_reason(bools[0], "Create folders", "Save a Copy as", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    if upls:
        return _file_pathlist_reason(upls[0], "Save a Copy as", autoopen=True, createmail=True)
    return None


# C — Export Records (36), Save Excel (143), Save JSONL (225): BASE + CONFIGURED (packet 1117). Each
# configured branch is a bounded grammar the emitter fully consumes; a variant it does not implement
# (an unmapped export format/charset/order kind, a worksheet-metadata shape, a mixed field/table) keeps
# its OWN named refusal (`export_records_format_unimplemented` / `excel_options_unimplemented` /
# `jsonl_data_complete_unimplemented`), never a silent drop. Path/calc TEXT is content — reasons name
# only structure and enum values.

def _pathlist_location_reason(upl, fam) -> "tuple[str, str] | None":
    """The UPL's path container: exactly one `<ObjectList>` holding exactly one `<Location>` path (its
    TEXT is content). A bare/empty node is fine; extra attrs/children refuse."""
    ols = upl.findall("ObjectList")
    if len(ols) != 1:
        return ("capability_unaccounted_shape", f"{fam}: exactly one <ObjectList> path container")
    ol = ols[0]
    locs = ol.findall("Location")
    if set(ol.attrib) or len(list(ol)) != 1 or len(locs) != 1 or len(locs[0]) or set(locs[0].attrib):
        return ("capability_unaccounted_shape", f"{fam}: <ObjectList> must hold exactly one bare <Location> path")
    return None


def _cap_export_order_reason(export) -> "tuple[str, str] | None":
    """id 36's `<Export>`: one `<Options name value Formatting>` (name in `_EXPORT_CHARSET`, Formatting
    bounded) + the ordered Order sequence `[Group, Field...]` — one EMPTY Group marker (proven
    target-absent) then one-or-more Field orders, each holding exactly one anchored FieldReference. A
    non-Field/Group order kind, a non-empty/misplaced Group, an unmapped charset/format, an empty or
    malformed order list refuses. Field identity is content; order topology + enum values are shape."""
    if set(export.attrib):
        return ("capability_unaccounted_shape", "Export Records: <Export> carries unexpected attribute(s)")
    opts = export.findall("Options")
    if len(opts) != 1:
        return ("export_records_format_unimplemented", "Export Records: exactly one export <Options> node")
    o = opts[0]
    if (set(o.attrib) - {"name", "value", "Formatting"}) or len(o):
        return ("capability_unaccounted_shape", "Export Records: export <Options> unexpected attrs/children")
    if o.get("name") not in _EXPORT_CHARSET:
        return ("export_records_format_unimplemented",
                f"Export Records: character set {o.get('name')!r} is not an implemented ExportOptions value "
                f"{sorted(_EXPORT_CHARSET)}")
    if o.get("Formatting") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape", "Export Records: export <Options Formatting> outside the Boolean vocabulary")
    orders = export.findall("Order")
    if [c.tag for c in export] != ["Options"] + ["Order"] * len(orders):
        return ("capability_unaccounted_shape", "Export Records: <Export> children beyond Options + an Order list")
    kinds = [od.get("type") for od in orders]
    if len(kinds) < 2 or kinds[0] != "Group" or any(k != "Field" for k in kinds[1:]):
        return ("export_records_format_unimplemented",
                f"Export Records: order-kind sequence {kinds} is not the implemented [Group, Field...] shape "
                "(a summary/subtotal order or a missing Field order is not accounted for)")
    g = orders[0]
    if (set(g.attrib) - {"type"}) or len(g):
        return ("capability_unaccounted_shape", "Export Records: the Group order marker must be empty")
    for od in orders[1:]:
        if set(od.attrib) - {"type"}:
            return ("capability_unaccounted_shape", "Export Records: a Field order carries unexpected attribute(s)")
        fields = od.findall("Field")           # packet 1129 — one Field order holds ONE OR MORE ordered fields
        if not fields or len(list(od)) != len(fields):
            return ("capability_unaccounted_shape", "Export Records: a Field order holds one or more <Field> only")
        for f in fields:
            if (set(f.attrib) - {"value"}) or (f.text or "").strip():
                return ("capability_unaccounted_shape", "Export Records: <Field> wrapper unexpected attrs/text")
            frs = f.findall("FieldReference")
            if len(list(f)) != 1 or len(frs) != 1:
                return ("capability_unaccounted_shape", "Export Records: <Field> must hold exactly one FieldReference")
            r = _field_ref_node_reason(frs[0], "Export Records", require_anchor=True)
            if r is not None:
                return r
    return None


def _cap_export_records(step) -> "tuple[str, str] | None":
    """id 36 — BASE (With-dialog + Create-folders Booleans, fixed Restore/AutoOpen/CreateEmail) OR the
    CONFIGURED shape (packet 1117): + one UniversalPathList (fileType in `_EXPORT_PROFILE`, bounded
    AutoOpen/CreateMail, one Location) + one `<Export>` order/format tree. A configured shape whose format
    the emitter does not model refuses `export_records_format_unimplemented`, never a silent drop."""
    params, reason = _step_body(step, "Export Records")
    if reason is not None:
        return reason
    exports = [p for p in params if p.get("type") == "Export"]
    upls = [p for p in params if p.get("type") == "UniversalPathList"]
    bools = [p for p in params if p.get("type") == "Boolean"]
    if not exports and not upls:               # BASE shape
        if any(p.get("type") != "Boolean" for p in params) or len(params) > 2:
            return ("export_records_format_unimplemented",
                    "Export Records: a configured export format/field list is present, which the base-shape emitter "
                    "does not consume — refused, not emitted with the configuration silently dropped")
        return _named_booleans_reason(params, "Export Records", {"With dialog", "Create folders"})
    if len(exports) != 1 or len(upls) != 1 or len(bools) != 2 or len(params) != 4:
        return ("export_records_format_unimplemented",
                "Export Records: the configured shape is Export + UniversalPathList + With-dialog + Create-folders; "
                "another configured parameter set is not implemented")
    r = _named_booleans_reason(bools, "Export Records", {"With dialog", "Create folders"})
    if r is not None:
        return r
    up = upls[0]
    if (set(up.attrib) - {"type"}) or (up.text or "").strip() or len(list(up)) != 1 or len(up.findall("UniversalPathList")) != 1:
        return ("capability_unaccounted_shape", "Export Records: the UniversalPathList parameter is malformed")
    upl = up.find("UniversalPathList")
    if set(upl.attrib) - {"fileType", "AutoOpen", "CreateMail", "membercount"}:
        return ("capability_unaccounted_shape",
                f"Export Records: <UniversalPathList> unexpected attribute(s) {sorted(upl.attrib)}")
    if upl.get("fileType") not in _EXPORT_PROFILE:
        return ("export_records_format_unimplemented",
                f"Export Records: export file type {upl.get('fileType')!r} is not an implemented export format "
                f"{sorted(_EXPORT_PROFILE)}")
    for a in ("AutoOpen", "CreateMail"):       # packet 1129 — absent attr = the False default (FM2026 omits it)
        if upl.get(a) is not None and upl.get(a) not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape", f"Export Records: <UniversalPathList {a}> outside the Boolean vocabulary")
    if [c.tag for c in upl] != ["ObjectList"]:
        return ("capability_unaccounted_shape", "Export Records: the export UniversalPathList holds only an <ObjectList> path")
    r = _pathlist_location_reason(upl, "Export Records")
    if r is not None:
        return r
    ep = exports[0]
    if (set(ep.attrib) - {"type"}) or (ep.text or "").strip() or len(list(ep)) != 1 or len(ep.findall("Export")) != 1:
        return ("capability_unaccounted_shape", "Export Records: the Export parameter is malformed")
    return _cap_export_order_reason(ep.find("Export"))


def _excel_metadata_reason(container, fam) -> "tuple[list, tuple[str, str] | None]":
    """The four ordered metadata calc Parameters (Worksheet/Title/Subject/Author, each the standard calc
    subtree). Returns ([(type, calctext)...], None) or ([], reason). Calc TEXT is content."""
    metas = container.findall("Parameter")
    seen = []
    for m in metas:
        ty = m.get("type")
        if ty not in _EXCEL_METADATA_TAGS:
            return [], ("excel_options_unimplemented", f"{fam}: metadata field {ty!r} is not implemented")
        r = _typed_calc_param_reason(m, fam, f"the {ty} metadata")
        if r is not None:
            return [], r
        seen.append((ty, _inner_text(m)))
    if [t for t, _ in seen] != ["Worksheet", "Title", "Subject", "Author"]:
        return [], ("excel_options_unimplemented",
                    f"{fam}: metadata order {[t for t, _ in seen]} is not the implemented "
                    "Worksheet/Title/Subject/Author sequence")
    return seen, None


def _excel_block_reason(excel, fam) -> "tuple[tuple | None, tuple[str, str] | None]":
    """The `<Excel name=mode value>` block inside the configured UPL: mode in `_EXCEL_SAVE_MODE`, one bounded
    'Use field names' Boolean (value in `_EXCEL_USE_FIELD_NAMES`), then the four ordered metadata calcs.
    Returns ((mode, value, ufn, metas), None) or (None, reason)."""
    if set(excel.attrib) - {"name", "value"}:
        return None, ("capability_unaccounted_shape", f"{fam}: <Excel> unexpected attribute(s) {sorted(excel.attrib)}")
    if excel.get("name") not in _EXCEL_SAVE_MODE:
        return None, ("excel_options_unimplemented",
                      f"{fam}: Excel save mode {excel.get('name')!r} is not implemented {sorted(_EXCEL_SAVE_MODE)}")
    bools = excel.findall("Boolean")
    if len(bools) != 1 or bools[0].get("type") != "Use field names as column names":
        return None, ("capability_unaccounted_shape", f"{fam}: exactly one 'Use field names as column names' Boolean")
    b = bools[0]
    if (set(b.attrib) - {"type", "value", "id"}) or len(b) or (b.text or "").strip():
        return None, ("capability_unaccounted_shape", f"{fam}: the Use-field-names Boolean carries unexpected attrs/children")
    if b.get("value") not in _EXCEL_USE_FIELD_NAMES:
        return None, ("excel_options_unimplemented",
                      f"{fam}: useFieldNames={b.get('value')!r} is unsettled — only the evidenced value has a proven "
                      "target UseFieldNames coupling; refused rather than guessed or inverted")
    metas, r = _excel_metadata_reason(excel, fam)
    if r is not None:
        return None, r
    if [c.tag for c in excel] != ["Boolean"] + ["Parameter"] * len(metas):
        return None, ("capability_unaccounted_shape", f"{fam}: <Excel> children beyond the Boolean + metadata calcs")
    return (excel.get("name"), excel.get("value"), b.get("value"), metas), None


def _excel_mirror_reason(opts, fam) -> "tuple[tuple | None, tuple[str, str] | None]":
    """The separate mirror `<Options>` block: one `<Save type value useFieldNames>` + the four ordered
    metadata calcs. Returns ((type, value, ufn, metas), None) or (None, reason)."""
    if set(opts.attrib):
        return None, ("capability_unaccounted_shape", f"{fam}: the mirror <Options> carries unexpected attribute(s)")
    saves = opts.findall("Save")
    if len(saves) != 1:
        return None, ("capability_unaccounted_shape", f"{fam}: the mirror <Options> holds exactly one <Save>")
    sv = saves[0]
    if (set(sv.attrib) - {"type", "value", "useFieldNames"}) or len(sv) or (sv.text or "").strip():
        return None, ("capability_unaccounted_shape", f"{fam}: <Save> unexpected attrs/children")
    metas, r = _excel_metadata_reason(opts, fam)
    if r is not None:
        return None, r
    if [c.tag for c in opts] != ["Save"] + ["Parameter"] * len(metas):
        return None, ("capability_unaccounted_shape", f"{fam}: the mirror <Options> children beyond Save + metadata calcs")
    return (sv.get("type"), sv.get("value"), sv.get("useFieldNames"), metas), None


def _cap_save_excel(step) -> "tuple[str, str] | None":
    """id 143 — BASE (Restore + With-dialog + EMPTY Options + Create-folders → fixed BrowsedRecords/
    UseFieldNames) OR the CONFIGURED shape (packet 1117): + one UniversalPathList/Excel block + a separate
    mirror `<Options>` block. Both mirrored structures are validated and REQUIRED to agree (save mode,
    useFieldNames, metadata calcs) — a mismatch refuses `excel_mirrored_options_mismatch`, never first-match.
    A worksheet-metadata shape the emitter does not model refuses `excel_options_unimplemented`."""
    params, reason = _step_body(step, "Save Records as Excel")
    if reason is not None:
        return reason
    upls = [p for p in params if p.get("type") == "UniversalPathList"]
    if not upls:                               # BASE shape (empty Options)
        opts = [p for p in params if p.get("type") == "Options"]
        if len(opts) == 1 and len(opts[0].findall("Options")) == 1 and len(opts[0].find("Options")):
            return ("excel_options_unimplemented",
                    "Save Records as Excel: a configured worksheet/metadata Options block is present without the "
                    "UniversalPathList mirror — an unimplemented shape; refused")
        if len(params) != 4 or params[0].get("type") != "Restore" or params[2].get("type") != "Options":
            return ("capability_unaccounted_shape",
                    "Save Records as Excel accounts for Restore + With-dialog Boolean + empty Options + Create-folders")
        rp, r = _restore_param_reason(params, "Save Records as Excel")
        if r is not None:
            return r
        if rp.find("Restore").get("value") != "False":
            return ("capability_unaccounted_shape",
                    "Save Records as Excel: the base emitter writes a fixed Restore=False, so a Restore=True source "
                    "would be silently dropped — refused")
        o = params[2]
        if (set(o.attrib) - {"type"}) or len(o.findall("Options")) != 1 or len(o.find("Options")) \
                or set(o.find("Options").attrib):
            return ("capability_unaccounted_shape", "Save Records as Excel: the Options must be a single empty <Options/>")
        r = _bare_boolean_reason(params[1], "With dialog", "Save Records as Excel", values=_DIRECT_BOOLEAN_VALUES)
        if r is not None:
            return r
        return _bare_boolean_reason(params[3], "Create folders", "Save Records as Excel", values=_DIRECT_BOOLEAN_VALUES)
    # CONFIGURED shape
    optparams = [p for p in params if p.get("type") == "Options"]
    bools = [p for p in params if p.get("type") == "Boolean"]
    if len(upls) != 1 or len(optparams) != 1 or len(bools) != 2 or len(params) != 5:
        return ("excel_options_unimplemented",
                "Save Records as Excel: the configured shape is Restore + With-dialog + UniversalPathList + a mirror "
                "Options + Create-folders; another configured parameter set is not implemented")
    rp, r = _restore_param_reason(params, "Save Records as Excel")
    if r is not None:
        return r
    r = _named_booleans_reason(bools, "Save Records as Excel", {"With dialog", "Create folders"})
    if r is not None:
        return r
    up = upls[0]
    if (set(up.attrib) - {"type"}) or (up.text or "").strip() or len(list(up)) != 1 or len(up.findall("UniversalPathList")) != 1:
        return ("capability_unaccounted_shape", "Save Records as Excel: the UniversalPathList parameter is malformed")
    upl = up.find("UniversalPathList")
    if set(upl.attrib) - {"fileType", "AutoOpen", "CreateMail", "membercount"}:
        return ("capability_unaccounted_shape",
                f"Save Records as Excel: <UniversalPathList> unexpected attribute(s) {sorted(upl.attrib)}")
    if upl.get("fileType") not in _EXCEL_PROFILE:
        return ("excel_options_unimplemented",
                f"Save Records as Excel: file type {upl.get('fileType')!r} is not an implemented Excel format")
    for a in ("AutoOpen", "CreateMail"):
        if upl.get(a) not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape", f"Save Records as Excel: <UniversalPathList {a}> outside the Boolean vocabulary")
    excels = upl.findall("Excel")
    if [c.tag for c in upl] != ["Excel", "ObjectList"] or len(excels) != 1:
        return ("capability_unaccounted_shape",
                "Save Records as Excel: the configured UniversalPathList holds one <Excel> then one <ObjectList>")
    r = _pathlist_location_reason(upl, "Save Records as Excel")
    if r is not None:
        return r
    excel_desc, r = _excel_block_reason(excels[0], "Save Records as Excel")
    if r is not None:
        return r
    op = optparams[0]
    if (set(op.attrib) - {"type"}) or (op.text or "").strip() or len(list(op)) != 1 or len(op.findall("Options")) != 1:
        return ("capability_unaccounted_shape", "Save Records as Excel: the mirror Options parameter is malformed")
    mirror_desc, r = _excel_mirror_reason(op.find("Options"), "Save Records as Excel")
    if r is not None:
        return r
    e_mode, e_val, e_ufn, e_meta = excel_desc
    m_type, m_val, m_ufn, m_meta = mirror_desc
    if (e_mode, e_val, e_ufn, e_meta) != (m_type, m_val, m_ufn, m_meta):
        return ("excel_mirrored_options_mismatch",
                "Save Records as Excel: the UniversalPathList/Excel block and the mirror Options block disagree on "
                "save mode, useFieldNames, or metadata calculations — refused rather than first-match selection")
    return None


def _cap_save_jsonl(step) -> "tuple[str, str] | None":
    """id 225 — BASE (Format-for-fine-tuning + Create-folders Booleans) OR the CONFIGURED data-complete shape
    (packet 1117): one bare UniversalPathList (a single Location, no fileType) + one
    SaveAsJSONLDataCompleteField (an anchored FieldReference) + one SaveAsJSONLTable (a TableOccurrenceReference
    id+name) + the two Booleans. The data-complete field's table anchor MUST match the SaveAsJSONLTable (the
    field/table relationship the emitter reproduces); a mismatch or another configured shape refuses
    `jsonl_data_complete_unimplemented`. Reference identity/path are content."""
    params, reason = _step_body(step, "Save Records as JSONL")
    if reason is not None:
        return reason
    upls = [p for p in params if p.get("type") == "UniversalPathList"]
    dcfs = [p for p in params if p.get("type") == "SaveAsJSONLDataCompleteField"]
    tbls = [p for p in params if p.get("type") == "SaveAsJSONLTable"]
    bools = [p for p in params if p.get("type") == "Boolean"]
    if not upls and not dcfs and not tbls:     # BASE shape
        if any(p.get("type") != "Boolean" for p in params) or len(params) > 2:
            return ("jsonl_data_complete_unimplemented",
                    "Save Records as JSONL: a configured data-complete field/table is present, which the base-shape "
                    "emitter does not consume — refused")
        return _named_booleans_reason(params, "Save Records as JSONL", {"Format for fine-tuning", "Create folders"})
    if len(upls) != 1 or len(dcfs) != 1 or len(tbls) != 1 or len(bools) != 2 or len(params) != 5:
        return ("jsonl_data_complete_unimplemented",
                "Save Records as JSONL: the configured shape is UniversalPathList + SaveAsJSONLDataCompleteField + "
                "SaveAsJSONLTable + Format-for-fine-tuning + Create-folders; another configured parameter set is not "
                "implemented")
    r = _named_booleans_reason(bools, "Save Records as JSONL", {"Format for fine-tuning", "Create folders"})
    if r is not None:
        return r
    up = upls[0]
    if (set(up.attrib) - {"type"}) or (up.text or "").strip() or len(list(up)) != 1 or len(up.findall("UniversalPathList")) != 1:
        return ("capability_unaccounted_shape", "Save Records as JSONL: the UniversalPathList parameter is malformed")
    upl = up.find("UniversalPathList")
    if (set(upl.attrib) - {"membercount"}) or [c.tag for c in upl] != ["ObjectList"]:
        return ("capability_unaccounted_shape",
                "Save Records as JSONL: the JSONL UniversalPathList is a bare path (no fileType/AutoOpen), one ObjectList")
    r = _pathlist_location_reason(upl, "Save Records as JSONL")
    if r is not None:
        return r
    r = _field_reference_reason(dcfs[0], "Save Records as JSONL", require_anchor=True)
    if r is not None:
        return r
    tp = tbls[0]
    if (set(tp.attrib) - {"type"}) or (tp.text or "").strip() or len(list(tp)) != 1 or len(tp.findall("TableOccurrenceReference")) != 1:
        return ("capability_unaccounted_shape", "Save Records as JSONL: exactly one SaveAsJSONLTable TableOccurrenceReference")
    tor = tp.find("TableOccurrenceReference")
    if (set(tor.attrib) - {"id", "name", "UUID"}) or len(tor) or tor.get("id") is None or tor.get("name") is None:
        return ("capability_unaccounted_shape", "Save Records as JSONL: <TableOccurrenceReference> must carry id and name")
    if dcfs[0].find("FieldReference/TableOccurrenceReference").get("name") != tor.get("name"):
        return ("jsonl_data_complete_unimplemented",
                "Save Records as JSONL: the data-complete field's table anchor and the SaveAsJSONLTable disagree — the "
                "field/table relationship the emitter reproduces is not established; refused")
    return None


# D — Insert File (131): FileMaker's own clip projection is the LOSSIER one (Title/Filters/Display omitted).

def _cap_insert_file(step) -> "tuple[str, str] | None":
    """id 131 — both committed shapes: the parameterless base, and the configured dialog/path/target shape. The
    configured Options holds the exact five siblings (Title/Filters/Storage/Display/Compress); Storage/Compress
    map through `_INSERT_FILE_STORAGE`/`_INSERT_FILE_COMPRESS` (only the evidenced `0`/UserChoice); Title/Filters/
    Display are the PROVEN target-absent projection (FileMaker's own clip omits them, emitting an empty FilterList)
    — accepted at their exact legal parents, projected away, never a wildcard. The Target FieldReference + path
    are optional. An unknown storage/compress value, a partial option set, or a malformed target/path refuses."""
    params, reason = _step_body(step, "Insert File")
    if reason is not None:
        return reason
    if not params:                                 # the parameterless base shape
        return None
    optparams = [p for p in params if p.get("type") == "Options"]
    targets = [p for p in params if p.get("type") == "Target"]
    upls = [p for p in params if p.get("type") == "UniversalPathList"]
    if (len(optparams) != 1 or len(targets) > 1 or len(upls) > 1
            or len(params) != len(optparams) + len(targets) + len(upls)):
        return ("capability_unaccounted_shape",
                "Insert File (configured) accounts for one Options block + an optional Target + an optional path")
    opts = optparams[0]
    if (set(opts.attrib) - {"type"}) or (opts.text or "").strip():
        return ("capability_unaccounted_shape", "Insert File: the Options parameter is not a bare type")
    siblings = opts.findall("Options")
    if len(list(opts)) != len(siblings):
        return ("capability_unaccounted_shape", "Insert File: the Options parameter holds a non-Options child")
    by_type = {}
    for o in siblings:
        kind = o.get("type")
        if kind in by_type:
            return ("capability_unaccounted_shape", f"Insert File: duplicate Options sibling {kind!r}")
        by_type[kind] = o
    if set(by_type) != {"Title", "Filters", "Storage", "Display", "Compress"}:
        return ("capability_unaccounted_shape",
                f"Insert File: the Options sibling set {sorted(by_type)} is not the exact five "
                "(Title/Filters/Storage/Display/Compress)")
    for kind, amap in (("Storage", _INSERT_FILE_STORAGE), ("Compress", _INSERT_FILE_COMPRESS)):
        node = by_type[kind].find(kind)
        if node is None or (set(node.attrib) - {"name", "value"}) or len(node):
            return ("capability_unaccounted_shape", f"Insert File: <{kind}> is malformed")
        if node.get("value") not in amap:
            return (f"insert_file_{kind.lower()}_unmapped",
                    f"Insert File: {kind} value {node.get('value')!r} is not a matched mode {sorted(amap)} — "
                    "refused rather than a guessed dialog mode")
    if targets:
        r = _target_branch_reason(targets[0], "Insert File")   # a FieldReference or Variable target
        if r is not None:
            return r
    if upls:
        return _file_pathlist_reason(upls[0], "Insert File")
    return None


# E — Export Field Contents (132)

def _cap_export_field(step) -> "tuple[str, str] | None":
    """id 132 — a bounded Create-folders Boolean + exactly one FieldReference (optional TO anchor + repetition)
    + an OPTIONAL output UniversalPathList (AutoOpen consumed; CreateEmail is fixed False). Field/path identity is
    content; path/repetition/anchor presence is shape. A missing/duplicate field, a multi-path list, or an
    unknown path attr refuses."""
    params, reason = _step_body(step, "Export Field Contents")
    if reason is not None:
        return reason
    bools = [p for p in params if p.get("type") == "Boolean"]
    frefs = [p for p in params if p.get("type") == "FieldReference"]
    upls = [p for p in params if p.get("type") == "UniversalPathList"]
    if (len(bools) != 1 or len(frefs) != 1 or len(upls) > 1
            or len(params) != len(bools) + len(frefs) + len(upls)):
        return ("capability_unaccounted_shape",
                "Export Field Contents accounts for a Create-folders Boolean + one FieldReference + an optional path")
    r = _bare_boolean_reason(bools[0], "Create folders", "Export Field Contents", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    r = _field_reference_reason(frefs[0], "Export Field Contents")
    if r is not None:
        return r
    if upls:
        return _file_pathlist_reason(upls[0], "Export Field Contents", autoopen=True)
    return None


# F — Save Records as Snapshot Link (152). The rule and `_emit_snapshot_link` share the existing explicit
# `_SNAPSHOT_SAVETYPE` map (promoted to the capability authority; the emitter's `.get(name, name)` fallback is
# unreachable once the rule has refused an unmapped mode).

def _cap_snapshot_link(step) -> "tuple[str, str] | None":
    """id 152 — an explicit `_SNAPSHOT_SAVETYPE` source selector + one output UniversalPathList + a bounded
    Create-folders Boolean (CreateEmail is a proven fixed False). An unknown source mode refuses
    `snapshot_save_type_unmapped`; a missing/duplicate path or malformed Boolean refuses."""
    params, reason = _step_body(step, "Save Records as Snapshot Link")
    if reason is not None:
        return reason
    upls = [p for p in params if p.get("type") == "UniversalPathList"]
    lists = [p for p in params if p.get("type") == "List"]
    bools = [p for p in params if p.get("type") == "Boolean"]
    if (len(upls) != 1 or len(lists) != 1 or len(bools) != 1
            or len(params) != len(upls) + len(lists) + len(bools)):
        return ("capability_unaccounted_shape",
                "Save Records as Snapshot Link accounts for a path + a source List + a Create-folders Boolean")
    mode, r = _selector_list_value(lists[0], fam="Save Records as Snapshot Link")
    if r is not None:
        return r
    if mode not in _SNAPSHOT_SAVETYPE:
        return ("snapshot_save_type_unmapped",
                f"Save Records as Snapshot Link: source mode {mode!r} is not a matched mapping "
                f"{sorted(_SNAPSHOT_SAVETYPE)} — refused rather than a raw pass-through")
    r = _bare_boolean_reason(bools[0], "Create folders", "Save Records as Snapshot Link", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    return _file_pathlist_reason(upls[0], "Save Records as Snapshot Link")


# G — Insert from URL (160)

def _cap_insert_from_url(step) -> "tuple[str, str] | None":
    """id 160 — bounded Verify-SSL / Select / With-dialog Booleans + exactly one field-or-variable Target
    (repetition included) + one URL block (bounded autoEncode) + an OPTIONAL one cURL Calculation. URL/cURL text
    is private content and never echoed. A missing/duplicate URL or target, a mixed field+variable target, or a
    malformed cURL refuses before first-match emission."""
    params, reason = _step_body(step, "Insert from URL")
    if reason is not None:
        return reason
    bools = [p for p in params if p.get("type") == "Boolean"]
    targets = [p for p in params if p.get("type") == "Target"]
    urls = [p for p in params if p.get("type") == "URL"]
    calcs = [p for p in params if p.get("type") == "Calculation"]
    if (len(targets) != 1 or len(urls) != 1 or len(calcs) > 1 or len(bools) != 3
            or len(params) != len(bools) + len(targets) + len(urls) + len(calcs)):
        return ("capability_unaccounted_shape",
                "Insert from URL accounts for three Booleans + a Target + a URL + an optional cURL Calculation")
    seen = {}
    for bp in bools:
        r = _bare_boolean_reason(bp, bp.find("Boolean").get("type") if bp.find("Boolean") is not None else "?",
                                 "Insert from URL", values=_DIRECT_BOOLEAN_VALUES)
        if r is not None:
            return r
        seen[bp.find("Boolean").get("type")] = bp
    if set(seen) != {"Verify SSL Certificates", "Select", "With dialog"}:
        return ("capability_unaccounted_shape",
                f"Insert from URL: the Boolean set {sorted(seen)} is not the exact three")
    r = _target_branch_reason(targets[0], "Insert from URL")
    if r is not None:
        return r
    r = _url_block_reason(urls[0], "Insert from URL")
    if r is not None:
        return r
    if calcs:
        return _typed_calc_param_reason(calcs[0], "Insert from URL", "the cURL options calculation")
    return None


# ── packet 1116 — permission-migration CLOSEOUT: Show Custom Dialog (87) + Replace Field Contents (91) ──
#
# The last two already-emitting ids without a capability rule. After this every VERIFIED_STEP_IDS id has an
# independent capability-before-evidence rule (set(_STEP_CAPABILITY_RULES) == set(VERIFIED_STEP_IDS)) — a
# closeout of the permission-model migration begun at packet 1091, NOT a claim of universal FileMaker step/option
# coverage. Named code gaps (configured export/save, unimplemented dialog input targets, unsettled Replace option
# values) stay refused. Evidence bound: the three committed dialog pairs + four committed Replace pairs (the
# master fixtures are clip-side fmxmlsnippet, not DDR sources). Neither predicate reads _VERIFIED_SIGS — permission
# is IMPLEMENTED CAPABILITY (packet 1088's split); fixture removal cannot revoke a grammar.


def _dialog_button_reason(p, slot) -> "tuple[str, str] | None":
    """One `<Parameter type="Button{i}">` slot: EXACTLY one bounded `Commit` Boolean plus, at most, ONE label
    in EXACTLY ONE of two bounded dialects (packet 1120) — the legacy `value` label ATTRIBUTE (→ a quoted target
    `<Calculation>`) OR a child `<Calculation>` label (→ the calc verbatim). Both dialects at once, more than one
    calc child, or any other child refuses — the emitter never guesses which is the label. Label PRESENCE +
    SOURCE and Commit VALUE are shape (signature-encoded); label text is content and never echoed."""
    if (set(p.attrib) - {"type", "value"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog: {slot} carries unexpected attribute(s)/text ({sorted(p.attrib)})")
    bs = p.findall("Boolean")
    calcs = p.findall("Calculation")
    if len(bs) != 1 or bs[0].get("type") != "Commit":
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog: {slot} must hold exactly one type=\"Commit\" Boolean")
    if len(calcs) > 1:
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog: {slot} accounts for at most one calculation-label child")
    if len(list(p)) != 1 + len(calcs):
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog: {slot} carries structure beyond a Commit Boolean + optional label calc")
    if p.get("value") is not None and calcs:
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog: {slot} carries BOTH an attribute label and a calculation label — the two "
                "dialects are exclusive; refused rather than guessing which is the button label")
    if calcs:
        r = _wrapped_calc_reason(calcs[0], "Show Custom Dialog", f"{slot} label")
        if r is not None:
            return r
    b = bs[0]
    if (set(b.attrib) - {"type", "value", "id"}) or len(b) or (b.text or "").strip():
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog: {slot} Commit Boolean carries unexpected attrs/children ({sorted(b.attrib)})")
    if b.get("value") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog: {slot} Commit value {b.get('value')!r} is outside the FileMaker vocabulary")
    return None


def _dialog_input_reason(f, slot) -> "tuple[str, str] | None":
    """One PRESENT `<Parameter type="Field{i}">` input slot (packet 1116, WIDENED packet 1120). Two derivable
    target forms: a VARIABLE target ($name, an optional repetition calc FileMaker's clip projects away) → a
    `<Field>$name</Field>`, or a FIELDREFERENCE target with a REQUIRED TableOccurrenceReference anchor (its id/
    UUID + the repetition projected away) → `<Field table id name/>`. Both carry an optional bounded Password
    Boolean and an optional Label calculation. An EMPTY present target, both/neither target branch, or any other
    structure refuses `dialog_input_slot_unimplemented` (the explicit-empty CLIP slot is synthesized by the
    caller for an ABSENT param, not from a present-empty source). Target/anchor KIND + presence are shape; field/
    variable/label TEXT is content."""
    if (set(f.attrib) - {"type"}) or (f.text or "").strip():
        return ("capability_unaccounted_shape", f"Show Custom Dialog: {slot} is not a bare type parameter")
    tgts = f.findall("Parameter[@type='Target']")
    labels = f.findall("Parameter[@type='Label']")
    pwds = f.findall("Boolean[@type='Password']")
    known = len(tgts) + len(labels) + len(pwds)
    if known != len(list(f)):
        return ("dialog_input_slot_unimplemented",
                f"Show Custom Dialog: {slot} carries structure the input-slot grammar does not implement")
    if len(tgts) != 1:
        return ("dialog_input_slot_unimplemented",
                f"Show Custom Dialog: {slot} must hold exactly one Target parameter")
    if len(pwds) > 1 or len(labels) > 1:
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog: {slot} accounts for at most one Password Boolean and one Label")
    t = tgts[0]
    if (set(t.attrib) - {"type"}) or (t.text or "").strip():
        return ("dialog_input_slot_unimplemented", f"Show Custom Dialog: {slot} Target is not a bare type=\"Target\"")
    vars_ = t.findall("Variable")
    frefs = t.findall("FieldReference")
    if len(list(t)) != 1 or (len(vars_) + len(frefs)) != 1:
        return ("dialog_input_slot_unimplemented",
                f"Show Custom Dialog: {slot} Target must hold exactly one Variable or one FieldReference (the two "
                "derivable input targets); an empty or other target has no matched clip and refuses")
    if frefs:
        r = _field_ref_node_reason(frefs[0], "Show Custom Dialog", require_anchor=True)
        if r is not None:
            return r
    else:
        v = vars_[0]
        if (set(v.attrib) - {"value"}) or v.get("value") is None or (v.text or "").strip():
            return ("capability_unaccounted_shape", f"Show Custom Dialog: {slot} Variable must carry a value ($name)")
        reps = v.findall("repetition")
        extra = sorted({c.tag for c in v if c.tag != "repetition"})
        if extra:
            return ("capability_unaccounted_shape",
                    f"Show Custom Dialog: {slot} Variable unexpected child(ren) {extra}")
        if len(reps) > 1:
            return ("capability_unaccounted_shape", f"Show Custom Dialog: {slot} Variable at most one repetition")
        if reps:
            if set(reps[0].attrib):
                return ("capability_unaccounted_shape",
                        f"Show Custom Dialog: {slot} repetition unexpected attribute(s)")
            r = _calc_subtree_reason(reps[0], "Show Custom Dialog", f"{slot} repetition")
            if r is not None:
                return r
    if pwds:
        pb = pwds[0]
        if (set(pb.attrib) - {"type", "value", "id"}) or len(pb) or (pb.text or "").strip():
            return ("capability_unaccounted_shape",
                    f"Show Custom Dialog: {slot} Password Boolean unexpected attrs/children ({sorted(pb.attrib)})")
        if pb.get("value") not in _DIRECT_BOOLEAN_VALUES:
            return ("capability_unaccounted_shape",
                    f"Show Custom Dialog: {slot} Password value {pb.get('value')!r} is outside the vocabulary")
    if labels:
        lr = _typed_calc_param_reason(labels[0], "Show Custom Dialog", f"{slot} label")
        if lr is not None:
            return lr
    return None


def _cap_show_custom_dialog(step) -> "tuple[str, str] | None":
    """id 87 (Show Custom Dialog) — the COMPLETE dialog grammar validated fail-loud BEFORE evidence (packet
    1116). Accounts for: an optional Title + a required Message calculation; EXACTLY the three ordered Button
    slots (each an optional label attr → quoted target Calculation + one bounded Commit Boolean); and, when any
    Field slot triggers the InputFields block, up to three ordered input slots whose ONLY derivable target is a
    Variable (repetition projected away) with an optional Password Boolean + Label calc. A field input target, an
    empty input target, a missing/duplicate Message, a missing/duplicated/misordered Button, or any unknown
    parameter refuses — the emitter's loop over three buttons/inputs is not proof every arrangement is capability-
    complete. Dialog TEXT (title/message/label/button label/variable name) is content and never enters a reason."""
    params, reason = _step_body(step, "Show Custom Dialog")
    if reason is not None:
        return reason
    types = [p.get("type") for p in params]
    allowed = ({"Title", "Message"} | set(_DIALOG_GEOMETRY_SLOTS)
               | set(_DIALOG_BUTTON_SLOTS) | set(_DIALOG_FIELD_SLOTS))
    unknown = sorted({t for t in types if t not in allowed})
    if unknown:
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog: parameter type(s) {unknown} outside the implemented dialog grammar")
    if types.count("Message") != 1:
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog accounts for exactly one Message; got {types.count('Message')}")
    if types.count("Title") > 1:
        return ("capability_unaccounted_shape", "Show Custom Dialog: at most one Title")
    for slot in _DIALOG_GEOMETRY_SLOTS:
        if types.count(slot) > 1:
            return ("capability_unaccounted_shape", f"Show Custom Dialog: at most one {slot} geometry calculation")
    for slot in _DIALOG_BUTTON_SLOTS:
        if types.count(slot) != 1:
            return ("capability_unaccounted_shape",
                    f"Show Custom Dialog accounts for exactly one {slot}; got {types.count(slot)}")
    for slot in _DIALOG_FIELD_SLOTS:
        if types.count(slot) > 1:
            return ("capability_unaccounted_shape", f"Show Custom Dialog: at most one {slot}")
    expected = ((["Title"] if "Title" in types else []) + ["Message"]
                + [g for g in _DIALOG_GEOMETRY_SLOTS if g in types] + list(_DIALOG_BUTTON_SLOTS)
                + [s for s in _DIALOG_FIELD_SLOTS if s in types])
    if types != expected:
        return ("capability_unaccounted_shape",
                f"Show Custom Dialog: parameters are misordered; expected the sequence {expected}")
    by = {p.get("type"): p for p in params}
    if "Title" in by:
        r = _typed_calc_param_reason(by["Title"], "Show Custom Dialog", "Title")
        if r is not None:
            return r
    r = _typed_calc_param_reason(by["Message"], "Show Custom Dialog", "Message")
    if r is not None:
        return r
    for slot in _DIALOG_GEOMETRY_SLOTS:
        if slot in by:
            r = _typed_calc_param_reason(by[slot], "Show Custom Dialog", f"{slot} geometry")
            if r is not None:
                return r
    for slot in _DIALOG_BUTTON_SLOTS:
        r = _dialog_button_reason(by[slot], slot)
        if r is not None:
            return r
    for slot in _DIALOG_FIELD_SLOTS:
        if slot in by:
            r = _dialog_input_reason(by[slot], slot)
            if r is not None:
                return r
    return None


# ── Replace Field Contents (91) ──
#
# _REPLACE_WITH (the emitter's source-value→target-value map, defined above) is PROMOTED to the capability
# authority: an unmapped mode value refuses `replace_mode_unmapped` BEFORE the emitter's `_REPLACE_WITH[value]`
# lookup (which would otherwise KeyError). _REPLACE_MODE_NAME is the INDEPENDENT matched name↔value coupling.
#
# packet 1120 — the serial mode (2) SerialNumbers block is now value-DRIVEN from the replace List (Skip→
# PerformAutoEnter inverted; Update Entry Options→UpdateEntryOptions identity; Entry option values→UseEntryOptions
# + explicit Initial/increment), so both Boolean values map directly and no longer refuse. The CALCULATION mode
# (3), by contrast, is a measured source-completeness hazard: its clip SerialNumbers reflects the TARGET FIELD's
# serial state/defaults, absent from the step DDR (two captures with the same signature emit different targets),
# so mode 3 is REFUSED capability-first (replace_calculation_serial_state_source_incomplete) — never a guessed
# default, never the pre-1120 aField shape.
_REPLACE_MODE_NAME = {"0": "Current contents", "1": "Current contents",
                      "2": "Replace with serial numbers: ", "3": "Replace with calculation: "}


def _replace_option_bool_reason(lst, btype) -> "tuple[str, str] | None":
    """A nested replace List Boolean (Skip auto-enter options / Update Entry Options): exactly one, bounded to
    the FileMaker Boolean vocabulary. packet 1120 — BOTH values now map directly (Skip→PerformAutoEnter inverted,
    Update→UpdateEntryOptions identity), so neither refuses on value alone."""
    bs = lst.findall(f"Boolean[@type='{btype}']")
    if len(bs) != 1:
        return ("capability_unaccounted_shape",
                f"Replace Field Contents: expected exactly one '{btype}' Boolean; got {len(bs)}")
    b = bs[0]
    if (set(b.attrib) - {"type", "value", "id"}) or len(b) or (b.text or "").strip():
        return ("capability_unaccounted_shape",
                f"Replace Field Contents: '{btype}' Boolean unexpected attrs/children ({sorted(b.attrib)})")
    if b.get("value") not in _DIRECT_BOOLEAN_VALUES:
        return ("capability_unaccounted_shape",
                f"Replace Field Contents: '{btype}' value {b.get('value')!r} is outside the FileMaker Boolean "
                "vocabulary")
    return None


def _replace_list_options_reason(val, lst) -> "tuple[str, str] | None":
    """The per-mode nested option grammar of the replace `<List>` for the STEP-DERIVABLE modes 0/1/2 (packet
    1120; mode 3 is refused BEFORE this by `_cap_replace_field_contents`). Every mode carries exactly one bounded
    'Skip auto-enter options' Boolean. Serial mode (2) additionally carries an 'Entry option values' inner List —
    value True (defer to the field's entry options; no explicit values) OR value False with EXACTLY one
    `<Initial value>` + one `<increment value>` (explicit serial; the numbers are content) — plus a bounded
    'Update Entry Options' Boolean. A calc, an unexpected List/Boolean, a malformed entry-value form, or an
    out-of-vocabulary value refuses by a named reason before emission. Branch/presence are shape."""
    calcs = lst.findall("Calculation")
    inner_lists = lst.findall("List")
    bools = lst.findall("Boolean")
    extra = sorted({c.tag for c in lst if c.tag not in ("Calculation", "List", "Boolean")})
    if extra:
        return ("capability_unaccounted_shape",
                f"Replace Field Contents: the replace List carries unexpected child(ren) {extra}")
    if calcs:
        return ("capability_unaccounted_shape",
                f"Replace Field Contents: mode {val} carries an unexpected <Calculation>")
    sk = _replace_option_bool_reason(lst, "Skip auto-enter options")
    if sk is not None:
        return sk
    if val == "2":
        if len(inner_lists) != 1 or inner_lists[0].get("name") != "Entry option values":
            return ("capability_unaccounted_shape",
                    "Replace Field Contents: serial mode requires exactly one 'Entry option values' inner List")
        eov = inner_lists[0]
        if (set(eov.attrib) - {"name", "value"}) or (eov.text or "").strip():
            return ("capability_unaccounted_shape",
                    "Replace Field Contents: the 'Entry option values' List carries unexpected attrs/text")
        ev = eov.get("value")
        if ev not in _DIRECT_BOOLEAN_VALUES:
            return ("replace_entry_option_values_unmapped",
                    f"Replace Field Contents: 'Entry option values'={ev!r} is outside the FileMaker Boolean "
                    "vocabulary")
        if ev == "True":
            if len(eov):
                return ("capability_unaccounted_shape",
                        "Replace Field Contents: 'Entry option values'=True (defer to the field's entry options) "
                        "carries no explicit Initial/increment children")
        else:                                  # explicit serial — exactly <Initial value> + <increment value>
            init = eov.findall("Initial")
            inc = eov.findall("increment")
            if len(init) != 1 or len(inc) != 1 or len(list(eov)) != 2:
                return ("capability_unaccounted_shape",
                        "Replace Field Contents: explicit serial ('Entry option values'=False) requires EXACTLY "
                        "one <Initial> and one <increment>")
            for node, tag in ((init[0], "Initial"), (inc[0], "increment")):
                if node.get("value") is None or (set(node.attrib) - {"value"}) or len(node) or (node.text or "").strip():
                    return ("capability_unaccounted_shape",
                            f"Replace Field Contents: <{tag}> must carry only a value attribute")
        ue = _replace_option_bool_reason(lst, "Update Entry Options")
        if ue is not None:
            return ue
        if len(bools) != 2:
            return ("capability_unaccounted_shape",
                    "Replace Field Contents: serial mode accounts for exactly the Skip + Update-Entry-Options "
                    f"Booleans; got {len(bools)}")
        return None
    if inner_lists:
        return ("capability_unaccounted_shape", f"Replace Field Contents: mode {val} carries no inner List")
    if len(bools) != 1:
        return ("capability_unaccounted_shape",
                f"Replace Field Contents: mode {val} accounts for exactly one 'Skip auto-enter options' Boolean")
    return None


def _cap_replace_field_contents(step) -> "tuple[str, str] | None":
    """id 91 (Replace Field Contents) — validated fail-loud BEFORE evidence (packet 1116; serial mode made
    value-driven + calculation mode retracted in packet 1120). The replace List's @value (not its misleading
    @name) selects the mode via the promoted _REPLACE_WITH authority (0→None / 1→CurrentContents / 2→SerialNumbers
    / 3→Calculation), with the matched @name↔@value coupling enforced. CALCULATION mode (3) is REFUSED capability-
    first (replace_calculation_serial_state_source_incomplete): its clip <SerialNumbers> reflects the target
    field's serial state/defaults, which the step DDR does not carry, so it is not a function of the source. Modes
    0/1/2 emit: mode 0 forbids a target FieldReference; modes 1/2 require exactly one anchored FieldReference
    (repetition projected away). Serial options are value-driven (both Skip and Update map directly; Entry option
    values selects UseEntryOptions + explicit Initial/increment). The whole List is validated before any first-
    match `.find()`. Field identity and initial/increment TEXT are content; mode, target/anchor presence, and
    serial branch/values are shape."""
    params, reason = _step_body(step, "Replace Field Contents")
    if reason is not None:
        return reason
    bools = [p for p in params if p.get("type") == "Boolean"]
    frefs = [p for p in params if p.get("type") == "FieldReference"]
    reps = [p for p in params if p.get("type") == "replace"]
    if len(bools) + len(frefs) + len(reps) != len(params):
        extra = sorted({p.get("type") for p in params if p.get("type") not in ("Boolean", "FieldReference", "replace")})
        return ("capability_unaccounted_shape",
                f"Replace Field Contents: unaccounted parameter type(s) {extra}")
    if len(bools) != 1:
        return ("capability_unaccounted_shape",
                f"Replace Field Contents accounts for exactly one 'With dialog' Boolean; got {len(bools)}")
    d = _with_dialog_boolean_reason(bools[0], "Replace Field Contents")
    if d is not None:
        return d
    if len(reps) != 1:
        return ("capability_unaccounted_shape",
                f"Replace Field Contents accounts for exactly one 'replace' parameter; got {len(reps)}")
    rp = reps[0]
    if (set(rp.attrib) - {"type"}) or (rp.text or "").strip():
        return ("capability_unaccounted_shape", "Replace Field Contents: the 'replace' parameter is not bare")
    lists = rp.findall("List")
    if len(list(rp)) != 1 or len(lists) != 1:
        return ("capability_unaccounted_shape", "Replace Field Contents: 'replace' must hold exactly one <List>")
    lst = lists[0]
    if set(lst.attrib) - {"name", "value"}:
        return ("capability_unaccounted_shape",
                f"Replace Field Contents: the replace <List> carries unexpected attribute(s) {sorted(lst.attrib)}")
    val = lst.get("value")
    if val not in _REPLACE_WITH:
        return ("replace_mode_unmapped",
                f"Replace Field Contents: replace mode value {val!r} is outside the implemented set "
                f"{sorted(_REPLACE_WITH)} (0/1/2/3) — refused before the target-value lookup")
    if lst.get("name") != _REPLACE_MODE_NAME[val]:
        return ("replace_mode_name_mismatch",
                f"Replace Field Contents: the replace List @name {lst.get('name')!r} does not match the matched "
                f"name for value {val!r} — a name/value mismatch or a raw target spelling used as source refuses "
                "before dictionary lookup")
    if val == "3":
        # packet 1120 — the measured source-completeness hazard. The clip <SerialNumbers> in calculation mode is
        # the TARGET FIELD's serial auto-enter state/defaults, NOT the step DDR: the pre-1120 `aField` capture and
        # the refreshed `PrimaryKey` capture share this exact step signature (field/calc identity is content) yet
        # FileMaker writes DIFFERENT SerialNumbers, so no step-derived projection is faithful. Refused for EVERY
        # calculation-mode Replace step, including the formerly verified one — never a guessed default, never
        # grandfathering a known-wrong signature. A field-aware context/design is a future packet.
        return ("replace_calculation_serial_state_source_incomplete",
                "Replace Field Contents calculation mode: FileMaker's target <SerialNumbers> block reflects the "
                "target field's serial auto-enter state/defaults, which the step's DDR projection does not carry — "
                "two captures with the same step signature produce DIFFERENT SerialNumbers targets, so no step-"
                "derived projection is faithful. Refused pending a field-aware context/design (never a guessed "
                "default, never the pre-1120 shape).")
    if val == "0":
        if frefs:
            return ("capability_unaccounted_shape",
                    "Replace Field Contents: mode 0 (unset/base) accounts for NO target FieldReference; one is "
                    "present and the emitter would emit a configured Restore/SerialNumbers/Field it does not model")
    else:
        if len(frefs) != 1:
            return ("capability_unaccounted_shape",
                    f"Replace Field Contents: replace mode {val} accounts for exactly one target FieldReference; "
                    f"got {len(frefs)}")
        fr_reason = _field_reference_reason(frefs[0], "Replace Field Contents", require_anchor=True)
        if fr_reason is not None:
            return fr_reason
    return _replace_list_options_reason(val, lst)


# The migrated capability registry: step id → rule. As of packet 1116 it holds 190 ids across nineteen families.
# The _emit_noninteract family (packets 1091/1092/1103): the seven SIMPLE one-Boolean ids 9/10/40/51/65/95/
# 104 share the ONE _cap_noninteract_dialog predicate; 26/117 get dedicated predicates (optional count calc /
# `Create folders` Boolean). The DIRECT-BOOLEAN base-shape family (packet 1104): the nine SelectAll ids
# 11/12/13/14/18/46/47/49/60 share _cap_select_all_boolean; 200 (Set Error Logging) and 207 (Revert
# Transaction) get dedicated predicates. The BASE-BARE + TOGGLE families (packet 1105 — the 65 `_emit_bare`
# ids + id 86): 54 CLEAN base-bare ids share _cap_clean_bare; the RAW-projection ids split by form
# (_cap_raw_source_uuid for 7/23/70/73, _cap_raw_owner_id for 237/247); the six flavor-toggle ids
# 85/86/94/115/168/223 share _cap_toggle. The SELECTOR-ENUM + EMBEDDED-INSERT families (packet 1106): the 13
# `_selector_emitter` ids share the ONE _cap_selector predicate (per-id source→target maps in _SELECTOR_SPECS);
# the three embedded-insert ids 56/158/159 share _cap_insert_embedded. The SIMPLE OPTION-BEARING BASE family
# (packet 1107 — 14 ids): the one-named-Boolean base shapes (41/55 via _cap_pause_boolean, 96 _cap_save_addon,
# 126 _cap_constrain_found, 190 _cap_create_data_file); the clean parameterless / optional-Collapsed base
# shapes (64 _cap_send_dde, 127 _cap_extend_found, both delegating to _cap_clean_bare); and the dedicated
# multi-parameter / selector predicates (29 _cap_show_hide_toolbars, 166 _cap_show_hide_menubar, 31
# _cap_adjust_window, 35 _cap_import_records_base, 48 _cap_paste, 97 _cap_set_zoom, 182 _cap_truncate_table).
# These are BASE-shape grammars only — a configured import order (35), an explicit non-current truncate table
# (182), or any richer configured form of the same id refuses. The BOUNDED REFERENCE-BEARING family (packet
# 1108 — 11 ids): Install Menu Set (142 _cap_install_menu_set — one CustomMenuSet reference + Use-as-file-
# default); the object-name family (145/167/180 _cap_object_name — one Object Name calc + per-id repetition
# policy); the WindowReference family (121/123 _cap_window_named, 124 _cap_set_window_title — current vs
# calculated-by-name selection, 124's required Rename); the FieldReference family (17 _cap_goto_field,
# 154 _cap_sort_by_field — one field ref + optional TO anchor / repetition, flattened to the target <Field>);
# and the current-file references (33 _cap_open_file, 34 _cap_close_file — DataSourceReference id="0" only, an
# external target refusing). Reference id/name are content; target-driving topology is signature-repaired (see
# _step_signature). The CALCULATION + DIRECT-CONTENT family (packet 1109 — 18 ids): control flow + comment
# (68/72/125 _cap_condition_calc, 103 _cap_exit_script, 69 _cap_else, 89 _cap_comment); variable/field/result
# calcs (141 _cap_set_variable, 76 _cap_set_field, 77/203 _cap_calc_into_target, 147 _cap_set_field_by_name);
# direct text/selection (61 _cap_insert_text, 130 _cap_set_selection); URL/web-viewer/JS (111 _cap_open_url,
# 146 _cap_set_web_viewer, 175 _cap_perform_js); duration/path (62 _cap_pause_resume, 197 _cap_delete_file).
# Calc/name/path/URL TEXT is content; absent/empty/populated calc, nested position, field-vs-variable target,
# and anchor/repetition topology are shape (signature-repaired where they collapsed). Many carry the SaveAsXML
# provenance bundle alongside <ParameterValues>; `_step_body` tolerates it as target-absent metadata. The
# LAYOUT + WINDOW family (packet 1110 — 5 ids): Go to Layout (6 _cap_goto_layout — LayoutReferenceContainer
# destination + Animation), Go to Related Record (74 _cap_goto_related — the Related subtree + optional new-
# window branch), Move/Resize Window (119 _cap_move_resize_window — packet-1108 window selection composed with
# Bounds), New Window (122 _cap_new_window — complete NewWndStyles + Bounds + Name + layout), Go to List of
# Records (228 _cap_goto_list — its OWN narrow current-layout grammar, not id 6/122's). Shared bounded
# authorities: _LAYOUT_DEST_SPECS (destination↔payload coupling), _ANIMATION (proven clip spellings only),
# _bounds_reason (four ordered optional dims), _newwnd_reason + _WINDOW_STYLE_VALUES (evidenced styles only, no
# arbitrary pass-through). Layout/TO/window names, ids, and calc/bound TEXT are content; destination/payload
# kind, animation mode, selection/current flag, Name-calc presence, per-bound presence, new-window presence,
# and style/option values are topology (signature-repaired for 119/122/74; 121/123/124 stay byte-identical). The
# RECORD + QUERY + STATE family (packet 1111 — 9 ids): record/find/sort/portal navigation (Go to Record 16
# _cap_goto_record — per-mode Records grammar via _GOTO_RECORD_SPECS; Enter Find Mode 22 _cap_enter_find_mode —
# bounded Pause; Perform Find 28 _cap_perform_find — no-query vs a fully-validated variable-length request set;
# Sort Records 39 _cap_sort_records — clear-sort vs a validated variable-length SortList; Go to Portal Row 99
# _cap_goto_portal_row — the By-Calculation portal grammar) and control/state options (Loop 71 _cap_loop —
# explicit _LOOP_FLUSH_MODES; Commit 75 / Refresh Window 80 / Open Transaction 205 — exact named-Boolean sets via
# _named_booleans_reason). Iteration is NOT capability: every request/criterion/sort node is validated fail-loud
# before any Query/SortList. Explicit source→target maps replace every emitter fallback (find→Include/omit→Omit,
# the flush identity map, per-mode RowPageLocation). Request/criteria/sort count + action/direction sequence,
# anchor presence, mode, named-Boolean values, and Restore/option source states are topology (signature-repaired
# id-scoped for 28/39/99; the shared Restore token 42/43/143/144/243 and the "action" Portal-branch users
# 146/187/201 stay byte-identical); field identity, TO name, criterion text, and formulas are content. The
# PRINT + PDF family (packet 1112 — 7 ids): Print Setup (42 _cap_print_setup — empty page-setup verified,
# populated registered source-incomplete), Print (43 _cap_print — _PRINT_TYPE + toFile + all-pages), the PDF
# file ops (244/246 _cap_open_append_pdf, 245 _cap_close_pdf — the File branch only), Create PDF (243
# _cap_create_pdf — in-memory Document/Security/View Options), Save Records as PDF (144 _cap_save_records_as_pdf
# — File/Target/Append destination dispatch). Explicit enum authorities (_PDF_CONTROL_*/_PDF_VIEW_*/_PDF_SOURCE/
# _PDF_SAVE_TYPE) refuse an unmapped value by name; paths/password/metadata are content, destination branch and
# security/view enums are shape. The SCRIPT-INVOCATION + ACCOUNT family (packet 1113 — 8 ids): Perform Script
# (1 _cap_perform_script — script selection + by-name param drop) / on Server (164 _cap_perform_script_server —
# + Wait-for-completion) share the bounded _script_selection_reason (From-list ScriptReference vs By-name name
# calc; external DataSourceReference refuses); the account operations (Change Password 83 _cap_change_password,
# Add Account 134 _cap_add_account, Delete Account 135 _cap_delete_account, Reset Account Password 136
# _cap_reset_password, Enable Account 137 _cap_enable_account, Re-Login 138 _cap_relogin) each get a DEDICATED
# predicate with its exact grammar. _ADD_ACCOUNT_TYPES and _ENABLE_ACCOUNT_OPERATIONS are INDEPENDENT literal
# maps (never a Boolean/List @name pass-through); an external Re-Login reference refuses
# external_file_reference_unsupported. Account names, password formula text, and reference id/name are content;
# selection mode, parameter presence (signature-repaired for 1/164), Wait value, and account operation are
# shape. Credential values are never logged/echoed. The AI-SERVICE + COMMUNICATION family (packet 1114 — 5 ids):
# Configure Machine Learning Model (202 _cap_configure_coreml — explicit _COREML_OPERATIONS map, replacing
# `.capitalize()` as permission), Configure AI Account (212 _cap_configure_ai_account — explicit _LLM_PROVIDER
# map + _LLM_ENDPOINT_PROVIDERS coupling + orthogonal SSL), Configure RAG Account (227 _cap_configure_rag_account
# — its OWN credential/SSL grammar, not the LLM structure), Send Mail (63 _cap_send_mail — a COMPLETE fail-loud
# validator for the whole Email subtree across plain/SMTP/OAuth, with explicit _SMTP_ENCRYPTION/_SMTP_AUTH/
# _OAUTH_PROVIDER maps and enforced mode↔subtree coupling; the _email_fingerprint is evidence discrimination, NOT
# capability), Speak (66 _cap_speak — Voice+Wait base shape; a spoken-text calc refuses speak_text_unimplemented
# rather than a silent drop). Config/message content (API keys, credentials, recipients, subject/body, spoken
# text) is content and NEVER enters a reason string; operation/provider/mode/endpoint/SSL/encryption/auth/voice/
# wait/recipient/attachment/content presence is shape (signature-repaired id-scoped for 63/66). The FILE-I/O
# family (packet 1115 — 9 ids 3/36/37/131/132/143/152/160/225): Save-a-Copy-as-XML/Save-a-Copy (3/37), the
# base-only export ids (36/143/225 — a configured format/Options/data field refuses its OWN feature reason),
# Insert File (131 — five Options siblings + the projected-away Title/Filters/Display trio), Export Field (132),
# Snapshot Link (152), Insert from URL (160). The CLOSEOUT (packet 1116 — the last 2 ids): Show Custom Dialog (87
# _cap_show_custom_dialog — Title/Message/three-Button grammar + the InputFields trigger whose only derivable
# target is a Variable; a field/empty input target refuses dialog_input_slot_unimplemented) and Replace Field
# Contents (91 _cap_replace_field_contents — the four modes with _REPLACE_WITH promoted to the source→target
# authority + _REPLACE_MODE_NAME name↔value coupling; unsettled nested options refuse by name). After 1116
# set(_STEP_CAPABILITY_RULES) == set(VERIFIED_STEP_IDS) — every verified emitter id has a capability-before-
# evidence rule, closing the permission migration begun at packet 1091 (NOT universal FileMaker option coverage).
# An id ABSENT here has no capability rule, so an unseen shape of it refuses (permission = the verified set only).
# Add an id here ONLY with a packet that proves the emitter genuinely consumes that id's whole option grammar
# — never merely because it shares a Python helper with a migrated id.
_STEP_CAPABILITY_RULES = {sid: _cap_noninteract_dialog for sid in (9, 10, 40, 51, 65, 95, 104)}
_STEP_CAPABILITY_RULES[26] = _cap_omit_multiple      # packet 1103 — optional count Calculation
_STEP_CAPABILITY_RULES[117] = _cap_execute_sql       # packet 1103 — second `Create folders` Boolean
_STEP_CAPABILITY_RULES.update(                        # packet 1104 — the SelectAll direct-Boolean family
    {sid: _cap_select_all_boolean for sid in (11, 12, 13, 14, 18, 46, 47, 49, 60)})
_STEP_CAPABILITY_RULES[200] = _cap_set_error_logging  # packet 1104 — one `enabled` Boolean → <Option>
_STEP_CAPABILITY_RULES[207] = _cap_revert_transaction  # packet 1104 — Condition + Error Code (True refuses)
_STEP_CAPABILITY_RULES.update({sid: _cap_clean_bare for sid in _CLEAN_BARE_IDS})       # packet 1105 — rule A
_STEP_CAPABILITY_RULES.update({sid: _cap_raw_source_uuid for sid in _RAW_SOURCE_UUID_IDS})  # 1105 — rule B
_STEP_CAPABILITY_RULES.update({sid: _cap_raw_owner_id for sid in _RAW_OWNER_ID_IDS})        # 1105 — rule B
_STEP_CAPABILITY_RULES.update({sid: _cap_toggle for sid in _TOGGLE_IDS})               # packet 1105 — rule C
_STEP_CAPABILITY_RULES.update({sid: _cap_selector for sid in _SELECTOR_SPECS})         # packet 1106 — selector
_STEP_CAPABILITY_RULES.update({sid: _cap_insert_embedded for sid in _EMBEDDED_INSERT_IDS})  # 1106 — embedded
_STEP_CAPABILITY_RULES.update({sid: _cap_pause_boolean for sid in (41, 55)})           # packet 1107 — Pause
_STEP_CAPABILITY_RULES[96] = _cap_save_addon           # packet 1107 — Replace UUIDs → LinkAvail
_STEP_CAPABILITY_RULES[150] = _cap_perform_quick_find  # packet 1129 — bare or search calc
_STEP_CAPABILITY_RULES[148] = _cap_install_ontimer     # packet 1129 — clear or Script+interval
_STEP_CAPABILITY_RULES[126] = _cap_constrain_found     # packet 1107 — Find without indexes → Option
_STEP_CAPABILITY_RULES[190] = _cap_create_data_file    # packet 1126 — Create folders + optional path (was 1107)
_STEP_CAPABILITY_RULES[188] = _cap_get_file_exists     # packet 1126 — Data File family: path + Target
_STEP_CAPABILITY_RULES[189] = _cap_get_file_size       # packet 1126
_STEP_CAPABILITY_RULES[191] = _cap_open_data_file      # packet 1126
_STEP_CAPABILITY_RULES[192] = _cap_write_data_file     # packet 1126 — Encoding→DataSourceType + id + Target + ALF
_STEP_CAPABILITY_RULES[193] = _cap_read_data_file      # packet 1126 — size dropped; empty form is a FileMaker failure
_STEP_CAPABILITY_RULES[194] = _cap_get_data_file_position   # packet 1126 — id + Target
_STEP_CAPABILITY_RULES[195] = _cap_set_data_file_position   # packet 1126 — id + position (position dropped)
_STEP_CAPABILITY_RULES[196] = _cap_close_data_file     # packet 1126 — id
_STEP_CAPABILITY_RULES[64] = _cap_send_dde             # packet 1107 — parameterless, fixed ContentType=File
_STEP_CAPABILITY_RULES[127] = _cap_extend_found        # packet 1107 — parameterless, fixed Restore=False
_STEP_CAPABILITY_RULES[31] = _cap_adjust_window        # packet 1107 — List window mode (_ADJUST_WINDOW)
_STEP_CAPABILITY_RULES[29] = _cap_show_hide_toolbars   # packet 1107 — Lock + IERT + Show/Hide List
_STEP_CAPABILITY_RULES[166] = _cap_show_hide_menubar   # packet 1107 — Show/Hide List + Lock
_STEP_CAPABILITY_RULES[35] = _cap_import_records_base   # packet 1107 — Verify SSL + With dialog (base only)
_STEP_CAPABILITY_RULES[48] = _cap_paste                # packet 1107 — Select + No style
_STEP_CAPABILITY_RULES[97] = _cap_set_zoom             # packet 1107 — Lock + zoom List (_ZOOM_LEVELS)
_STEP_CAPABILITY_RULES[182] = _cap_truncate_table      # packet 1107 — With dialog + <Current Table> List
_STEP_CAPABILITY_RULES[142] = _cap_install_menu_set    # packet 1108 — CustomMenuSet ref + Use-as-file-default
_STEP_CAPABILITY_RULES.update({sid: _cap_object_name for sid in (145, 167, 180)})   # 1108 — object-name family
_STEP_CAPABILITY_RULES.update({sid: _cap_window_named for sid in (121, 123)})       # 1108 — WindowReference
_STEP_CAPABILITY_RULES[124] = _cap_set_window_title    # packet 1108 — WindowReference + required Rename
_STEP_CAPABILITY_RULES[17] = _cap_goto_field           # packet 1108 — Select/perform Boolean + FieldReference
_STEP_CAPABILITY_RULES[154] = _cap_sort_by_field       # packet 1108 — sort List + FieldReference
_STEP_CAPABILITY_RULES[33] = _cap_open_file            # packet 1108 — Open hidden + current-file DataSource
_STEP_CAPABILITY_RULES[34] = _cap_close_file           # packet 1108 — current-file DataSource only
_STEP_CAPABILITY_RULES[68] = _cap_if                   # packet 1109 — condition calc (+ Collapsed)
_STEP_CAPABILITY_RULES[72] = _cap_exit_loop_if         # packet 1109 — condition calc
_STEP_CAPABILITY_RULES[125] = _cap_else_if             # packet 1109 — condition calc (+ Collapsed)
_STEP_CAPABILITY_RULES[103] = _cap_exit_script         # packet 1109 — optional result calc
_STEP_CAPABILITY_RULES[69] = _cap_else                 # packet 1109 — two Collapsed markers
_STEP_CAPABILITY_RULES[89] = _cap_comment              # packet 1109 — Comment value → Text (set/bare)
_STEP_CAPABILITY_RULES[141] = _cap_set_variable        # packet 1109 — value/Name/repetition
_STEP_CAPABILITY_RULES[76] = _cap_set_field            # packet 1109 — FieldReference target + value calc
_STEP_CAPABILITY_RULES[77] = _cap_insert_calc_result   # packet 1109 — Select + Target + value calc
_STEP_CAPABILITY_RULES[203] = _cap_execute_data_api    # packet 1109 — Select + Target + value calc
_STEP_CAPABILITY_RULES[147] = _cap_set_field_by_name   # packet 1109 — positions 0 (Result) / 1 (TargetName)
_STEP_CAPABILITY_RULES[61] = _cap_insert_text          # packet 1109 — Select + optional Target + Text set/empty
_STEP_CAPABILITY_RULES[130] = _cap_set_selection       # packet 1109 — Start/End bounds + optional FieldReference
_STEP_CAPABILITY_RULES[111] = _cap_open_url            # packet 1109 — two Booleans + URL calc
_STEP_CAPABILITY_RULES[146] = _cap_set_web_viewer      # packet 1109 — action map + ObjectName + URL calc
_STEP_CAPABILITY_RULES[175] = _cap_perform_js          # packet 1109 — Name + FunctionRef (zero-argument)
_STEP_CAPABILITY_RULES[62] = _cap_pause_resume         # packet 1109 — Duration mode + seconds calc
_STEP_CAPABILITY_RULES[197] = _cap_delete_file         # packet 1109 — single UniversalPathList/Location
_STEP_CAPABILITY_RULES[6] = _cap_goto_layout           # packet 1110 — LRC destination + Animation
_STEP_CAPABILITY_RULES[74] = _cap_goto_related         # packet 1110 — Related subtree + new-window branch
_STEP_CAPABILITY_RULES[119] = _cap_move_resize_window  # packet 1110 — window selection + bounds
_STEP_CAPABILITY_RULES[122] = _cap_new_window          # packet 1110 — new-window style/bounds/name/layout
_STEP_CAPABILITY_RULES[228] = _cap_goto_list           # packet 1110 — narrow current-layout grammar
_STEP_CAPABILITY_RULES[16] = _cap_goto_record          # packet 1111 — per-mode Records grammar
_STEP_CAPABILITY_RULES[22] = _cap_enter_find_mode      # packet 1111 — bounded Pause Boolean
_STEP_CAPABILITY_RULES[28] = _cap_perform_find         # packet 1111 — no-query vs validated request set
_STEP_CAPABILITY_RULES[39] = _cap_sort_records         # packet 1111 — clear-sort vs validated SortList
_STEP_CAPABILITY_RULES[99] = _cap_goto_portal_row      # packet 1111 — By-Calculation portal grammar
_STEP_CAPABILITY_RULES[71] = _cap_loop                 # packet 1111 — explicit flush-mode map
_STEP_CAPABILITY_RULES[75] = _cap_commit_records       # packet 1111 — three named Booleans
_STEP_CAPABILITY_RULES[80] = _cap_refresh_window       # packet 1111 — two named Booleans
_STEP_CAPABILITY_RULES[205] = _cap_open_transaction    # packet 1111 — three named Booleans + Collapsed
_STEP_CAPABILITY_RULES[42] = _cap_print_setup          # packet 1112 — empty verified / populated source-incomplete
_STEP_CAPABILITY_RULES[43] = _cap_print                # packet 1112 — print type + toFile + pages grammar
_STEP_CAPABILITY_RULES[144] = _cap_save_records_as_pdf  # packet 1112 — File/Target/Append PDF branches
_STEP_CAPABILITY_RULES[243] = _cap_create_pdf          # packet 1112 — in-memory Options grammar
_STEP_CAPABILITY_RULES[244] = _cap_open_append_pdf     # packet 1112 — Append PDF File branch
_STEP_CAPABILITY_RULES[245] = _cap_close_pdf           # packet 1112 — Close PDF File branch
_STEP_CAPABILITY_RULES[246] = _cap_open_append_pdf     # packet 1112 — Open PDF File branch
_STEP_CAPABILITY_RULES[1] = _cap_perform_script        # packet 1113 — script selection + by-name param drop
_STEP_CAPABILITY_RULES[164] = _cap_perform_script_server  # packet 1113 — + Wait-for-completion Boolean
_STEP_CAPABILITY_RULES[83] = _cap_change_password      # packet 1113 — Old + New + With-dialog
_STEP_CAPABILITY_RULES[134] = _cap_add_account         # packet 1113 — AccountType map + privilege ref
_STEP_CAPABILITY_RULES[135] = _cap_delete_account      # packet 1113 — one account-name calc
_STEP_CAPABILITY_RULES[136] = _cap_reset_password      # packet 1113 — Name + Password + change-on-login
_STEP_CAPABILITY_RULES[137] = _cap_enable_account      # packet 1113 — enable operation map (name↔value)
_STEP_CAPABILITY_RULES[138] = _cap_relogin             # packet 1113 — current-file only; external refuses
_STEP_CAPABILITY_RULES[202] = _cap_configure_coreml    # packet 1114 — explicit operation map (uninstall)
_STEP_CAPABILITY_RULES[212] = _cap_configure_ai_account  # packet 1114 — provider map + endpoint coupling + SSL
_STEP_CAPABILITY_RULES[227] = _cap_configure_rag_account  # packet 1114 — own RAG credential/SSL grammar
_STEP_CAPABILITY_RULES[63] = _cap_send_mail            # packet 1114 — whole Email subtree, three modes
_STEP_CAPABILITY_RULES[66] = _cap_speak                # packet 1114 — Voice+Wait base; spoken text refuses
_STEP_CAPABILITY_RULES[3] = _cap_save_as_xml           # packet 1115 — 3 Booleans + path + options calc
_STEP_CAPABILITY_RULES[37] = _cap_save_a_copy_as       # packet 1115 — explicit Copy map + optional path
_STEP_CAPABILITY_RULES[36] = _cap_export_records       # packet 1115 — base only; format refuses
_STEP_CAPABILITY_RULES[143] = _cap_save_excel          # packet 1115 — base only; worksheet Options refuses
_STEP_CAPABILITY_RULES[225] = _cap_save_jsonl          # packet 1115 — base only; data-complete refuses
_STEP_CAPABILITY_RULES[131] = _cap_insert_file         # packet 1115 — Options siblings + projected-away trio
_STEP_CAPABILITY_RULES[132] = _cap_export_field        # packet 1115 — FieldReference + optional path
_STEP_CAPABILITY_RULES[152] = _cap_snapshot_link       # packet 1115 — explicit source map + path
_STEP_CAPABILITY_RULES[160] = _cap_insert_from_url     # packet 1115 — URL/target/cURL/Boolean topology
_STEP_CAPABILITY_RULES[87] = _cap_show_custom_dialog   # packet 1116 — Title/Message/3 Buttons/InputFields
_STEP_CAPABILITY_RULES[91] = _cap_replace_field_contents  # packet 1116 — 4 modes + per-mode option grammar


class StepAssessment(NamedTuple):
    """The single structured verdict for one DDR <Step> under the packet-1086 fmClip epoch (packet 1091 —
    the script analogue of field_emit.FieldAssessment).

    permission is the emit/refuse gate under DEFAULT (non-strict) policy; evidence separates a byte-captured
    emit (verified) from a capability-complete uncaptured one (experimental) and from a registered class-2
    shape (source_incomplete); result_state is the canonical fmClip-epoch state; reason_code is stable for
    machines; detail names the concrete source feature; step_id/name/signature are diagnostic;
    source_incomplete carries the registered _SOURCE_INCOMPLETE_SIGS entry (or None). Strict/verified-only is
    a caller POLICY applied ON TOP of this verdict — see _blocked_reason; the assessment itself is
    strict-agnostic so one object describes the step's nature once."""
    permission: str       # "emit" | "refuse"  (default policy)
    evidence: str         # "verified" | "experimental" | "source_incomplete" | "none"
    result_state: str     # generated_verified | generated_experimental | generated_static_valid | refused_known_hazard
    reason_code: str
    detail: str
    step_id: object       # int | None
    name: object
    signature: tuple
    source_incomplete: object   # dict | None
    external_resolution: object = None   # packet 1118 — crossfile.ExternalResolution | None (reporting only,
                                         # attached when an external-file DataSourceReference is resolved
                                         # against a supplied ClipEmitContext; NEVER affects permission)


# ── external-file reference resolver (packet 1118) — pure, reporting-only, privacy-safe ──────────

def _external_dsr_for_family(step, sid):
    """The one LEGAL external `<DataSourceReference>` node for a family step, or None when there is nothing
    to resolve (current-file id=0, no reference, or a placement/coupling the capability rule would refuse as
    malformed — those keep their existing behavior). Never a catalog-lookup success on a malformed tree.
      33/34/138 — a top-level `<Parameter type="DataSourceReference">` holding one reference.
      1/164     — a `<DataSourceReference>` inside the From-list script-selection `<List>`, coupled to
                  exactly one `<ScriptReference>`."""
    pv = step.find("ParameterValues")
    params = pv.findall("Parameter") if pv is not None else []
    if sid in (33, 34, 138):
        dsrps = [p for p in params if p.get("type") == "DataSourceReference"]
        if len(dsrps) != 1:
            return None
        p = dsrps[0]
        if (set(p.attrib) - {"type"}) or (p.text or "").strip():
            return None
        dsrs = p.findall("DataSourceReference")
        if len(list(p)) != 1 or len(dsrs) != 1:
            return None
        return dsrs[0] if _is_external_dsr(dsrs[0]) else None
    # ids 1 / 164 — the From-list selection List
    lps = [p for p in params if p.get("type") == "List"]
    if len(lps) != 1:
        return None
    l = lps[0].find("List")
    if l is None or l.get("name") != "From list":
        return None
    dsrs = l.findall("DataSourceReference")
    srefs = l.findall("ScriptReference")
    if len(dsrs) != 1 or len(srefs) != 1:      # external From-list couples one DataSourceReference + one ScriptReference
        return None
    return dsrs[0] if _is_external_dsr(dsrs[0]) else None


def _is_external_dsr(d) -> bool:
    """A well-formed EXTERNAL DataSourceReference: attrs ⊆ {id, name, UUID}, no children, id + name present,
    id != "0". The current-file id="0" form and any malformed tree return False (left to existing behavior)."""
    if (set(d.attrib) - {"id", "name", "UUID"}) or len(d):
        return False
    if d.get("id") is None or d.get("name") is None or d.get("id") == "0":
        return False
    return True


def resolve_external_reference(step, context):
    """A pure, privacy-safe resolution verdict (`crossfile.ExternalResolution`) for one DDR step's
    external-file reference, or None when there is nothing to resolve — not one of the five families, no
    context/authority, the current-file form, no reference, or a malformed placement (those keep their
    existing capability behavior). Reporting ONLY: it NEVER changes permission, and `resolved_unverified`
    is not a licence to emit. (packet 1118 §D)"""
    if context is None or getattr(context, "external_data_sources", None) is None:
        return None
    try:
        sid = int(step.get("id"))
    except (TypeError, ValueError):
        return None
    if sid not in _EXTERNAL_REF_STEP_IDS:
        return None
    d = _external_dsr_for_family(step, sid)
    if d is None:
        return None
    return context.resolve_external(d.get("id"), d.get("name"))


# ── packet 1119 — captured external-file emission for the five families ──────────────────────────
#
# Resolution now PARTICIPATES in permission (packet 1118 only reported). For a family step carrying a
# well-formed external <DataSourceReference>, the step emits its external clip branch ONLY when the family's
# external option grammar holds (capability-first, checked BEFORE any catalog lookup) AND the reference
# uniquely resolves to one FileMaker sibling with EXACTLY one path alternative. Resolution alone never grants
# permission; a multi-path / ambiguous / non-FileMaker / unresolved / context-less / malformed form refuses by
# a named reason and withholds the whole script. The raw path is CLIP CONTENT — it reaches the emitter through
# `resolve_external_path` and NEVER a reason/report/log. FileReference id/name follow the resolved entry and
# the agreeing step reference, with no normalization (§B).

_FAM_NAME = {1: "Perform Script", 33: "Open File", 34: "Close File",
             138: "Re-Login", 164: "Perform Script on Server"}


def _file_reference_el(parent, ref_id, ref_name, raw_path):
    """§B — the ONE bounded external FileReference projection: <FileReference id name><UniversalPathList>path.
    id/name follow the resolved catalog entry + agreeing step reference; the raw path is preserved EXACTLY —
    no basename extraction, suffix addition, normalization, alias substitution, or path-derived id. The path is
    clip CONTENT; it never enters a reason/report/log."""
    fr = ET.SubElement(parent, "FileReference", {"id": ref_id, "name": ref_name})
    ET.SubElement(fr, "UniversalPathList").text = raw_path
    return fr


def _emit_open_file_external(step, file_ref):  # 33 — Option(Open hidden) · DisableStepCollapsed · FileReference
    s = _new_step(step)
    ET.SubElement(s, "Option", {"state": _first_bool_value(step)})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    _file_reference_el(s, *file_ref)
    return s


def _emit_close_file_external(step, file_ref):  # 34 — DisableStepCollapsed · FileReference
    s = _step_el(step, restore=False)
    _file_reference_el(s, *file_ref)
    return s


def _emit_perform_script_external(step, file_ref):  # 1 — Disable · FileReference · Script (empty param → no calc)
    s = _new_step(step)
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    _file_reference_el(s, *file_ref)
    ref = step.find(".//Parameter[@type='List']/List/ScriptReference")
    ET.SubElement(s, "Script", {"id": ref.get("id") or "", "name": ref.get("name") or ""})
    return s                                    # no CurrentScript and no empty <Calculation> in the captured target


def _emit_perform_script_server_external(step, file_ref):  # 164 — Wait · Disable · FileReference · Calc · Script
    lst = step.find(".//Parameter[@type='List']/List")
    param = step.find(".//Parameter[@type='Parameter']/Parameter")
    param_calc = _inner_text(param) if param is not None else ""
    s = _new_step(step)
    ET.SubElement(s, "WaitForCompletion", {"state": _bool_state(step, "Wait for completion")})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    _file_reference_el(s, *file_ref)
    if param_calc:                              # populated (captured); an empty-param external PSoS omits it
        ET.SubElement(s, "Calculation").text = param_calc
    ref = lst.find("ScriptReference")
    ET.SubElement(s, "Script", {"id": ref.get("id") or "", "name": ref.get("name") or ""})
    return s


def _emit_relogin_external(step, file_ref):    # 138 — NoInteract · Disable · FileReference · [AccountName/Password]
    s = _new_step(step)
    ET.SubElement(s, "NoInteract",
                  {"state": "True" if _bool_state(step, "With dialog") == "False" else "False"})
    ET.SubElement(s, "DisableStepCollapsed", {"state": _collapsed_state(step)})
    _file_reference_el(s, *file_ref)
    if step.find(".//Parameter[@type='Name']") is not None:   # credential coupling enforced by the option rule
        _account_name_password(s, step)
    return s


_EXTERNAL_EMITTERS = {33: _emit_open_file_external, 34: _emit_close_file_external,
                      1: _emit_perform_script_external, 164: _emit_perform_script_server_external,
                      138: _emit_relogin_external}


def _external_from_list_reason(p, fam) -> "tuple[str, str] | None":
    """The external From-list script selection (ids 1/164): one <List name="From list" value> holding EXACTLY
    one external <DataSourceReference> (validated + resolved elsewhere) + one <ScriptReference id name [UUID]>,
    no name <Calculation>. id/name are content; UUID dropped. A malformed shape refuses capability-first."""
    if (set(p.attrib) - {"type"}) or (p.text or "").strip():
        return ("capability_unaccounted_shape", f"{fam}: the selection parameter is not a bare type=\"List\"")
    lists = p.findall("List")
    if len(list(p)) != 1 or len(lists) != 1:
        return ("capability_unaccounted_shape", f"{fam}: the selection must hold exactly one <List>")
    l = lists[0]
    exp_value = _SCRIPT_SELECTION["From list"][0]
    if l.get("name") != "From list" or (set(l.attrib) - {"name", "value"}) or l.get("value") not in (None, exp_value):
        return ("capability_unaccounted_shape",
                f"{fam}: external selection must be a From-list <List> with the coupled value {exp_value!r}")
    dsrs = l.findall("DataSourceReference")
    srefs = l.findall("ScriptReference")
    if len(dsrs) != 1 or len(srefs) != 1 or l.findall("Calculation") or len(list(l)) != 2:
        return ("capability_unaccounted_shape",
                f"{fam}: external From-list must couple exactly one <DataSourceReference> + one <ScriptReference>")
    r = srefs[0]
    if (set(r.attrib) - {"id", "name", "UUID"}) or r.get("id") is None or r.get("name") is None or len(r):
        return ("capability_unaccounted_shape", f"{fam}: <ScriptReference> must carry id + name and no children")
    return None


def _ext_opt_open_file(step) -> "tuple[str, str] | None":     # 33
    params, reason = _step_body(step, "Open File")
    if reason is not None:
        return reason
    if len(params) != 2 or params[1].get("type") != "DataSourceReference":
        return ("capability_unaccounted_shape",
                "external Open File accounts for an 'Open hidden' Boolean + an external DataSourceReference")
    return _bare_boolean_reason(params[0], "Open hidden", "Open File", values=_DIRECT_BOOLEAN_VALUES)


def _ext_opt_close_file(step) -> "tuple[str, str] | None":    # 34
    params, reason = _step_body(step, "Close File")
    if reason is not None:
        return reason
    if len(params) != 1 or params[0].get("type") != "DataSourceReference":
        return ("capability_unaccounted_shape", "external Close File accounts for exactly one DataSourceReference")
    return None


def _ext_opt_perform_script(step) -> "tuple[str, str] | None":  # 1
    params, reason = _step_body(step, "Perform Script")
    if reason is not None:
        return reason
    if len(params) != 2 or params[0].get("type") != "List" or params[1].get("type") != "Parameter":
        return ("capability_unaccounted_shape",
                "external Perform Script accounts for a From-list selection + a Parameter block")
    r = _external_from_list_reason(params[0], "Perform Script")
    if r is not None:
        return r
    presence, r = _script_parameter_reason(params[1], "Perform Script")
    if r is not None:
        return r
    if presence == "set":
        return ("perform_script_external_parameter_unsupported",
                "external From-list mode with a populated script parameter — no matched external pair proves "
                "FileMaker retains it here (the captured external Perform Script parameter is empty), so the step "
                "refuses rather than silently dropping or inventing it; do not infer it from Perform Script on Server")
    return None


def _ext_opt_perform_script_server(step) -> "tuple[str, str] | None":  # 164
    params, reason = _step_body(step, "Perform Script on Server")
    if reason is not None:
        return reason
    if (len(params) != 3 or params[0].get("type") != "List" or params[1].get("type") != "Parameter"
            or params[2].get("type") != "Boolean"):
        return ("capability_unaccounted_shape",
                "external Perform Script on Server accounts for a From-list selection + a Parameter block + a "
                "'Wait for completion' Boolean")
    r = _external_from_list_reason(params[0], "Perform Script on Server")
    if r is not None:
        return r
    _, r = _script_parameter_reason(params[1], "Perform Script on Server")
    if r is not None:
        return r
    return _bare_boolean_reason(params[2], "Wait for completion", "Perform Script on Server",
                                values=_DIRECT_BOOLEAN_VALUES)


def _ext_opt_relogin(step) -> "tuple[str, str] | None":       # 138
    params, reason = _step_body(step, "Re-Login")
    if reason is not None:
        return reason
    if (len(params) not in (2, 4) or params[0].get("type") != "DataSourceReference"
            or params[1].get("type") != "Boolean"):
        return ("capability_unaccounted_shape",
                "external Re-Login accounts for a DataSourceReference + a 'With dialog' Boolean, optionally "
                "followed by a Name calc + a Password calc (credentials both-present or both-absent)")
    r = _bare_boolean_reason(params[1], "With dialog", "Re-Login", values=_DIRECT_BOOLEAN_VALUES)
    if r is not None:
        return r
    if len(params) == 4:                        # credential coupling: both present
        if params[2].get("type") != "Name" or params[3].get("type") != "Password":
            return ("capability_unaccounted_shape",
                    "Re-Login: the credential pair must be a Name calc + a Password calc, in that order")
        r = _typed_calc_param_reason(params[2], "Re-Login", "account-name calculation")
        if r is not None:
            return r
        return _typed_calc_param_reason(params[3], "Re-Login", "password calculation")
    return None                                 # 2-param: both credentials absent — the coupling holds


_EXTERNAL_OPTION_RULES = {33: _ext_opt_open_file, 34: _ext_opt_close_file, 1: _ext_opt_perform_script,
                          164: _ext_opt_perform_script_server, 138: _ext_opt_relogin}


def _external_branch_assessment(step, context):
    """packet 1119 §D — the context-aware EXTERNAL emission verdict for the five families:
        None                       — no (well-formed) external form here; base behavior applies unchanged.
        ("refuse", code, detail)   — an external form that cannot emit (no context, catalog absent, unresolved/
                                     ambiguous, non-FileMaker, multi-path, or a malformed per-family grammar).
        ("emit", file_ref, ev)     — resolved to a unique FileMaker one-path entry AND the family's external
                                     grammar holds; file_ref=(id, name, raw_path); ev ∈ {"verified","experimental"}.
    Capability-first: the per-family option grammar is validated BEFORE any catalog lookup, so a malformed
    external form refuses without a string-match resolution. Only a single-path FileMaker entry emits."""
    try:
        sid = int(step.get("id"))
    except (TypeError, ValueError):
        return None
    if sid not in _EXTERNAL_REF_STEP_IDS:
        return None
    d = _external_dsr_for_family(step, sid)
    if d is None:
        return None                             # current-file / no-ref / malformed placement → base handles it
    fam = _FAM_NAME[sid]
    opt = _EXTERNAL_OPTION_RULES[sid](step)     # capability-first (no lookup yet)
    if opt is not None:
        return ("refuse", opt[0], opt[1])
    if context is None or getattr(context, "external_data_sources", None) is None:
        return ("refuse", "external_file_reference_unresolved",
                f"{fam}: an external-file reference needs a resolution context to emit; none was supplied, so the "
                "step refuses rather than inventing a file/path")
    res = context.resolve_external(d.get("id"), d.get("name"))
    if res is None or not res.resolved:
        detail = res.detail if res is not None else "no resolution authority"
        code = f"external_file_{res.status}" if res is not None else "external_file_reference_unresolved"
        return ("refuse", code, detail)
    if res.path_alternative_count != 1:
        return ("refuse", "external_file_multiple_paths",
                f"the resolved FileMaker entry declares {res.path_alternative_count} path alternatives; only the "
                "single-path grammar is implemented, so it refuses rather than choosing one")
    raw_path = context.resolve_external_path(d.get("id"), d.get("name"))
    if not raw_path:                            # defensive — single path guaranteed by the count check above
        return ("refuse", "external_file_reference_unresolved",
                "the resolved entry yielded no single path")
    file_ref = (d.get("id") or "", d.get("name") or "", raw_path)
    ev = "verified" if _step_signature(step) in _VERIFIED_SIGS.get(sid, set()) else "experimental"
    return ("emit", file_ref, ev)


# ── packet 1123 Stage C — the flavor authority (assessment must agree with emitted bytes) ────────
# The one place where the WHOLE-SCRIPT XMSC clip and the BARE-STEPS XMSS clip diverge is the toggle
# family (`_XMSS_SET_STATE`). XMSS's native pair carries a leading <Set state>; FileMaker's native
# COPIED XMSC is bare. Stage C makes the GENERATED XMSC preserve the state with the same <Set> child
# (live-paste-proven, Scratch3/Scratch4) — but that deliberately differs from the native XMSC bytes, so
# the XMSC toggle is `generated_experimental` (paste-proven, NOT native byte-exact) and strict refuses
# it, while XMSS stays `generated_verified`. The SAME flavor must reach assessment AND emission so the
# label can never disagree with the bytes; callers thread it explicitly (default 'xmsc' = the
# whole-script default). No id outside `_XMSS_SET_STATE` is affected.
XMSC_TOGGLE_DIALECT_REASON = "xmsc_state_preserving_dialect"
_XMSC_TOGGLE_DIALECT_DETAIL = (
    "the generated XMSC clip preserves the source On/Off state with a leading <Set state> child — live "
    "paste proved FileMaker accepts it for all 12 tested toggle cases (Scratch3 id-86, Scratch4 the "
    "other five), but FileMaker's OWN copied XMSC projection is bare/lossy, so this deliberate "
    "state-preserving dialect is NOT byte-exact against the native XMSC pair (verified only under XMSS); "
    "strict/verified-only output refuses it")


def _flavor_adjusted(a: StepAssessment, flavor: str) -> StepAssessment:
    """Apply the flavor authority to a base assessment (packet 1123 Stage C). Only the toggle family under
    `flavor='xmsc'` changes: a would-be `verified` toggle becomes `experimental` with a stable dialect
    reason, because generated XMSC now carries a <Set> child the native XMSC pair omits. XMSS, every
    non-toggle id, and any already-refused/experimental/source-incomplete toggle are returned unchanged."""
    if flavor == "xmsc" and a.permission == "emit" and a.evidence == "verified" \
            and a.step_id in _XMSS_SET_STATE:
        return a._replace(evidence="experimental", result_state="generated_experimental",
                          reason_code=XMSC_TOGGLE_DIALECT_REASON, detail=_XMSC_TOGGLE_DIALECT_DETAIL)
    return a


def step_generation_assessment(step, *, context=None, flavor: str = "xmsc") -> StepAssessment:
    """Emit/refuse permission + evidence for one DDR <Step> (packet 1091), plus context-aware external-file
    handling. The base verdict is context-independent — an external form still REFUSES exactly as before
    (`context=None` returns the base verdict unchanged, byte-for-byte).

    When a `context` with an external-data-source authority is supplied, the verdict additionally carries the
    privacy-safe `external_resolution` for reporting (packet 1118), and — for the five external-reference
    families — external EMISSION PERMISSION participates (packet 1119): a well-formed external form that
    resolves to a unique FileMaker one-path sibling AND passes its family's external grammar EMITS
    (`generated_verified` if the exact external shape is a committed pair, else `generated_experimental`);
    every unresolved / ambiguous / non-FileMaker / multi-path / malformed / context-less external form REFUSES
    by a named reason. Resolution alone never grants permission.

    `flavor` (packet 1123 Stage C — default 'xmsc', the whole-script default) is the authority that must equal
    the EMISSION flavor: for the toggle family the generated XMSC now carries a state-preserving <Set> child,
    so an XMSC toggle is `generated_experimental` (paste-proven, not native-byte-exact) while XMSS stays
    verified. See _flavor_adjusted; no other id is affected."""
    a = _assess_step_base(step)
    if context is not None:
        res = resolve_external_reference(step, context)        # privacy-safe reporting verdict (may be None)
        branch = _external_branch_assessment(step, context)    # packet 1119 — external emission permission
        if branch is not None:
            if branch[0] == "emit":
                _, _file_ref, ev = branch
                state = "generated_verified" if ev == "verified" else "generated_experimental"
                code = "verified" if ev == "verified" else "capability_complete_uncaptured_external"
                detail = ("" if ev == "verified" else
                          "an external-file reference resolved to a unique FileMaker one-path sibling and this "
                          "family's external grammar is fully accounted for, but this exact external shape has "
                          "no committed (DDR, clip) pair — emits experimentally (static-valid, correct by "
                          "construction, NOT FileMaker-verified)")
                a = StepAssessment("emit", ev, state, code, detail, a.step_id, a.name, a.signature, None,
                                   external_resolution=res)
            else:
                _, rcode, rdetail = branch
                a = StepAssessment("refuse", "none", "refused_known_hazard", rcode,
                                   f"step id {a.step_id} ({a.name}): {rdetail}", a.step_id, a.name,
                                   a.signature, None, external_resolution=res)
        elif res is not None:
            a = a._replace(external_resolution=res)
    return _flavor_adjusted(a, flavor)


def _assess_step_base(step) -> StepAssessment:
    """Emit/refuse permission + evidence for one DDR <Step> (packet 1091). The SINGLE permission authority
    for emit_step / emit_script_clip / export_object_clip. Strict-AGNOSTIC — a caller applies verified-only
    policy via _blocked_reason.

    Order — CAPABILITY BEFORE EVIDENCE for registered ids (packet 1104 correction of the packet-1091 order):
      1. unreadable id / no emitter          → refuse (no_emitter)
      2a. id HAS a registered capability rule:
          · rule refuses                     → refuse (its named hazard) — EVEN IF the signature collides
            with a verified one. `_step_signature` flattens away extra attrs/children/non-Parameter siblings,
            so a malformed source could otherwise inherit a verified verdict without passing the fail-loud
            grammar. Capability is the gate; evidence only labels what capability already accepted.
          · rule accepts + exact verified sig → emit, verified
          · rule accepts + source-incomplete  → emit, source_incomplete (default; preserved for any overlap)
          · rule accepts + otherwise          → emit, experimental
      2b. id has NO registered rule (pre-1104 order stands):
          · exact verified signature          → emit, verified
          · registered source-incomplete shape→ emit, source_incomplete (default) — strict refuses via policy
          · otherwise                         → refuse, capability_unaccounted_shape

    The final refuse is a concrete SILENT-OMISSION hazard: an emitter exists, but no capability rule declares
    it consumes this option shape, so it refuses rather than emit with unmodelled options dropped. It is NOT
    worded as 'no captured pair, therefore no permission', and it never asks the user for a capture."""
    name = step.get("name")
    try:
        sid = int(step.get("id"))
    except (TypeError, ValueError):
        return StepAssessment("refuse", "none", "refused_known_hazard", "unreadable_step_id",
                              "unreadable step id", None, name, (), None)
    sig = _step_signature(step)
    if sid not in _EMITTERS:
        return StepAssessment("refuse", "none", "refused_known_hazard", "no_emitter",
                              "unsupported step type", sid, name, sig, None)

    def _verified():
        return StepAssessment("emit", "verified", "generated_verified", "verified", "", sid, name, sig, None)

    def _source_incomplete(entry):
        return StepAssessment(
            "emit", "source_incomplete", "generated_static_valid", "source_incomplete",
            "registered class-2 (source-completeness) shape — the clip needs data the DDR projection never "
            "held; emits its schema-held minimum, labelled source-incomplete (never invented)",
            sid, name, sig, entry)

    rule = _STEP_CAPABILITY_RULES.get(sid)
    if rule is not None:
        # CAPABILITY BEFORE EVIDENCE (packet 1104): validate the actual source tree first, so a malformed
        # shape whose signature collides with a verified one is refused rather than handed a verified pass.
        cap = rule(step)
        if cap is not None:
            code, detail = cap
            return StepAssessment("refuse", "none", "refused_known_hazard", code,
                                  f"step id {sid} ({name}): {detail}", sid, name, sig, None)
        if sig in _VERIFIED_SIGS[sid]:
            return _verified()
        entry = _source_incomplete_entry(step)   # preserved for any future rule+class-2 overlap
        if entry is not None:
            return _source_incomplete(entry)
        return StepAssessment(
            "emit", "experimental", "generated_experimental", "capability_complete_uncaptured",
            "every source feature of this step is accounted for by the current emitter, but this exact "
            "id/shape has no committed (DDR, clip) pair — emits experimentally (static-valid, correct "
            "by construction, NOT FileMaker-verified)", sid, name, sig, None)

    if sig in _VERIFIED_SIGS[sid]:
        return _verified()
    entry = _source_incomplete_entry(step)
    if entry is not None:
        return _source_incomplete(entry)
    return StepAssessment(
        "refuse", "none", "refused_known_hazard", "capability_unaccounted_shape",
        f"option shape {list(sig)} of step id {sid} ({name}) is not accounted for by the current emitter "
        "family — an emitter exists, but no capability rule declares it consumes this source structure, so "
        "it is refused rather than emitted with unmodelled options silently dropped (this names a "
        "capability gap, not a missing captured pair)", sid, name, sig, None)


def _blocked_reason(a: StepAssessment, *, strict: bool) -> "str | None":
    """None if the step EMITS under the given policy; else the refusal reason string. Default (strict
    False): verified / experimental / source_incomplete all emit. strict True = verified-only: experimental
    AND source-incomplete are BLOCKED, each naming the caller-selected strictness (never a capture ask)."""
    if a.permission == "refuse":
        return a.detail
    if not strict or a.evidence == "verified":
        return None
    if a.evidence == "experimental":
        return ("experimental (capability-complete but uncaptured) — refused ONLY because you requested "
                "strict/verified-only output. Not a capture gap; drop strict to generate it.")
    absent = ", ".join((a.source_incomplete or {}).get("source_absent_for_target", []))
    return ("source-incomplete (class 2) — the DDR does not hold "
            f"{absent}, so a byte-exact clip is impossible from this input (not a capture gap; do not "
            "retry). You asked for STRICT/verified-only output, so this shape is refused. The DEFAULT "
            "generates its schema-held minimum, clearly labelled source-incomplete — drop the strict flag "
            "to get it.")


def _unsupported_reason(step, *, strict: bool = False, context=None, flavor: str = "xmsc") -> "str | None":
    """None if `step` emits under the policy; else a precise refusal reason. Thin wrapper over
    step_generation_assessment + _blocked_reason (packet 1091) — the single permission authority; kept as a
    string API for callers/tests that want a reason, not the whole verdict.

    `strict` (packet 1091 — replaces the inverted `allow_source_incomplete`): request VERIFIED-ONLY output.
    Default False emits experimental + source-incomplete shapes; True refuses them, each naming the
    caller-selected strictness (never a capture ask).

    EPOCH NOTE (packet 1086 — policy): missing fixture coverage alone is NOT a refusal. Permission now comes
    from implemented capability (verified OR a migrated capability rule); the exact-signature set is
    EVIDENCE (verified vs experimental). A NON-migrated id in an unseen shape still refuses — but for a
    named `capability_unaccounted_shape` hazard (the emitter does not account for that option shape), not
    'no captured pair'. Do not relax that fence without migrating the id's grammar.

    `context` (packet 1118/1119) is threaded to the assessment so the SAME external resolution drives both the
    reason and permission: without a context an external form still refuses; WITH one, a resolved unique
    FileMaker one-path external form emits (packet 1119) and every other external form refuses by a named
    reason. Emission and assessment therefore share one context instance.

    `flavor` (packet 1123 Stage C) is threaded so the permission reason matches the emitted bytes: under
    `strict` an XMSC toggle refuses the deliberate state-preserving dialect while XMSS keeps emitting it."""
    return _blocked_reason(step_generation_assessment(step, context=context, flavor=flavor), strict=strict)


def _build_step(ddr_step, flavor: str, *, strict: bool = False, context=None):
    """One DDR <Step> → clip <Step> for `flavor`, or None if outside the fence. The only flavor-divergent
    shape is the toggle family (finding C): the bare-steps XMSS clip carries a leading <Set state> the
    whole-script XMSC clip drops. Every other step is flavor-identical (only the outer wrapper differs).

    `strict` (packet 1091) defaults False: experimental and registered source-incomplete shapes build
    their emittable form. Pass True for strict/verified-only output.
    `context` (packet 1118) is threaded to the permission check so emission and assessment share it. For the
    five external-reference families it now selects the resolved external emitter (packet 1119) when the SAME
    context permits an external branch; `context=None` and every non-permitted external form still return None."""
    if _unsupported_reason(ddr_step, strict=strict, context=context, flavor=flavor) is not None:
        return None
    sid = int(ddr_step.get("id"))
    branch = _external_branch_assessment(ddr_step, context) if context is not None else None
    if branch is not None and branch[0] == "emit":   # packet 1119 — the resolved external clip branch
        s = _EXTERNAL_EMITTERS[sid](ddr_step, branch[1])
    else:
        s = _EMITTERS[sid](ddr_step)
    if sid in _XMSS_SET_STATE:
        # packet 1123 Stage C — the state-preserving toggle dialect. XMSS always carried the leading
        # <Set state> (its native pair does); XMSC now carries it too, because live paste proved
        # FileMaker accepts it for all 12 tested {id × True/False} cases (Scratch3 id-86 + Scratch4 the
        # other five). This deliberately differs from FileMaker's OWN copied XMSC, which is bare/lossy —
        # so the XMSC form is assessed `generated_experimental` (paste-proven, NOT native-pair byte-exact;
        # strict refuses it), while XMSS stays verified. See _flavor_adjusted / step_generation_assessment.
        s.insert(0, ET.Element("Set", {"state": _first_bool_value(ddr_step)}))
    return s


def scan_step_assessments(steps_source_xml, *, strict: bool = False, context=None,
                          flavor: str = "xmsc") -> list:
    """Per-step verdicts for every <Step> in a DDR blob — the assessment companion to emit_script_clip, so
    a caller (export_object_clip) can report each step's permission/evidence/reason without re-deriving it.

    Each entry: {index, id, name, permission, evidence, result_state, reason_code, detail, signature,
    blocked} — `blocked` reflects the strict POLICY (a step that would emit by default but refuses under
    strict). `signature` is included only for non-verified steps (diagnostic; keeps a verified step tiny).
    When `context` resolves a step's external-file reference, a privacy-safe `external_resolution` dict is
    added (packet 1118 — reporting only, no raw paths).

    `flavor` (packet 1123 Stage C) MUST equal the emit flavor the caller used (XMSS for as_steps, XMSC for
    the whole-script clip) so a reported verdict never disagrees with the emitted bytes."""
    root = ET.fromstring(_strip_xml_decl(
        steps_source_xml.decode("utf-8", "replace") if isinstance(steps_source_xml, bytes)
        else steps_source_xml))
    out = []
    for i, st in enumerate(root.iter("Step")):
        a = step_generation_assessment(st, context=context, flavor=flavor)
        blocked = _blocked_reason(a, strict=strict) is not None
        row = {"index": i, "id": a.step_id, "name": a.name, "permission": a.permission,
               "evidence": a.evidence, "result_state": a.result_state, "reason_code": a.reason_code,
               "detail": a.detail, "blocked": blocked}
        if a.external_resolution is not None:
            row["external_resolution"] = a.external_resolution.to_report_dict()
        if a.evidence != "verified":
            row["signature"] = list(a.signature)
        out.append(row)
    return out


def emit_step(ddr_step, *, flavor: str = "xmsc", strict: bool = False, context=None):
    """DDR <Step> → clip <Step> element (default XMSC flavor), or None when the step's TYPE or its OPTION
    SHAPE is outside what the emitter can produce (see step_generation_assessment / _unsupported_reason).
    `flavor='xmss'` emits the bare-steps form — identical except the toggle family carries <Set state>
    (finding C).

    `strict` (packet 1091 — replaces the inverted `allow_source_incomplete`) defaults False: a
    capability-experimental shape (a migrated id whose exact pair is uncaptured — ids 9/10 today) and a
    registered source-incomplete shape (populated Print Setup) both emit their emittable form. The
    limitations travel in the RESULT METADATA, not the clip XML (see emit_script_clip / scan_source_incomplete
    / scan_step_assessments). Pass True for strict/verified-only output — those shapes then return None.
    `context` (packet 1118) shares the external-data-source authority with the permission check; for the five
    external-reference families a resolved unique FileMaker one-path sibling now emits an external clip branch
    (packet 1119). `context=None` and every non-permitted external form still return None."""
    return _build_step(ddr_step, flavor, strict=strict, context=context)


def scan_source_incomplete(steps_source_xml) -> list:
    """The class-2 steps in a DDR blob: [{index, id, name, gap_class, emits, absent, why}] — the
    companion to emit_script_clip, so a caller that opts into a lossy clip can SAY what is missing.

    Separate from emit_script_clip's return rather than bolted onto it: the emit path stays a 2-tuple
    (its callers are unchanged), and a caller physically cannot emit a source-incomplete clip while
    staying ignorant of which steps made it lossy — it has to ask, and asking hands it the label."""
    root = ET.fromstring(_strip_xml_decl(
        steps_source_xml.decode("utf-8", "replace") if isinstance(steps_source_xml, bytes)
        else steps_source_xml))
    out = []
    for i, st in enumerate(root.iter("Step")):
        entry = _source_incomplete_entry(st)
        if entry is not None:
            out.append({"index": i, "id": st.get("id"), "name": st.get("name"), **entry})
    return out


def emit_script_clip(steps_source_xml, *, script_name: str, script_id: str = "",
                     include_in_menu: str = "False", require_complete: bool = True,
                     flavor: str = "xmsc", strict: bool = False,
                     verified_only: "bool | None" = None, context=None) -> tuple:
    """DDR `StepsForScripts` `<Script>` blob → (clip_xml, unsupported).

    unsupported = [{"index", "id", "name", "reason"}] for every step the emitter will not build — an
    unsupported TYPE, an unaccounted OPTION SHAPE (no verified pair AND no capability rule), and, under
    strict, an experimental or source-incomplete shape. When `require_complete` and unsupported is
    non-empty, clip_xml is '' — FAIL CLOSED whole-script; the caller refuses and reports the exact step
    ids. Never emits a partial/best-effort clip: a genuinely unsupported step withholds the WHOLE requested
    script, never omits itself from it.

    require_complete (packet 1091 — renamed from `verified_only`, which meant whole-script atomicity, NOT
    literal verified-only evidence; the old name is accepted as a deprecated alias). Defaults True: any
    step in `unsupported` withholds the whole script. This is the atomicity gate, ORTHOGONAL to `strict`.

    strict (packet 1091 — replaces the inverted `allow_source_incomplete`). Defaults False: capability-
    experimental shapes (a migrated id whose exact pair is uncaptured — ids 9/10 today) and registered
    source-incomplete shapes emit, so they are NOT in `unsupported` and coexist with verified steps in one
    clip. Their limitations do not travel in the clip XML — pair with `scan_step_assessments` /
    `scan_source_incomplete` on the same blob so the caller discloses them. Pass True for verified-only:
    experimental and source-incomplete shapes then join `unsupported` (each naming the caller-selected
    strictness) and, with require_complete, withhold the whole script.

    flavor (packet 1043 §6) — the paste target, NOT interchangeable:
      'xmsc' (default) — a whole SCRIPT object (`<Script>…steps…</Script>`); pastes into the Scripts
                         list / a script folder as a new script.
      'xmss'           — bare STEPS (no `<Script>` wrapper); pastes INTO an already-open script at the
                         cursor. Same emittable steps + same fence; only the wrapper differs."""
    if verified_only is not None:              # deprecated alias (packet 1091) — atomicity, not evidence
        require_complete = verified_only
    root = ET.fromstring(_strip_xml_decl(
        steps_source_xml.decode("utf-8", "replace") if isinstance(steps_source_xml, bytes)
        else steps_source_xml))
    ddr_steps = list(root.iter("Step"))
    unsupported, out = [], []
    for i, st in enumerate(ddr_steps):
        reason = _unsupported_reason(st, strict=strict, context=context, flavor=flavor)
        if reason is None:
            out.append(_build_step(st, flavor, strict=strict, context=context))
        else:
            unsupported.append({"index": i, "id": st.get("id"), "name": st.get("name"),
                                "reason": reason})
    if require_complete and unsupported:
        return "", unsupported
    snip = ET.Element("fmxmlsnippet", {"type": "FMObjectList"})
    if flavor == "xmss":                       # bare steps — paste into an OPEN script (no wrapper)
        for s in out:
            snip.append(s)
    else:                                       # xmsc — a whole script object
        script = ET.Element("Script", {"includeInMenu": include_in_menu or "False",
                                        "SiriShortcutVisible": "False", "runFullAccess": "False",
                                        "id": str(script_id or ""), "name": script_name})
        for s in out:
            script.append(s)
        snip.append(script)
    xml = ET.tostring(snip, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml, unsupported
