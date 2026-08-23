"""DDR field → XMFD clipboard clip emitter — packet 1070.

The WRITE side of the field work whose validator/read side shipped in packet 1058 P2: turn a stored
SaveAsXML's field definition into a paste-ready **XMFD** clip (`<fmxmlsnippet type="FMObjectList">` whose
top-level objects are `<Field>` — "paste into Manage Database → Fields").

Mirrors `clip_emit.py`'s design exactly, and for the same reason: per-shape emitters behind an evidence
fence. A field shape is emitted ONLY when its DDR→XMFD transform is round-trip-verified byte-exact
against a real, captured pair; an unverified shape REFUSES with the exact reason. A community CC BY 4.0
RE spec of the XMFD format exists (andykear/FileMaker-XML-field-definitions — see
docs/clip-format-references.md) and was used to SHAPE this work, never to widen it: the spec is a
starting hypothesis, our captured pairs are ground truth. The two disagree in at least one place
already — see `_FIELD_TYPE_NOTE`.

⚠ THE DIALECT WARNING (packet 1070, and it is the whole trap). DDR field XML and clipboard XMFD are
DIFFERENT dialects for the same object, not the same XML twice:
  * the DDR says   `<Field id name fieldtype="Normal" datatype="Text" comment="">`
  * the clip says  `<Field id dataType="Text" fieldType="Normal" name=…>` — different attribute NAMES,
    different CASING, and the comment becomes a `<Comment/>` ELEMENT.
Do not copy one shape into the other; every mapping below was read off a real pair.
"""
from __future__ import annotations

from typing import NamedTuple

from corpusfm.core import safe_xml as ET

# The clip's own class token (the FM clipboard dialect for field definitions). The envelope is shared
# with script clips — `<fmxmlsnippet type="FMObjectList">` — so the CLASS is carried out-of-band by the
# pasteboard, not by the XML. A clip declares nothing about itself; see clip_gap.py for the same lesson.
XMFD_CLASS = "XMFD"

# DDR @datatype → clip @dataType. NOT a mechanical copy and not merely a case-fold: `Timestamp` becomes
# `TimeStamp` (capital S), which no amount of `.title()`/`.capitalize()` produces. Verified against a
# captured pair; unsampled datatypes are absent on purpose and refuse through the shape fence.
# A container field's DDR token is `Binary`, NOT `Container` — the andykear spec's name for it was a
# hypothesis that never fired (`datatype="Container"` appears zero times in a 39 MB real FM 2026 export;
# `Binary` is what FM writes, and the clip echoes `Binary` back). Evidence replaced the guess.
_DATATYPE = {"Text": "Text", "Number": "Number", "Date": "Date", "Time": "Time",
             "Timestamp": "TimeStamp", "Binary": "Binary"}

# DDR @type (auto-enter mode) → clip @value. The SAME capital-S quirk as the datatype map above, and for
# the same word: `CreationTimestamp` → `CreationTimeStamp`. The account/name modes pass through unchanged,
# so this is a lookup of proven values rather than a `Timestamp`→`TimeStamp` substring rule — the rule
# would be a guess about modes we have never captured, and the fence would not catch it (the mode rides
# through as @value, not as a shape token).
_AUTOENTER_MODE = {"CreationTimestamp": "CreationTimeStamp",
                   "ModificationTimestamp": "ModificationTimeStamp",
                   # DDR "value from last visited record" is renamed in the clip (packet 1102, from the stored
                   # round-2 field 30). An EXPLICIT per-value remap, NOT a naming rule — a raw pass-through
                   # would emit value="LastVisited", which FileMaker never writes.
                   "LastVisited": "PreviousRecord"}

# The clip models auto-enter as a SET OF FLAGS (constant/calculation/lookup/furigana…) and, for some
# modes, a @value naming the primary mode; the DDR states a single @type plus the matching child
# elements. So the flags are read off WHICH CHILDREN EXIST — a field can carry both a ConstantData and a
# Calculated block at once (id 19 does) — while @value carries the DDR's @type. `Calculated` is the one
# mode that omits @value entirely.
_AUTOENTER_CHILD_FLAG = {"ConstantData": "constant", "Calculated": "calculation",
                         "Looked_up": "lookup"}
# `Looked_up` joins `Calculated` in omitting @value: the clip states the mode through its `lookup` flag +
# the <Lookup> block, exactly as it does for a calc. Read off a real pair, not assumed from symmetry.
_AUTOENTER_VALUE_OMITTED = frozenset({"Calculated", "Looked_up", "SerialNumber"})

# DDR <LanguageReference name> → clip <Storage indexLanguage>. An EXPLICIT per-VALUE map, exactly like
# _DATATYPE, NOT a suffix rule / case-fold / pass-through: `Unicode` becomes `Unicode_Raw` in the clip
# while `English` passes through untouched. Proven by a real pair (Scratch1::PrimaryKey, packet 1083) —
# this axis had been seen from one side only (every committed pair was English), so a straight @name copy
# shipped indexLanguage="Unicode" where FileMaker writes "Unicode_Raw".
#
# ⚖ RATIFIED POLICY (packet 1090 — the final decision, no longer a placeholder). Because this axis is
# DEMONSTRATED NON-IDENTITY, an unmapped name cannot be assumed verbatim: a blind pass-through could paste
# cleanly while SILENTLY changing indexing behaviour — a concrete materially-misleading-output hazard,
# which meets the packet-1086 refusal policy. So a name not in this map REFUSES the field with
# `unmapped_index_language` (in _unmapped_value, BEFORE this lookup — a KeyError here would be a bug, not
# the fence). This is NOT "uncaptured means refuse": a KNOWN language (English/Unicode) emits in any
# capability-complete shape, verified or experimental. Adding a future language is a DEVELOPER MAPPING
# DECISION backed by real FileMaker behaviour — an explicit entry here + a regression — never merely
# putting its signature in _VERIFIED_FIELD_SIGS.
_INDEX_LANGUAGE = {"English": "English", "Unicode": "Unicode_Raw"}

_FIELD_TYPE_NOTE = (
    "Only the shapes below are verified byte-exact against a captured pair. "
    "Validation — type='Always', the strict-data-type/range/calc/max-length/value-list children, and the "
    "message fan-out — became capable in packet 1093 (fields 39/41 verified; the full house proven at the "
    "subtree level). The Lookup no-match remaps — DoNotCopy / "
    "CopyNextLower / CopyNextHigher / CopyConstant(+CopyConstantValue) — became capable in packet 1095 "
    "(all four Scratch1 Alookup fields verified). External-container Remote storage — the Secure and Open "
    "topologies — became capable in packet 1096 (fields 23/42 verified; absolute=True stays incapable). All "
    "13 summary operations + both AdditionalField anchor projections became capable in packet 1097 (the 15 "
    "Scratch1 Summary fields verified). Furigana — the five input modes + the flattened base-table field "
    "reference — became capable in packet 1099 (the 7 Scratch1 Furigana fields verified whole-field). "
    "DisplayNames — the @enable flag + the display-name calc — became capable in packet 1100, the final "
    "PLANNED observed field-feature branch. A non-empty nested Annotation became capable in packet 1101, and "
    "the LastVisited auto-enter mode (DDR LastVisited -> clip PreviousRecord, an explicit remap) in packet "
    "1102 — so Scratch1 field 30 now emits as a complete VERIFIED whole field (LastVisited + populated "
    "Annotation + DisplayNames-on together). This closes the PLANNED sequence + the field-30 follow-ups, NOT "
    "all FileMaker field vocabulary — unknown elements/values still refuse through the ordinary capability "
    "model. Widen only with a captured pair, exactly as clip_emit.py does."
)


def _attr(el, name) -> str:
    """An attribute for the fence, with ABSENT ('~') distinguished from any literal value.

    Load-bearing, not pedantry: FileMaker uses the literal string "None" as an index value, so a naive
    `str(el.get('index'))` renders BOTH an absent index and `index="None"` as `None` — one token for two
    different facts. A Calculated field has no index attribute at all while a Normal field can literally
    be index="None", and their clips differ. Nothing collides today because other tokens separate them,
    but a fence that conflates absent-vs-empty is exactly the bug that has now bitten three times
    (PageSetup/1076, the PDF Options subtree/1081, Insert Text + Set Selection/1082)."""
    if el is None or el.get(name) is None:
        return "~"
    return el.get(name)


def _validation_children_token(val) -> str:
    """The shape descriptor of a DDR <Validation>'s HOUSE children — '' for an attribute-only validation
    (the pre-1093 shape, so every existing signature is unchanged). Records the driving facts each child
    contributes to the clip: the strict-data-type VALUE (it becomes an @value), the calc/message ENABLE
    state (a disabled block would emit differently and is refused, so the state is part of the shape), the
    value-list FORM (a real reference emits a <ValueList> child, id=-1 emits none), and mere presence for
    Range/MaxDataLength. Deterministic order, so the token is stable."""
    parts = []
    strict = val.find("Strict")
    if strict is not None:
        parts.append(f"strict={(strict.text or '').strip()}")
    if val.find("Range") is not None:
        parts.append("range")
    calc = val.find("Calculated")
    if calc is not None:
        parts.append(f"calc={calc.get('enable')}")
    msg = val.find("MessageCalc")
    if msg is not None:
        parts.append(f"msgcalc={msg.get('enable')}")
    if val.find("MaximumSize") is not None:
        parts.append("maxlen")
    vlref = val.find("ValueListReference")
    if vlref is not None:
        parts.append(f"vl={'real' if vlref.get('id') != '-1' else 'none'}")
    return "|".join(parts)


def _summary_anchor_kind(fr) -> str:
    """The ANCHOR KIND of a summary <FieldReference> — the shape token for whether the flattened target
    <Field> carries a @table (packet 1097). A TableOccurrenceReference anchor emits @table; a
    BaseTableReference anchor omits it; absent is 'none'. The anchor drives @table, NOT the operation name,
    so this MUST be a signature token — else a TO-anchored AdditionalField (target has @table) collapses onto
    a base-anchored one (no @table) and emits through the fence unverified."""
    if fr is None:
        return "none"
    if fr.find("TableOccurrenceReference") is not None:
        return "to"
    if fr.find("BaseTableReference") is not None:
        return "base"
    return "?"


def _field_signature(field) -> tuple:
    """The DDR field's SHAPE — the per-field fence key.

    Mirrors clip_emit._step_signature: fence what the emitter cannot reproduce generically. The field's
    NAME/id/calc TEXT are copied through and never fenced (content, not shape); its type, auto-enter
    mode, validation switches and storage mode ARE the shape, because each changes which elements and
    attributes the clip carries."""
    ae = field.find("AutoEnter")
    val = field.find("Validation")
    sto = field.find("Storage")
    si = field.find("SummaryInfo")
    # @enable is part of the SHAPE, not content: `<Calculated enable="False">` is a retained-but-disabled
    # block, and its clip differs (calculation="False" while still carrying the <Calculation>). Recording
    # only the child TAG collapses enabled and disabled into one signature — the sixth instance of the
    # collapse-the-driving-option hole (PageSetup/1076, PDF Options/1081, Insert Text + Set Selection/1082,
    # Insert File's Options siblings/1082, Summary @operation/1070).
    ae_kids = ("".join(sorted(f"[{k.tag}{'' if k.get('enable') is None else ':' + k.get('enable')}]"
                              for k in ae)) if ae is not None else "")
    # A serial's `generate` mode (OnCreation / OnCommit) DRIVES the clip's <Serial generate=…> and is
    # otherwise invisible to the shape — `ae_kids` records only that a <SerialNumber> child EXISTS, so
    # OnCreation and OnCommit collapse onto one signature. Scoped to serial-bearing fields (empty for every
    # other field, so no churn elsewhere), it makes an un-captured generate mode REFUSE instead of riding a
    # verified twin's fence. The eighth collapse-the-driving-option hole, and the same class the index
    # language was (packet 1083). Pass-through, not a remap: the DDR and clip name the mode identically.
    serial = ae.find("SerialNumber") if ae is not None else None
    serial_gen = f",serialGenerate={serial.get('generate')}" if serial is not None else ""
    # The Lookup no-match option + constant-fallback presence DRIVE the emitted <Lookup> (each option is a
    # distinct <NoMatchCopyOption> remap, and ConstantData ALSO emits a <CopyConstantValue> child), so they
    # MUST be shape tokens — without them all four no-match modes collapse onto the one `[Looked_up:True]`
    # child token and emit through the fence unverified (the same collapse-the-driving-option lesson as the
    # serial generate mode / index language). Appended ONLY for a Looked_up auto-enter, so every non-lookup
    # signature is byte-identical; the existing DoNotCopy Lookup pairs regenerate WITH the token. Packet 1095.
    lu_sig = ae.find("Looked_up") if ae is not None else None
    lookup_tok = ""
    if lu_sig is not None:
        const = "+const" if lu_sig.find("ConstantData") is not None else ""
        lookup_tok = f",lookup={lu_sig.get('noMatchCopyOption')}{const}"
    # The top-level Furigana block DRIVES both the AutoEnter furigana flag and a whole target subtree
    # (<Furigana inputMode><Field baseTable/>). Its input MODE, anchor FORM, and repetition change/limit that
    # target, so they MUST be shape tokens — without them the five modes collapse onto one otherwise-identical
    # field shape (ids 22/24–27 differ ONLY by mode) and four would emit through a sibling's fence. The
    # collapse-the-driving-option lesson again (serial generate / index language / summary operation). Field
    # id/name/base-table strings are content, not shape. Appended ONLY for a Furigana-bearing field, so every
    # non-Furigana signature is byte-identical. Packet 1099.
    fu_sig = field.find("Furigana")
    furigana_tok = ""
    if fu_sig is not None:
        fu_fr = fu_sig.find("FieldReference")
        furigana_tok = (f",furigana={fu_sig.get('inputMode')},"
                        f"anchor={_summary_anchor_kind(fu_fr)},"
                        f"rep={fu_fr.get('repetition') if fu_fr is not None else '~'}")
    # A LastVisited AutoEnter's prohibitModification DRIVES the target allowEditing (inverted polarity), and is
    # otherwise invisible to the shape (ae_kids records only child tags; LastVisited has none). So without this
    # token the verified True side and an uncaptured False recombination collapse onto one signature and the
    # False side would emit through the True fence entry. Scoped to LastVisited + append-only, so every non-
    # LastVisited signature is byte-identical (the collapse-the-driving-option lesson, now for LastVisited).
    # Packet 1102.
    lastvisited_tok = ""
    if ae is not None and ae.get("type") == "LastVisited":
        lastvisited_tok = f",lastVisited=prohibitMod={_attr(ae, 'prohibitModification')}"
    val_flags = ""
    if val is not None:
        val_flags = ",".join(f"{k}={val.get(k)}" for k in sorted(val.keys()) if k != "type")
        # The validation HOUSE children DRIVE the clip (StrictDataType / Range / the calc / the message /
        # MaxDataLength / the value-list child), so they MUST be shape tokens — else a field with a Range
        # matches a field without one and emits through the fence unverified (the collapse-the-driving-
        # option lesson, now for validation). Appended ONLY when children exist, so every attribute-only
        # validation — every pre-1093 verified field — keeps its EXACT signature (no fence churn).
        vchild = _validation_children_token(val)
        if vchild:
            val_flags += ";" + vchild
    # @operation DRIVES the emitted SummaryInfo, so it MUST be a shape token. Without it a Summary/Number
    # `Total` would match the captured `Count` shape and emit through the fence unverified — the exact
    # collapse-the-driving-option hole that has bitten repeatedly (PageSetup/1076, the PDF Options
    # subtree/1081, Insert Text + Set Selection/1082, Insert File's Options siblings/1082). All 13 summary
    # operations are captured now (packet 1097), and the token also carries the AdditionalField TOPOLOGY —
    # the primary + additional anchor KIND (to/base/none) — because the anchor drives whether the flattened
    # target <Field> has a @table. Without the additional token a TO-anchored AdditionalField collapses onto
    # a base-anchored one and emits the wrong target through the fence. Field id/name/table-name strings are
    # content, not shape; only the anchor KIND + presence are tokened. Non-Summary fields keep `summary:~`.
    summary = "~"
    if si is not None:
        summary = (f"{_attr(si, 'operation')},restart={_attr(si, 'restartEachGroup')},"
                   f"rep={_attr(si, 'summarizeRepetition')},"
                   f"fields={len(si.findall('SummaryField/FieldReference'))},"
                   f"primary={_summary_anchor_kind(si.find('SummaryField/FieldReference'))},"
                   f"additional={_summary_anchor_kind(si.find('AdditionalField/FieldReference'))}")
    # The index language DRIVES the clip's indexLanguage and is REMAPPED per-value (Unicode → Unicode_Raw),
    # so it MUST be a shape token — without it a Unicode-indexed field yields a signature byte-identical to
    # its English twin, matches a verified shape, and emits the wrong token through the fence. The seventh
    # instance of the collapse-the-driving-option hole (PageSetup/1076, PDF Options/1081, Insert Text + Set
    # Selection/1082, Insert File/1082, Summary @operation/1070, <Calculated enable>/1070). `_attr` keeps
    # absent ('~', a Summary field has no Storage) distinct from any present language. Packet 1083.
    lang = sto.find("LanguageReference") if sto is not None else None
    # External-container Remote storage DRIVES a whole target subtree (Secure vs Open are DIFFERENT trees:
    # the empty <Secure/> marker + withFewerFolders, vs a <Location> path calc), and the base-directory
    # reference @id becomes the clip's relativeTo — a catalog key we have observed only as 0, so a nonzero id
    # must NOT match id-0's verified shape (the honest evidence bound, same discipline as the index language).
    # So the token carries type, withFewerFolders, Location presence, base id, and the absolute state.
    # Appended ONLY for a Remote-bearing Storage, so every non-Remote storage signature is byte-identical.
    # The base-directory NAME (→ relativeToPath, a free path string) is content, not shape — not tokened.
    # Packet 1096.
    rem = sto.find("Remote") if sto is not None else None
    remote_tok = ""
    if rem is not None:
        bdr = rem.find("BaseDirectoryReference")
        remote_tok = (f";remote={_attr(rem, 'type')},fewer={_attr(rem, 'withFewerFolders')},"
                      f"loc={'1' if rem.find('Location') is not None else '0'},"
                      f"baseId={_attr(bdr, 'id')},absolute={_attr(bdr, 'absolute')}")
    # DisplayNames DRIVES the target: an enable="True" field emits a <DisplayNames enable="True"><Calculation>
    # child, an enable="False" one emits a bare <DisplayNames enable="False"/>. So the enable value + calc
    # presence are shape — without them an enable="True"+calc field would yield a signature identical to its
    # enable="False" twin, match a verified False shape, and emit the wrong DisplayNames through the fence
    # (the collapse-the-driving-option lesson again). The calc TEXT/TO-name is content, not shape. Appended
    # ONLY when enable != "False" (or a calc is present), so every enable="False" field — every pre-1100
    # committed pair — keeps its EXACT signature. Packet 1100.
    dn = field.find("DisplayNames")
    dn_tok = ""
    if dn is not None and (dn.get("enable") != "False" or dn.find("Calculation") is not None):
        dn_tok = f";displayNames={_attr(dn, 'enable')},calc={'1' if dn.find('Calculation') is not None else '0'}"
    return (
        f"type:{field.get('fieldtype')}/{field.get('datatype')}",
        f"autoenter:{_attr(ae, 'type')}{ae_kids}{serial_gen}{lookup_tok}{furigana_tok}{lastvisited_tok}",
        f"summary:{summary}",
        f"validation:{_attr(val, 'type')};{val_flags}",
        f"storage:stored={_attr(sto, 'storeCalculationResults')},autoIndex={_attr(sto, 'autoIndex')},"
        f"index={_attr(sto, 'index')},global={_attr(sto, 'global')},"
        f"repetitions={_attr(sto, 'maxRepetitions')},indexLang={_attr(lang, 'name')}{remote_tok}{dn_tok}",
    )


# Per-shape VERIFIED field shapes — the fence. Same contract as clip_emit._VERIFIED_SIGS: a shape here has
# been proven byte-exact against a captured (DDR field, XMFD clip) pair in
# tests/fixtures/field_emit/field_emit_pairs.xml, and the lockstep guard fails the build if the two
# disagree. NOTHING else emits. Generated FROM the fixture, never hand-typed — the comment above each entry
# names the pair(s) that prove it.
#
# 82 shapes / 88 pairs (re-count from the fixture, never from this line — DO NOT hand-edit this set;
# regenerate it with scripts/gen_field_emit_fence.py, which the lockstep guard proves matches the fixture).
# Sources: the dev's own file (SeedDB and PTLaunchPad are the same database under two names), three
# `Scratch1` rounds, and a business file whose source stays UNNAMED by the naming rule. Shapes: Normal
# Text/Number/Date/Time/Binary with and without auto-enter, the Calculated auto-enter across index modes
# plus the notEmpty+unique variant, a ConstantData auto-enter that ALSO carries a calc, true Calculated
# fields (Text/Number/Date/Timestamp, stored and unstored), global storage, repetitions, the six
# creation/modification auto-enter modes, Serial, Lookup across ALL FOUR no-match modes (DoNotCopy /
# CopyNextLower / CopyNextHigher / CopyConstant+CopyConstantValue, packet 1095) and both dontCopyIfEmpty
# polarities, external-container Remote storage in BOTH topologies (Secure + Open, packet 1096),
# Summary across ALL 13 operations + both AdditionalField anchor projections (TO-anchored → target @table;
# base-anchored → no @table, packet 1097), Furigana across ALL FIVE input modes (Hiragana /
# 1ByteKatakana / 2ByteKatakana / 1ByteRoman / 2ByteRoman) with the flattened base-table field reference
# (packet 1099), and the LastVisited auto-enter mode (→ PreviousRecord) combined with a populated Annotation +
# DisplayNames-on in one whole field (Scratch1 field 30, packet 1102). @operation, the AdditionalField anchor
# kind, the Furigana input mode, and the LastVisited prohibitModification are fence tokens, so an unmapped
# operation/mode or an uncaptured topology/Boolean recombination refuses/experiments rather than emitting
# through a sibling's fence.
#
# ✅ THE INDEX LANGUAGE IS A SIGNATURE TOKEN (packet 1083 — the seventh fence hole, CLOSED). It was once
# blind: `_field_signature`'s storage token carried stored/autoIndex/index/global/repetitions but NOT the
# `<LanguageReference name>`, so a Unicode-indexed field yielded a signature byte-identical to its English
# twin, matched a verified shape, and `_emit_storage` copied @name straight through — emitting
# indexLanguage="Unicode" where FileMaker writes "Unicode_Raw", structurally valid and silently WRONG. Two
# changes closed it, and BOTH are load-bearing: (1) the storage token now carries `indexLang`, so an
# un-captured language REFUSES rather than matching an English shape; (2) `_INDEX_LANGUAGE` remaps
# Unicode → Unicode_Raw per value while English passes through. Shipping (2) without (1) would leave the
# hole open for every language that isn't Unicode. The one committed non-English pair is Scratch1::PrimaryKey
# (`indexLang=Unicode` below); every other pair is English, so all other languages correctly refuse.
_VERIFIED_FIELD_SIGS = {
    # UMASESSION::TimestampCreated.Date
    ('type:Calculated/Date',
     'autoenter:~',
     'summary:~',
     'validation:~;',
     'storage:stored=True,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMAACTIONLOG::TimestampCreated.Date
    ('type:Calculated/Date',
     'autoenter:~',
     'summary:~',
     'validation:~;',
     'storage:stored=True,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::TimestampCreated.Month
    ('type:Calculated/Number',
     'autoenter:~',
     'summary:~',
     'validation:~;',
     'storage:stored=False,autoIndex=~,index=~,global=False,repetitions=1,indexLang=English'),
    # UMAUSER::Display.Name · UMAUSER::Display.LoginID
    ('type:Calculated/Text',
     'autoenter:~',
     'summary:~',
     'validation:~;',
     'storage:stored=False,autoIndex=~,index=~,global=False,repetitions=1,indexLang=English'),
    # UMAUSER::LowerCase.Login
    ('type:Calculated/Text',
     'autoenter:~',
     'summary:~',
     'validation:~;',
     'storage:stored=True,autoIndex=True,index=Minimal,global=False,repetitions=1,indexLang=English'),
    # UMAFEATURE::Concatenate.GroupCommaUUID
    ('type:Calculated/Text',
     'autoenter:~',
     'summary:~',
     'validation:~;',
     'storage:stored=True,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMAUSER::CatalogOfSearchTerms
    ('type:Calculated/Text',
     'autoenter:~',
     'summary:~',
     'validation:~;',
     'storage:stored=True,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # UMAUSER::LastSeenTimestamp
    ('type:Calculated/Timestamp',
     'autoenter:~',
     'summary:~',
     'validation:~;',
     'storage:stored=False,autoIndex=~,index=~,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::Display.TimestampCreated
    ('type:Calculated/Timestamp',
     'autoenter:~',
     'summary:~',
     'validation:~;',
     'storage:stored=True,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::FileConduit
    ('type:Normal/Binary',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=False,repetitions=1,indexLang=~'),
    # Scratch1::ACOntainer Copy
    ('type:Normal/Binary',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=False,repetitions=1,indexLang=~;remote=Open,fewer=~,loc=1,baseId=0,absolute=False'),
    # Scratch1::ACOntainer
    ('type:Normal/Binary',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=False,repetitions=1,indexLang=~;remote=Secure,fewer=True,loc=0,baseId=0,absolute=False'),
    # UMAGLOBAL::Logo.Primary
    ('type:Normal/Binary',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=True,repetitions=1,indexLang=~'),
    # UMAGLOBAL::NoContext.ContainerField
    ('type:Normal/Binary',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=True,repetitions=1,indexLang=~'),
    # UMASESSION::aDate
    ('type:Normal/Date',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # TSGTHEMESTYLEGRID::Field.Date
    ('type:Normal/Date',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=True,repetitions=1,indexLang=English'),
    # UMAGLOBAL::REPORT.RangeStart
    ('type:Normal/Date',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=True,repetitions=1,indexLang=English'),
    # UMASESSION::aNumber
    ('type:Normal/Number',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMAGLOBAL::CreateModifyUser.CcActiveUserWithInstructs
    ('type:Normal/Number',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=True,repetitions=1,indexLang=English'),
    # UMAFEATURE::IsInvisible
    ('type:Normal/Number',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # UMAGLOBAL::NoContext.NumberField
    ('type:Normal/Number',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=True,repetitions=1,indexLang=English'),
    # UMASETTING::General.ImageStoreMaxPixel
    ('type:Normal/Number',
     'autoenter:ConstantData[Calculated:False][ConstantData]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMARECORDLOG::IsRestored
    ('type:Normal/Number',
     'autoenter:ConstantData[Calculated:True][ConstantData]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMAFEATURE::RankInGroup
    ('type:Normal/Number',
     'autoenter:ConstantData[ConstantData]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Scratch1::ASerial Copy
    ('type:Normal/Number',
     'autoenter:SerialNumber[Calculated:True][SerialNumber],serialGenerate=OnCommit',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=True,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # Scratch1::ASerial
    ('type:Normal/Number',
     'autoenter:SerialNumber[SerialNumber],serialGenerate=OnCreation',
     'summary:~',
     'validation:Always;allowOverride=False,alwaysValidate=True,existing=False,notEmpty=False,unique=True;calc=True',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # Scratch1::ASerial Copy2
    ('type:Normal/Number',
     'autoenter:SerialNumber[SerialNumber],serialGenerate=OnCreation',
     'summary:~',
     'validation:Always;allowOverride=True,alwaysValidate=False,existing=True,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # PVAASSETS::PVABase64
    ('type:Normal/Text',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=False,index=None,global=False,repetitions=1,indexLang=English'),
    # PVAASSETS::PVAName
    ('type:Normal/Text',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=Minimal,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::Bad+FieldName
    ('type:Normal/Text',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::aRepeatingField
    ('type:Normal/Text',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=3,indexLang=English'),
    # UMAUSERTOFEATURE::UUIDUser
    ('type:Normal/Text',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::!CartesianConnector
    ('type:Normal/Text',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=True,repetitions=1,indexLang=English'),
    # Scratch1::PrimaryKey · Scratch1::EmptyAutoEnterCalc
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=False,alwaysValidate=False,existing=False,notEmpty=True,unique=True',
     'storage:stored=~,autoIndex=True,index=Minimal,global=False,repetitions=1,indexLang=Unicode'),
    # UMASESSION::UUID
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=False,alwaysValidate=False,existing=False,notEmpty=True,unique=True',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # UMAUSER::Email
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=Minimal,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::ApplicationVersion · UMAUSER::Note
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMAUSER::Name
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # UMAGLOBAL::NoContext.TextField
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=True,repetitions=1,indexLang=English'),
    # UMAUSER::LoginID
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=True,unique=True',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Text Copy3
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True],furigana=1ByteKatakana,anchor=base,rep=1',
     'summary:~',
     'validation:Always;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=True,unique=False;strict=Numeric|range|calc=True|msgcalc=True|maxlen|vl=none',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Text Copy4
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True],furigana=1ByteRoman,anchor=base,rep=1',
     'summary:~',
     'validation:Always;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=True,unique=False;strict=Numeric|range|calc=True|msgcalc=True|maxlen|vl=none',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Text Copy
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True],furigana=2ByteKatakana,anchor=base,rep=1',
     'summary:~',
     'validation:Always;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=True,unique=False;strict=Numeric|range|calc=True|msgcalc=True|maxlen|vl=none',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Text Copy2
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True],furigana=2ByteRoman,anchor=base,rep=1',
     'summary:~',
     'validation:Always;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=True,unique=False;strict=Numeric|range|calc=True|msgcalc=True|maxlen|vl=none',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Text
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True],furigana=Hiragana,anchor=base,rep=1',
     'summary:~',
     'validation:Always;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=True,unique=False;strict=Numeric|range|calc=True|msgcalc=True|maxlen|vl=none',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Text 2 Copy
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True],furigana=Hiragana,anchor=base,rep=1',
     'summary:~',
     'validation:Always;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=True,unique=True;strict=Time|range|calc=True|msgcalc=True|maxlen|vl=none',
     'storage:stored=~,autoIndex=True,index=Minimal,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Text 2
    ('type:Normal/Text',
     'autoenter:Calculated[Calculated:True],furigana=Hiragana,anchor=base,rep=1',
     'summary:~',
     'validation:Always;allowOverride=True,alwaysValidate=False,existing=True,notEmpty=True,unique=False;strict=FourDigitYear|range|calc=True|msgcalc=True|maxlen|vl=real',
     'storage:stored=~,autoIndex=True,index=Minimal,global=False,repetitions=1,indexLang=English'),
    # UMASETTING::Users.InactivityLimit
    ('type:Normal/Text',
     'autoenter:ConstantData[Calculated:False][ConstantData]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMAFEATURE::Activation
    ('type:Normal/Text',
     'autoenter:ConstantData[Calculated:True][ConstantData]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=Minimal,global=False,repetitions=1,indexLang=English'),
    # UMAUSER::Timezone
    ('type:Normal/Text',
     'autoenter:ConstantData[Calculated:True][ConstantData]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMAGLOBAL::CreateModifyUser.Activation
    ('type:Normal/Text',
     'autoenter:ConstantData[Calculated:True][ConstantData]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=True,repetitions=1,indexLang=English'),
    # UMASESSION::AccountCreated
    ('type:Normal/Text',
     'autoenter:CreationAccountName',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::ClientCreated
    ('type:Normal/Text',
     'autoenter:CreationName',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Number
    ('type:Normal/Text',
     'autoenter:LastVisited,lastVisited=prohibitMod=True',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English;displayNames=True,calc=1'),
    # Scratch1::Alookup Copy3
    ('type:Normal/Text',
     'autoenter:Looked_up[Looked_up:True],lookup=ConstantData+const',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Products::CategoryID
    ('type:Normal/Text',
     'autoenter:Looked_up[Looked_up:True],lookup=DoNotCopy',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=Minimal,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Alookup
    ('type:Normal/Text',
     'autoenter:Looked_up[Looked_up:True],lookup=DoNotCopy',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Products::Category
    ('type:Normal/Text',
     'autoenter:Looked_up[Looked_up:True],lookup=DoNotCopy',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Alookup Copy2
    ('type:Normal/Text',
     'autoenter:Looked_up[Looked_up:True],lookup=NextHigher',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Scratch1::Alookup Copy
    ('type:Normal/Text',
     'autoenter:Looked_up[Looked_up:True],lookup=NextLower',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::AccountModified
    ('type:Normal/Text',
     'autoenter:ModificationAccountName',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::ClientModified
    ('type:Normal/Text',
     'autoenter:ModificationName',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # Products::Serial
    ('type:Normal/Text',
     'autoenter:SerialNumber[SerialNumber],serialGenerate=OnCreation',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMAUSER::UserType
    ('type:Normal/Text',
     'autoenter:[Calculated:False]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # UMAGLOBAL::Menu.ListOfFeature
    ('type:Normal/Text',
     'autoenter:[Calculated:False]',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=~,global=True,repetitions=1,indexLang=English'),
    # UMASESSION::aTime
    ('type:Normal/Time',
     'autoenter:',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::TimestampCreated
    ('type:Normal/Timestamp',
     'autoenter:CreationTimestamp',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=~,index=All,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::TimestampModified
    ('type:Normal/Timestamp',
     'autoenter:ModificationTimestamp',
     'summary:~',
     'validation:OnlyDuringDataEntry;allowOverride=True,alwaysValidate=False,existing=False,notEmpty=False,unique=False',
     'storage:stored=~,autoIndex=True,index=None,global=False,repetitions=1,indexLang=English'),
    # UMASESSION::CountOf.UUID · Scratch1::Sum_CountOf Copy
    ('type:Summary/Number',
     'autoenter:',
     'summary:Count,restart=False,rep=Together,fields=1,primary=base,additional=none',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_FractionOfTotal Copy
    ('type:Summary/Number',
     'autoenter:',
     'summary:Fractional,restart=False,rep=Together,fields=1,primary=base,additional=none',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_FractionOfTotal
    ('type:Summary/Number',
     'autoenter:',
     'summary:FractionalSubtotal,restart=False,rep=Individually,fields=1,primary=base,additional=to',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_CountOf
    ('type:Summary/Number',
     'autoenter:',
     'summary:RunningCount,restart=True,rep=Together,fields=1,primary=base,additional=to',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_Total
    ('type:Summary/Number',
     'autoenter:',
     'summary:RunningTotal,restart=True,rep=Together,fields=1,primary=base,additional=to',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_StandardDev Copy
    ('type:Summary/Number',
     'autoenter:',
     'summary:StdDeviation,restart=False,rep=Individually,fields=1,primary=base,additional=none',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_StandardDev
    ('type:Summary/Number',
     'autoenter:',
     'summary:StdDeviationByPopulation,restart=False,rep=Individually,fields=1,primary=base,additional=none',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum · Scratch1::Sum_Total Copy
    ('type:Summary/Number',
     'autoenter:',
     'summary:Total,restart=False,rep=Together,fields=1,primary=base,additional=none',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_ListOf
    ('type:Summary/Text',
     'autoenter:',
     'summary:List,restart=False,rep=Individually,fields=1,primary=base,additional=none',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # UMASESSION::Summary.FieldListAsJSON · Scratch1::Sum_ListOf Copy
    ('type:Summary/Text',
     'autoenter:',
     'summary:List,restart=False,rep=Together,fields=1,primary=base,additional=none',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_AverageOf Copy
    ('type:Summary/Timestamp',
     'autoenter:',
     'summary:Average,restart=False,rep=Individually,fields=1,primary=base,additional=none',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_Maximim
    ('type:Summary/Timestamp',
     'autoenter:',
     'summary:Maximum,restart=False,rep=Together,fields=1,primary=base,additional=none',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_Minimum
    ('type:Summary/Timestamp',
     'autoenter:',
     'summary:Minimum,restart=False,rep=Together,fields=1,primary=base,additional=none',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
    # Scratch1::Sum_AverageOf
    ('type:Summary/Timestamp',
     'autoenter:',
     'summary:WeightedAverage,restart=False,rep=Individually,fields=1,primary=base,additional=base',
     'validation:~;',
     'storage:stored=~,autoIndex=~,index=~,global=~,repetitions=~,indexLang=~'),
}


# The serial `generate` modes we have ACTUALLY OBSERVED in a captured pair, derived from the fence (never
# hand-listed) — {OnCreation, OnCommit} today, which is FileMaker's whole serial-generate enum. Both pass
# through byte-exact, so a serial whose only uncaptured aspect is a known mode in a new shape combination
# emits experimentally; an UNrecognized generate value refuses by name (we cannot prove an unseen mode
# passes through rather than remapping — the index-language lesson). `serialGenerate=` is the final token
# appended to the auto-enter signature element.
_CAPTURED_SERIAL_MODES = frozenset(
    s[1].split(",serialGenerate=", 1)[1] for s in _VERIFIED_FIELD_SIGS if ",serialGenerate=" in s[1])


def _sig_token_value(sig, index, prefix):
    """The bare value of a signature token, e.g. 'autoenter:Calculated[Calculated]' -> 'Calculated'."""
    tok = sig[index][len(prefix):]
    for stop in ("[", ","):
        tok = tok.split(stop)[0]
    return tok


# ── Implemented-capability model (packet 1088) ────────────────────────────────────────────────────────
#
# PERMISSION is capability, not fixture membership. The fence (_VERIFIED_FIELD_SIGS) answers only the
# EVIDENCE question — "is this exact shape byte-captured?" — which separates a VERIFIED emit from an
# EXPERIMENTAL one. Whether a field may emit AT ALL is answered here: does the current transform account
# for every source feature that drives the clip, with no unmapped value and no silently-ignored
# child/attribute? A field the transform fully handles emits even with no captured pair (experimentally);
# a field with any unaccounted feature REFUSES and names it. An emitter helper merely EXISTING is not proof
# it consumes every child of the element it handles — several helpers intentionally omit unimplemented
# children (Furigana, DisplayNames target structure — the validation house/1093, the lookup no-match
# remaps/1095, external-container Remote storage/1096, and the summary operations + AdditionalField
# topology/1097 are now built), and this is where those omissions are caught and named.

# The three field types the emitter dispatches on (Normal leads with <Comment>, Calculated with its
# <Calculation>, Summary with its <SummaryInfo>). Any other fieldtype has no emitter branch.
_FIELD_TYPES = frozenset({"Normal", "Calculated", "Summary"})

# FileMaker's Summary @operation vocabulary — the 13 tokens OBSERVED in the stored Scratch1 table (packet
# 1097), read off the pair, never inferred. This is an INDEPENDENT capability authority: permission comes
# from THIS set, NOT from _VERIFIED_FIELD_SIGS / CLIP_SUMMARY_OPERATIONS (those are evidence/read-side
# outputs derived from the fence — removing a fixture must not silently revoke an implemented operation).
# Two spellings were earlier guessed WRONG and are pinned here from the bytes: `StdDeviation` (not
# StandardDeviation) and `Fractional` (not FractionOfTotal). DDR→clip identity, so an unmapped operation
# refuses by name rather than riding through as a raw @value the fence cannot check.
_SUMMARY_OPERATIONS = frozenset({
    "Total", "RunningTotal", "Average", "WeightedAverage", "Count", "RunningCount", "Minimum", "Maximum",
    "StdDeviation", "StdDeviationByPopulation", "Fractional", "FractionalSubtotal", "List"})
# The two SummaryInfo option vocabularies, likewise bounded and validated. `restartEachGroup` is a Boolean;
# `summarizeRepetition` is one of these two. An unseen value refuses (a guess the fence cannot catch).
_SUMMARY_RESTART = frozenset({"True", "False"})
_SUMMARY_REPETITION = frozenset({"Together", "Individually"})

# Auto-enter @type values the transform IMPLEMENTS. An INDEPENDENT capability authority (packet 1102) — was
# derived from the fence (`_sig_token_value(s, 1, ...) for s in _VERIFIED_FIELD_SIGS`), an old-policy coupling
# that violates packet 1088's epoch rule: removing a fixture could revoke an implemented mode, and adding a
# pair could grant permission. Permission is now an explicit source-mode set, decided by the CODE, not the
# evidence; the fence only decides verified-vs-experimental. An UNSAMPLED mode would ride through
# _AUTOENTER_MODE.get(m, m) as a raw @value the fence cannot check, so a mode NOT listed here refuses by name.
# '' is the no-auto-enter mode (DDR type=""); '~' (no AutoEnter element) is never a mode. Do NOT re-couple
# this to _VERIFIED_FIELD_SIGS or any fixture-derived / generated set — test_autoenter_capability_is_
# independent_of_the_fence guards it.
_CAPABLE_AUTOENTER_MODES = frozenset({
    "", "Calculated", "ConstantData", "CreationAccountName", "CreationName", "CreationTimestamp",
    "Looked_up", "ModificationAccountName", "ModificationName", "ModificationTimestamp", "SerialNumber",
    "LastVisited"})
# The LastVisited AutoEnter's prohibitModification Boolean drives the target allowEditing (inverted). Only
# True is captured (field 30); a False recombination is capability-complete-but-uncaptured -> experimental.
# An unrecognized value refuses. Packet 1102.
_AUTOENTER_PROHIBIT_MOD = frozenset({"True", "False"})

# DDR Looked_up/@noMatchCopyOption → clip <NoMatchCopyOption>/@value. An EXPLICIT per-VALUE map, exactly like
# _INDEX_LANGUAGE — NOT a prefix rule, suffix rule, or pass-through: DoNotCopy passes through, but
# NextLower→CopyNextLower, NextHigher→CopyNextHigher, and ConstantData→CopyConstant (which ALSO emits a
# <CopyConstantValue> child from the DDR Looked_up/ConstantData text). All four proven byte-exact against the
# stored Scratch1 Alookup fields 18–21 (packet 1095). An unmapped value REFUSES in _lookup_capability rather
# than riding through as a raw @value the fence cannot check — the same discipline the index-language axis
# established (a blind pass-through would emit a value FileMaker does not accept).
_LOOKUP_NOMATCH = {"DoNotCopy": "DoNotCopy", "NextLower": "CopyNextLower",
                   "NextHigher": "CopyNextHigher", "ConstantData": "CopyConstant"}

# External-container Remote storage @type — the two source-visible topologies (packet 1096, from the stored
# Scratch1 Secure/Open pair). DDR→clip identity, but the two are DIFFERENT structural branches (Secure adds an
# empty <Secure/> marker + withFewerFolders; Open adds a <Location> path calc), dispatched in _emit_remote and
# grammar-checked in _remote_capability. An unmapped type refuses by name — never borrows the other branch.
_REMOTE_TYPES = frozenset({"Secure", "Open"})
# Secure's withFewerFolders is a direct Boolean pass-through into the clip; only "True" is captured, "False" is
# capable/experimental (same evidence-vs-permission split as the serial generate mode). An unrecognized value
# refuses. This is the OBSERVED vocabulary — do not invent alternate spellings.
_REMOTE_FEWER_FOLDERS = frozenset({"True", "False"})
# The base-directory reference @absolute state this packet accounts for. Only "False" is observed; "True" has
# no observed clip form (its numeric relativeTo target is unknown — never guess Boolean-as-integer), so it
# refuses by name. Packet 1096's honest evidence bound.
_REMOTE_ABSOLUTE_OK = "False"
# The five Furigana input modes observed across Scratch1 fields 22/24–29 (packet 1099). The DDR names them
# exactly as the clip does (pass-through, NOT a remap), but the vocabulary is CAPABILITY — an unobserved
# mode has no proven clip form and refuses by name rather than riding through raw. Declared independently of
# the fence, like _SUMMARY_OPERATIONS / _INDEX_LANGUAGE.
_FURIGANA_INPUT_MODES = frozenset({"Hiragana", "1ByteKatakana", "2ByteKatakana", "1ByteRoman", "2ByteRoman"})
# The only observed Furigana FieldReference repetition. Its target form (dropped from XMFD) is demonstrated
# only for "1"; another value could imply a different target the clip does not show, so it refuses.
_FURIGANA_REPETITION = "1"
# The DisplayNames @enable vocabulary (packet 1100, from the stored Scratch1 round-2 pair — SaveAsXML
# b0fd8707 → fmClip 0c4a7e03, field 30 "Number"). DDR→clip identity (True→True, False→False, both observed),
# but bounded: an unknown enable value refuses rather than riding through raw. An enable="True" DisplayNames
# couples to exactly one <Calculation> (the display-name calc, flattened by _calc_el exactly like every other
# calc in this dialect); enable="False" carries no children.
_DISPLAYNAMES_ENABLE = frozenset({"True", "False"})

# The ONE shared capability declaration: DDR tag → (attributes, child tags) the transform ACCOUNTS FOR —
# each is consumed by an _emit_* function above, or explicitly dropped the way the clip drops it (field /
# reference UUIDs, <TagList>: the XMFD format carries no element for them — the Projections Principle). A
# source attribute or child NOT listed is one the emitter would silently ignore, so capability fails and
# names it. A new FileMaker child/attribute lands here as an unaccounted-source refusal until its mapping
# is built and captured. This is the safety net behind every _emit_* helper; the value-level maps above
# (_DATATYPE, _INDEX_LANGUAGE, _CAPABLE_AUTOENTER_MODES, _CAPTURED_SERIAL_MODES, _LOOKUP_NOMATCH)
# guard the VALUES this walk cannot judge.
_CAPABLE_ELEMENTS = {
    "Field": ({"id", "name", "fieldtype", "datatype", "comment"},
              {"Calculation", "SummaryInfo", "AutoEnter", "Validation", "Storage", "Annotation",
               "DisplayNames", "TagList", "UUID", "Furigana"}),
    "Calculation": (set(), {"TableOccurrenceReference", "DDRREF", "Text"}),
    "Text": (set(), set()),
    "TableOccurrenceReference": ({"id", "name", "UUID"}, set()),
    # AdditionalField (packet 1097) is the second summary reference (weighted-average / running / fraction);
    # its cardinality + the mutually-exclusive TO/BaseTable anchor coupling the set-walk cannot express live
    # in _summary_capability. Whitelisting the tag alone is insufficient.
    "SummaryInfo": ({"operation", "restartEachGroup", "summarizeRepetition"},
                    {"SummaryField", "AdditionalField"}),
    "SummaryField": (set(), {"FieldReference"}),
    "AdditionalField": (set(), {"FieldReference"}),
    # `repetition` is carried by a Furigana FieldReference (packet 1099) and dropped from the target; the
    # summary/lookup FieldReferences never carry it. It rides the SHARED spec (FM reuses the tag), and the
    # value is judged where it matters — _furigana_capability requires the observed "1"; elsewhere it is
    # simply absent, so widening the attr set changes no existing field.
    "FieldReference": ({"id", "name", "UUID", "repetition"}, {"BaseTableReference", "TableOccurrenceReference"}),
    "BaseTableReference": ({"id", "name", "UUID"}, set()),
    # Top-level Furigana (packet 1099) — the input-mode VALUE + the reference CARDINALITY/ANCHOR/repetition
    # grammar the set-walk cannot express live in _furigana_capability; these specs declare the raw shape. The
    # target flattens FieldReference+BaseTableReference to one <Field id baseTable name/>; source UUIDs, the
    # base-table id, and the repetition are dropped.
    "Furigana": ({"inputMode"}, {"FieldReference"}),
    "AutoEnter": ({"type", "prohibitModification", "overwriteExisting", "alwaysEvaluate"},
                  {"Calculated", "ConstantData", "Looked_up", "SerialNumber"}),
    "Calculated": ({"enable"}, {"Calculation"}),
    "ConstantData": (set(), set()),
    # The ConstantData fallback child is legal here but ONLY for the ConstantData no-match option; the
    # option/child coupling + cardinality the set-walk cannot express live in _lookup_capability (packet 1095).
    "Looked_up": ({"dontCopyIfEmpty", "enable", "noMatchCopyOption"},
                  {"Context", "FieldReference", "ConstantData"}),
    "Context": (set(), {"TableOccurrenceReference"}),
    "SerialNumber": ({"generate", "increment", "nextvalue"}, set()),
    # The validation HOUSE (packet 1093, from the stored Scratch1 pair). The DDR carries the six switches as
    # ATTRIBUTES and the richer facts as CHILD elements: <Strict> (data-type), <Range>, <Calculated> (the
    # validation calc, same wrapper as auto-enter), <MessageCalc> (the failure-message calc), <MaximumSize>,
    # and <ValueListReference>. Whitelisting the PARENT alone is insufficient (packet 1093) — each child's
    # own attrs/children are declared below, and the value-level enum/enable checks live in
    # _validation_capability. A validation child NOT listed here is one _emit_validation would silently drop.
    "Validation": ({"allowOverride", "alwaysValidate", "existing", "notEmpty", "type", "unique"},
                   {"Strict", "Range", "Calculated", "MessageCalc", "MaximumSize", "ValueListReference"}),
    "Strict": (set(), set()),                          # <Strict>Numeric</Strict> — text = data-type enum
    "Range": ({"to", "from"}, set()),
    "MessageCalc": ({"enable"}, {"Calculation"}),      # same wrapper shape as auto-enter's <Calculated>
    "MaximumSize": (set(), set()),                     # <MaximumSize>3</MaximumSize> — text = max length
    "ValueListReference": ({"id", "name", "UUID"}, set()),
    "Storage": ({"storeCalculationResults", "autoIndex", "index", "global", "maxRepetitions"},
                {"LanguageReference", "Remote"}),
    "LanguageReference": ({"id", "name"}, set()),
    # External-container Remote storage (packet 1096, from the stored Scratch1 Secure/Open pair). The branch
    # cardinality/coupling + the absolute bound the set-walk cannot express live in _remote_capability; these
    # specs declare the raw grammar. Secure has @withFewerFolders + a <BaseDirectoryReference>; Open has a
    # <BaseDirectoryReference> + a <Location>. The base-directory UUID/@absolute are dropped by the emitter.
    "Remote": ({"type", "withFewerFolders"}, {"BaseDirectoryReference", "Location"}),
    "BaseDirectoryReference": ({"id", "name", "absolute", "UUID"}, set()),
    "Location": (set(), {"Calculation"}),
    # A non-empty field annotation is a nested <Annotation><Text>…</Text></Annotation> (packet 1101, from the
    # stored round-2 field 30). The at-most-one Text + no-direct-text coupling the set-walk cannot express live
    # in _annotation_capability; this declares the raw grammar. The empty form is a bare <Annotation/>.
    "Annotation": (set(), {"Text"}),
    # DisplayNames carries a display-name <Calculation> when enable="True" (packet 1100, from the stored
    # round-2 pair); the enable↔calc coupling + cardinality the set-walk cannot express live in
    # _displaynames_capability. The calc is the ordinary wrapper (TableOccurrenceReference/DDRREF/Text),
    # already declared above and flattened by _calc_el.
    "DisplayNames": ({"enable"}, {"Calculation"}),
    # SaveAsXML-only projection metadata (packet 1094, from the raw Scratch1::PrimaryKey source). FileMaker
    # keeps these in the DDR projection but writes NONE of them into XMFD, so they are accounted here as
    # TARGET-ABSENT — accepted at their exact legal parent (field <UUID>/<TagList>, calculation <DDRREF>),
    # then dropped by the emitter because the clip has no element to carry them. This is an explicit
    # projection drop, NOT a generic noise stripper: the grammar is the observed one only (their attributes
    # and text are recorded, not emitted), and any UNKNOWN attribute/child on them, or either element at an
    # unaccounted parent, still refuses through the ordinary walk (the parent's child whitelist gates
    # placement; these specs gate their own attrs). Their values are provenance, never a target enum, so
    # changing them does not move the signature or the clip.
    "UUID": ({"modifications", "userName", "accountName", "timestamp"}, set()),  # a <Field> identity child
    "DDRREF": ({"kind", "hash"}, set()),               # a <Calculation> cross-reference child (ChunkList)
    "TagList": ({"primary"}, set()),                   # a <Field> tag child; @primary was the masked blocker
}

# Validation VALUE vocabularies — hand-listed maps grounded in the stored pair, exactly like _LOOKUP_NOMATCH
# / _INDEX_LANGUAGE (the value-level guards the structural walk cannot make). FM's "Validate data in this
# field" dropdown has exactly these two modes (DDR→clip identity: Always→Always). The strict-data-type axis
# is an explicit DDR→XMFD VALUE MAP, NOT identity: its keys are the DDR <Strict> source tokens, its values
# the observed clip @value tokens (packet 1098 — the stored field 29 pair proved DDR `Time` → clip
# `TimeOfDay`, so the target spelling is NOT a valid source and is never accepted by analogy). An unseen
# source value is refused by name rather than guessed — a guess the fence could not catch (the value rides
# as element text / an @type, not a shape token), the same discipline the index-language axis established.
_VALIDATION_TYPES = frozenset({"OnlyDuringDataEntry", "Always"})
_STRICT_DATATYPES = {"Numeric": "Numeric", "FourDigitYear": "FourDigitYear", "Time": "TimeOfDay"}


def _validation_capability(val) -> "tuple[str, str] | None":
    """None when _emit_validation fully consumes this DDR <Validation>, else the first (reason_code, detail)
    that blocks it. The value/enum/enable checks the structural walk (_unaccounted_source) cannot make:
    an unseen validation type or strict-data-type value, or a DISABLED validation <Calculated>/<MessageCalc>
    whose clip form we have never observed. Structural unknowns (a new attribute/child/nesting) are caught
    generically by _unaccounted_source against the whitelist above; this adds only the value layer."""
    if val is None:
        return None
    vtype = val.get("type")
    if vtype not in _VALIDATION_TYPES:
        return ("unmapped_validation_type",
                f"validation type {vtype!r} has no verified clip mapping (known: {sorted(_VALIDATION_TYPES)})")
    strict = val.find("Strict")
    if strict is not None and (strict.text or "").strip() not in _STRICT_DATATYPES:
        return ("unmapped_strict_datatype",
                f"strict data type {(strict.text or '').strip()!r} has no verified clip mapping "
                f"(known: {sorted(_STRICT_DATATYPES)})")
    for tag in ("Calculated", "MessageCalc"):
        node = val.find(tag)
        if node is not None and node.get("enable") == "False":
            return ("disabled_validation_calc",
                    f"a disabled <{tag} enable=\"False\"> inside <Validation> has no observed clip form — "
                    f"its emitted shape is unknown, so it refuses rather than guess")
    return None


def _lookup_capability(ae) -> "tuple[str, str] | None":
    """None when _emit_lookup fully reproduces this DDR Looked_up auto-enter, else the first
    (reason_code, detail). The Lookup VALUE + CARDINALITY + COUPLING grammar the set-based structural walk
    (_unaccounted_source) cannot express: that walk proves each child TAG is whitelisted, but not that there
    is EXACTLY ONE source field / context / required TableOccurrenceReference, nor that the ConstantData
    fallback child is coupled to the ConstantData option. _emit_lookup uses first-match .find(), so a
    duplicate or a missing node would be silently flattened away — this refuses by name instead. Only fires
    for a Looked_up auto-enter; every other field returns None here."""
    if ae is None or ae.get("type") != "Looked_up":
        return None
    lus = ae.findall("Looked_up")
    if len(lus) != 1:
        return ("lookup_cardinality",
                f"a Looked_up auto-enter must carry exactly one <Looked_up> child (found {len(lus)})")
    lu = lus[0]
    if lu.get("enable") != "True":
        return ("lookup_disabled",
                f"a <Looked_up enable={lu.get('enable')!r}> is not the observed enabled 'True' form — its "
                f"clip shape is unobserved (does FileMaker retain a disabled lookup block?), so it refuses "
                f"rather than guess")
    opt = lu.get("noMatchCopyOption")
    if opt not in _LOOKUP_NOMATCH:
        return ("unmapped_nomatch_option",
                f"lookup noMatchCopyOption {opt!r} has no verified clip mapping (known: "
                f"{sorted(_LOOKUP_NOMATCH)}) — an unmapped value is not proven to pass through unremapped")
    frs = lu.findall("FieldReference")
    if len(frs) != 1:
        return ("lookup_source_field",
                f"a Lookup requires exactly one source <FieldReference> (found {len(frs)})")
    if len(frs[0].findall("TableOccurrenceReference")) != 1:
        return ("lookup_source_to",
                "a Lookup source <FieldReference> requires exactly one <TableOccurrenceReference>")
    ctxs = lu.findall("Context")
    if len(ctxs) != 1:
        return ("lookup_context", f"a Lookup requires exactly one <Context> (found {len(ctxs)})")
    if len(ctxs[0].findall("TableOccurrenceReference")) != 1:
        return ("lookup_context_to",
                "a Lookup <Context> requires exactly one <TableOccurrenceReference>")
    consts = lu.findall("ConstantData")
    if opt == "ConstantData":
        if len(consts) != 1:
            return ("lookup_constant_child",
                    f"the ConstantData no-match option requires exactly one <ConstantData> fallback child "
                    f"(the <CopyConstantValue> source; found {len(consts)})")
    elif consts:
        return ("lookup_stray_constant",
                f"noMatchCopyOption {opt!r} must carry no <ConstantData> fallback child (found "
                f"{len(consts)}) — only ConstantData does")
    return None


def _remote_capability(sto) -> "tuple[str, str] | None":
    """None when _emit_remote fully reproduces this DDR Storage's external-container Remote block, else the
    first (reason_code, detail). The Remote VALUE + BRANCH + CARDINALITY grammar the set-based walk cannot
    express (packet 1096, from the stored Scratch1 Secure/Open pair): a mapped @type, exactly one base
    reference, the absolute bound, and the Secure-vs-Open branch coupling (withFewerFolders + no Location for
    Secure; a single Location/Calculation + no withFewerFolders for Open). Only fires when a <Remote> is
    present; every non-Remote Storage returns None."""
    if sto is None:
        return None
    rems = sto.findall("Remote")
    if not rems:
        return None
    if len(rems) != 1:
        return ("remote_cardinality",
                f"Storage must carry exactly one <Remote> child (found {len(rems)})")
    rem = rems[0]
    # a Remote container has NO index/language topology in the observed pair; combining them is unobserved,
    # so refuse rather than emit a plausible-but-unseen tree (never silently discard the index side).
    if sto.find("LanguageReference") is not None or any(
            sto.get(a) is not None for a in ("storeCalculationResults", "autoIndex", "index")):
        return ("remote_with_index_topology",
                "Remote external-container storage combined with an index/storeCalculationResults/language "
                "topology is an unobserved combination — refused rather than emit an unverified tree")
    rtype = rem.get("type")
    if rtype not in _REMOTE_TYPES:
        return ("unmapped_remote_type",
                f"Remote storage type {rtype!r} has no verified clip mapping (known: {sorted(_REMOTE_TYPES)}) "
                f"— an unmapped type must not borrow another branch's shape")
    bdrs = rem.findall("BaseDirectoryReference")
    if len(bdrs) != 1:
        return ("remote_base_reference",
                f"a Remote requires exactly one <BaseDirectoryReference> (found {len(bdrs)})")
    absolute = bdrs[0].get("absolute")
    if absolute != _REMOTE_ABSOLUTE_OK:
        return ("unmapped_remote_absolute",
                f"BaseDirectoryReference absolute={absolute!r} is outside the observed bound "
                f"(only {_REMOTE_ABSOLUTE_OK!r} is captured) — an absolute base path has no observed clip "
                f"form, so it refuses rather than guess a Boolean-as-integer relativeTo")
    fewer = rem.get("withFewerFolders")
    locs = rem.findall("Location")
    if rtype == "Secure":
        if fewer is None:
            return ("remote_missing_fewer_folders",
                    "a Secure Remote requires the observed withFewerFolders attribute")
        if fewer not in _REMOTE_FEWER_FOLDERS:
            return ("unmapped_fewer_folders",
                    f"withFewerFolders={fewer!r} is not the observed Boolean vocabulary "
                    f"{sorted(_REMOTE_FEWER_FOLDERS)}")
        if locs:
            return ("remote_secure_location",
                    "a Secure Remote must carry no <Location> (that is the Open branch)")
    else:                                                  # Open
        if fewer is not None:
            return ("remote_open_fewer_folders",
                    "an Open Remote must carry no withFewerFolders (that is the Secure branch)")
        if len(locs) != 1:
            return ("remote_location",
                    f"an Open Remote requires exactly one <Location> (found {len(locs)})")
        calcs = locs[0].findall("Calculation")
        if len(calcs) != 1:
            return ("remote_location_calc",
                    f"an Open Remote <Location> requires exactly one <Calculation> (found {len(calcs)})")
        if not (calcs[0].findtext("Text") or ""):
            return ("remote_incomplete_calc",
                    "the Open Remote <Location> <Calculation> carries no <Text> — an empty path calc is "
                    "an incomplete Remote, refused rather than emit a blank Location")
    return None


def _summary_anchor_error(fr, where) -> "tuple[str, str] | None":
    """None when a summary <FieldReference> carries EXACTLY ONE anchor of the observed kinds (a
    TableOccurrenceReference OR a BaseTableReference, never neither/both/duplicate), else the (reason_code,
    detail). The anchor determines the flattened target's @table, and _emit_summary_info dispatches on it —
    a missing or ambiguous anchor would emit the wrong target, so it refuses by name (packet 1097)."""
    n = len(fr.findall("TableOccurrenceReference")) + len(fr.findall("BaseTableReference"))
    if n != 1:
        return ("summary_anchor",
                f"a {where} <FieldReference> requires exactly one anchor — a <TableOccurrenceReference> "
                f"(target gets @table) or a <BaseTableReference> (target omits @table), found {n}")
    return None


def _summary_capability(field) -> "tuple[str, str] | None":
    """None when _emit_summary_info fully reproduces this DDR Summary field, else the first
    (reason_code, detail). The Summary VOCABULARY + CARDINALITY + ANCHOR grammar the set-based walk cannot
    express (packet 1097): a mapped operation/restart/repetition, exactly one SummaryInfo/SummaryField/
    primary FieldReference with one anchor, and an optional single AdditionalField whose one FieldReference
    carries exactly one anchor. The operation vocabulary is INDEPENDENT of the fence (permission ≠ evidence).
    Only fires for a Summary field; every other field returns None here."""
    if field.get("fieldtype") != "Summary":
        return None
    sis = field.findall("SummaryInfo")
    if len(sis) != 1:
        return ("summary_cardinality",
                f"a Summary field requires exactly one <SummaryInfo> (found {len(sis)})")
    si = sis[0]
    op = si.get("operation")
    if op not in _SUMMARY_OPERATIONS:
        return ("unmapped_summary_operation",
                f"summary operation {op!r} is not in the observed FileMaker vocabulary "
                f"(known: {sorted(_SUMMARY_OPERATIONS)}) — an unmapped operation is not proven to pass "
                f"through unremapped")
    if si.get("restartEachGroup") not in _SUMMARY_RESTART:
        return ("unmapped_summary_restart",
                f"restartEachGroup={si.get('restartEachGroup')!r} is not the observed Boolean vocabulary "
                f"{sorted(_SUMMARY_RESTART)}")
    if si.get("summarizeRepetition") not in _SUMMARY_REPETITION:
        return ("unmapped_summary_repetition",
                f"summarizeRepetition={si.get('summarizeRepetition')!r} is not the observed vocabulary "
                f"{sorted(_SUMMARY_REPETITION)}")
    sfs = si.findall("SummaryField")
    if len(sfs) != 1:
        return ("summary_field_cardinality",
                f"a Summary requires exactly one <SummaryField> (found {len(sfs)})")
    pfrs = sfs[0].findall("FieldReference")
    if len(pfrs) != 1:
        return ("summary_field_reference",
                f"the primary <SummaryField> requires exactly one <FieldReference> (found {len(pfrs)})")
    if err := _summary_anchor_error(pfrs[0], "primary SummaryField"):
        return err
    adds = si.findall("AdditionalField")
    if len(adds) > 1:
        return ("summary_additional_cardinality",
                f"a Summary carries at most one <AdditionalField> (found {len(adds)})")
    if adds:
        afrs = adds[0].findall("FieldReference")
        if len(afrs) != 1:
            return ("summary_additional_reference",
                    f"an <AdditionalField> requires exactly one <FieldReference> (found {len(afrs)})")
        if err := _summary_anchor_error(afrs[0], "AdditionalField"):
            return err
    return None


def _furigana_capability(field) -> "tuple[str, str] | None":
    """None when _emit_furigana fully reproduces this field's top-level <Furigana>, else the first
    (reason_code, detail). Furigana is a TOP-LEVEL DDR <Field> child (never nested under AutoEnter): the
    input-mode VALUE vocabulary + the reference CARDINALITY / ANCHOR / repetition grammar the set-based walk
    (_unaccounted_source) cannot express. That walk proves each child TAG is whitelisted; this proves there
    is exactly ONE <Furigana>, on a supported Normal Text field with a flag-bearing AutoEnter, carrying
    exactly one <FieldReference> (id+name, the observed repetition "1") anchored by exactly one
    <BaseTableReference> — no TableOccurrenceReference anchor and no duplicates the first-match emitter would
    silently flatten (packet 1099)."""
    furis = field.findall("Furigana")
    if not furis:
        return None
    if len(furis) > 1:
        return ("furigana_cardinality",
                f"a field carries at most one <Furigana> (found {len(furis)})")
    fu = furis[0]
    if field.get("fieldtype") != "Normal" or field.get("datatype") != "Text":
        return ("furigana_field_shape",
                f"Furigana is observed only on a Normal Text field, not "
                f"{field.get('fieldtype')!r}/{field.get('datatype')!r}")
    ae = field.find("AutoEnter")
    if ae is None or ae.get("type") is None:
        return ("furigana_autoenter",
                "a Furigana field needs a flag-bearing <AutoEnter type=…> to carry furigana=\"True\"")
    mode = fu.get("inputMode")
    if mode not in _FURIGANA_INPUT_MODES:
        return ("unmapped_furigana_mode",
                f"input mode {mode!r} is not an observed Furigana mode "
                f"(known: {sorted(_FURIGANA_INPUT_MODES)})")
    frs = fu.findall("FieldReference")
    if len(frs) != 1:
        return ("furigana_reference_cardinality",
                f"<Furigana> requires exactly one <FieldReference> (found {len(frs)})")
    fr = frs[0]
    if fr.find("TableOccurrenceReference") is not None:
        return ("furigana_anchor_type",
                "a Furigana <FieldReference> anchors on a <BaseTableReference>; a "
                "<TableOccurrenceReference> has no observed target form")
    if not fr.get("id") or not fr.get("name"):
        return ("furigana_reference_incomplete",
                "the Furigana <FieldReference> needs both id and name")
    if fr.get("repetition") != _FURIGANA_REPETITION:
        return ("unmapped_furigana_repetition",
                f"repetition {fr.get('repetition')!r} has no demonstrated target form "
                f"(observed: {_FURIGANA_REPETITION!r})")
    btrs = fr.findall("BaseTableReference")
    if len(btrs) != 1:
        return ("furigana_anchor_cardinality",
                f"the Furigana <FieldReference> requires exactly one <BaseTableReference> "
                f"(found {len(btrs)})")
    btr = btrs[0]
    if not btr.get("name") or not btr.get("id"):
        return ("furigana_anchor_incomplete",
                "the Furigana <BaseTableReference> needs both name and id")
    return None


def _displaynames_capability(field) -> "tuple[str, str] | None":
    """None when _emit_displaynames fully reproduces this field's <DisplayNames>, else the first
    (reason_code, detail). DisplayNames is a top-level DDR <Field> child: the @enable VALUE + the
    enable↔<Calculation> COUPLING the set-based walk (_unaccounted_source) cannot express. That walk proves
    the <Calculation> TAG is whitelisted; this proves there is exactly ONE <DisplayNames>, its @enable is one
    of the two observed values, an enable="True" carries exactly one <Calculation> (the display-name calc),
    and an enable="False" carries none — the observed grammar of the stored round-2 pair (packet 1100)."""
    dns = field.findall("DisplayNames")
    if not dns:
        return None
    if len(dns) > 1:
        return ("displaynames_cardinality",
                f"a field carries at most one <DisplayNames> (found {len(dns)})")
    dn = dns[0]
    enable = dn.get("enable")
    if enable not in _DISPLAYNAMES_ENABLE:
        return ("unmapped_displaynames_enable",
                f"DisplayNames enable {enable!r} is not an observed value "
                f"(known: {sorted(_DISPLAYNAMES_ENABLE)})")
    calcs = dn.findall("Calculation")
    if enable == "False" and calcs:
        return ("displaynames_false_with_calc",
                "an enable=\"False\" <DisplayNames> carrying a <Calculation> has no observed clip form")
    if enable == "True" and len(calcs) != 1:
        return ("displaynames_calc_cardinality",
                f"an enable=\"True\" <DisplayNames> requires exactly one <Calculation> (found {len(calcs)})")
    return None


def _annotation_capability(field) -> "tuple[str, str] | None":
    """None when _emit_field fully reproduces this field's <Annotation>, else the first (reason_code, detail).
    The two observed content states (packet 1101, from the stored round-2 field 30): an empty <Annotation/>
    and a nested <Annotation><Text>…</Text></Annotation>. The at-most-one-Text CARDINALITY + the no-direct-text
    COUPLING the set-based walk (_unaccounted_source) cannot express — that walk proves the <Text> TAG is
    whitelisted, but not that there is exactly one, nor that the emitter (which reads the nested <Text>) would
    not silently drop direct annotation text. The text itself is CONTENT, not a bounded vocabulary."""
    anns = field.findall("Annotation")
    if not anns:
        return None
    if len(anns) > 1:
        return ("annotation_cardinality",
                f"a field carries at most one <Annotation> (found {len(anns)})")
    ann = anns[0]
    if (ann.text or "").strip():
        return ("annotation_direct_text",
                "an <Annotation> with direct text (not a nested <Text>) has no observed clip form — the "
                "emitter reads the nested <Text>, so direct text would be silently dropped")
    texts = ann.findall("Text")
    if len(texts) > 1:
        return ("annotation_text_cardinality",
                f"an <Annotation> carries at most one <Text> (found {len(texts)})")
    return None


def _lastvisited_capability(field) -> "tuple[str, str] | None":
    """None when _emit_autoenter fully reproduces this field's LastVisited AutoEnter, else the first
    (reason_code, detail). The mode-specific cardinality/coupling the generic AutoEnter whitelist cannot
    express (packet 1102, from the stored round-2 field 30): exactly one AutoEnter; the prohibitModification
    Boolean present + bounded (it drives the target allowEditing via the proven polarity flip); and — as the
    single observed shape demonstrates — NO overwriteExisting/alwaysEvaluate attributes and NO auto-enter
    child blocks (an unobserved coupling the emitter would otherwise flatten). Only fires for a LastVisited
    AutoEnter; the mode VALUE itself is gated by _CAPABLE_AUTOENTER_MODES in _unmapped_value."""
    ae = field.find("AutoEnter")
    if ae is None or ae.get("type") != "LastVisited":
        return None
    if len(field.findall("AutoEnter")) != 1:
        return ("autoenter_cardinality",
                f"a field carries exactly one <AutoEnter> (found {len(field.findall('AutoEnter'))})")
    pm = ae.get("prohibitModification")
    if pm not in _AUTOENTER_PROHIBIT_MOD:
        return ("lastvisited_prohibit_modification",
                f"LastVisited prohibitModification {pm!r} is not a bounded Boolean "
                f"(known: {sorted(_AUTOENTER_PROHIBIT_MOD)})")
    extra = set(ae.attrib) - {"type", "prohibitModification"}
    if extra:
        return ("lastvisited_unexpected_attr",
                f"the observed LastVisited AutoEnter carries only type + prohibitModification; "
                f"{sorted(extra)} is unaccounted")
    if len(ae):
        return ("lastvisited_unexpected_child",
                f"the observed LastVisited AutoEnter carries no child blocks; "
                f"{sorted(c.tag for c in ae)} is unaccounted")
    return None


def _unmapped_value(field) -> "tuple[str, str] | None":
    """First (reason_code, detail) for a source VALUE that drives a remap / bounded vocabulary the transform
    does not map — else None. These are values that, blindly passed through, emit structurally-valid but
    WRONG (the Unicode → Unicode_Raw lesson), so an unknown one refuses by NAME here instead of KeyError-ing
    in the emitter."""
    dt = field.get("datatype")
    if dt not in _DATATYPE:
        return ("unmapped_datatype",
                f"datatype {dt!r} has no verified clip mapping (known: {sorted(_DATATYPE)})")
    ae = field.find("AutoEnter")
    if ae is not None:
        mode = ae.get("type")
        if mode is not None and mode not in _CAPABLE_AUTOENTER_MODES:
            return ("unmapped_autoenter_mode",
                    f"auto-enter mode {mode!r} has no verified clip mapping — it would ride through as a "
                    f"raw @value the fence cannot check (known: {sorted(_CAPABLE_AUTOENTER_MODES)})")
        serial = ae.find("SerialNumber")
        if serial is not None and serial.get("generate") not in _CAPTURED_SERIAL_MODES:
            return ("unmapped_serial_generate",
                    f"serial generate mode {serial.get('generate')!r} is not a recognized FileMaker serial "
                    f"mode (known: {sorted(_CAPTURED_SERIAL_MODES)}) — an unseen value is not proven to "
                    f"pass through unremapped")
        # The Lookup no-match value + its full grammar are judged by _lookup_capability (a dedicated
        # authority — cardinality and option/child coupling the set-walk cannot express), not here.
    lang = field.find("Storage/LanguageReference")
    if lang is not None and lang.get("name") not in _INDEX_LANGUAGE:
        return ("unmapped_index_language",
                f"index language {lang.get('name')!r} is not in the explicit clip mapping "
                f"(mapped: {sorted(_INDEX_LANGUAGE)}). This axis is DEMONSTRATED NON-IDENTITY "
                f"(Unicode → Unicode_Raw), so an unmapped name cannot be assumed verbatim — a blind "
                f"pass-through could paste cleanly while silently changing indexing behaviour. Refused as "
                f"a known misleading-output hazard (packet 1090 — final policy), NOT a missing-pair gap; a "
                f"new language needs an explicit mapping decision + regression, not a captured signature")
    return None


def _unaccounted_source(field) -> "tuple[str, str] | None":
    """First (reason_code, detail) for a source element / attribute / child the transform does not account
    for — else None. Walks the whole field against _CAPABLE_ELEMENTS: a child the emitter would silently
    ignore is NOT supported, so it fails capability and is named rather than dropped."""
    for el in field.iter():
        spec = _CAPABLE_ELEMENTS.get(el.tag)
        if spec is None:
            return ("unaccounted_source_element",
                    f"<{el.tag}> is a source element the field transform does not handle")
        allowed_attrs, allowed_children = spec
        if extra := (set(el.attrib) - allowed_attrs):
            return ("unaccounted_source_attr",
                    f"<{el.tag}> carries attribute(s) {sorted(extra)} the transform does not consume")
        if kids := ({k.tag for k in el} - allowed_children):
            return ("unaccounted_source_child",
                    f"<{el.tag}> carries child element(s) {sorted(kids)} the transform does not consume")
    return None


def _field_capability(field) -> "tuple[str, str] | None":
    """None when the current transform fully accounts for every source feature of this field; otherwise the
    first (reason_code, detail) that blocks it. Permission — NOT evidence. Order: root shape, then unmapped
    VALUES (named mapping hazards, ahead of the generic walk), then any unaccounted element/attr/child."""
    if field.tag != "Field":
        return ("not_a_field", f"not a DDR <Field> element (got <{field.tag}>)")
    ft = field.get("fieldtype")
    if ft not in _FIELD_TYPES:
        return ("unmapped_fieldtype",
                f"field type {ft!r} has no emitter branch (handled: {sorted(_FIELD_TYPES)})")
    if ft == "Summary" and field.find("SummaryInfo") is None:
        return ("incomplete_summary", "summary field carries no <SummaryInfo> aggregate to emit")
    if ft == "Calculated" and field.find("Calculation") is None:
        return ("incomplete_calculated", "calculated field carries no <Calculation> formula to emit")
    return (_unmapped_value(field)
            or _validation_capability(field.find("Validation"))
            or _lookup_capability(field.find("AutoEnter"))
            or _remote_capability(field.find("Storage"))
            or _summary_capability(field)
            or _furigana_capability(field)
            or _displaynames_capability(field)
            or _annotation_capability(field)
            or _lastvisited_capability(field)
            or _unaccounted_source(field))


class FieldAssessment(NamedTuple):
    """The single structured verdict for one DDR <Field> under the packet-1086 epoch (packet 1088).

    permission is the emit/refuse gate; evidence separates a byte-captured emit from an uncaptured one;
    result_state is the canonical fmClip-epoch state; reason_code is stable for machines; detail names the
    concrete source feature; signature is for diagnostics ONLY, never the permission decision. One object,
    so the MCP result is built from it without parallel booleans that can disagree."""
    permission: str       # "emit" | "refuse"
    evidence: str         # "verified" | "experimental" | "none"
    result_state: str     # generated_verified | generated_experimental | refused_known_hazard
    reason_code: str
    detail: str
    signature: tuple


def unsupported_field_reason(field) -> "str | None":
    """Why this field is not a VERIFIED (byte-exact) shape, or None when it is. The EVIDENCE predicate,
    unchanged by the epoch: an experimental field (capability-complete but uncaptured) is still not
    byte-verified, so this still returns a reason for it. Permission is a SEPARATE question — see
    field_generation_assessment / _field_capability — and a field this reports on may well still EMIT
    (experimentally). Do not repurpose this as the permission gate; callers that want emit/refuse must ask
    the assessment."""
    if field.tag != "Field":
        return f"not a DDR <Field> element (got <{field.tag}>)"
    sig = _field_signature(field)
    if sig in _VERIFIED_FIELD_SIGS:
        return None
    return (f"unverified field shape {list(sig)} — no captured (DDR field, XMFD clip) pair grounds it. "
            f"{_FIELD_TYPE_NOTE}")


def field_generation_assessment(field) -> FieldAssessment:
    """Emit/refuse permission + evidence state for one DDR <Field> (packet 1088, fmClip epoch).

    Two independent questions, one verdict:
      · CAPABILITY (_field_capability) — does the transform account for every source feature? This is
        PERMISSION. A field with any unmapped value or unaccounted child/attr REFUSES, named.
      · EVIDENCE (_VERIFIED_FIELD_SIGS) — is the exact shape byte-captured? This only splits a VERIFIED
        emit from an EXPERIMENTAL one; it never grants or denies permission by itself.

    So: capable + captured → generated_verified; capable + uncaptured → generated_experimental; incapable
    → refused_known_hazard. Fixture absence alone no longer refuses — the packet-1087 serial cross-mode is
    now just one ordinary capable-but-uncaptured case. emit_field / emit_field_clip gate on .permission."""
    if field.tag != "Field":
        return FieldAssessment("refuse", "none", "refused_known_hazard", "not_a_field",
                               f"not a DDR <Field> element (got <{field.tag}>)", ())
    sig = _field_signature(field)
    cap = _field_capability(field)
    if cap is not None:
        code, detail = cap
        return FieldAssessment("refuse", "none", "refused_known_hazard", code, detail, sig)
    if sig in _VERIFIED_FIELD_SIGS:
        return FieldAssessment("emit", "verified", "generated_verified", "verified", "", sig)
    return FieldAssessment(
        "emit", "experimental", "generated_experimental", "capability_complete_uncaptured",
        "every source feature is accounted for by the current transform, but this exact shape has no "
        "captured (DDR field, XMFD clip) pair — emits experimentally (static-valid, correct by "
        "construction, NOT FileMaker-verified)", sig)


def _calc_el(parent, calc_node):
    """<Calculation table="<TO name>">…text…</Calculation> from a DDR Calculation block.

    The calc text is NOT passed through verbatim — FileMaker canonicalizes some built-in function-name
    casings differently in the clipboard than in the DDR (`GetAsTimeStamp` → `GetAsTimestamp`). Both
    parse — FM function names are case-insensitive — so a straight copy is not *broken*, just not
    byte-identical to a real FM copy, which is the only thing this emitter's fence measures.

    Shared with clip_emit rather than reimplemented: a field's calc and a script step's calc go through
    the same clipboard, and two copies of that map would drift invisibly."""
    from corpusfm.core.clip_emit import _canon_calc
    to = calc_node.find("TableOccurrenceReference")
    c = ET.SubElement(parent, "Calculation", {"table": to.get("name") if to is not None else ""})
    c.text = _canon_calc(calc_node.findtext("Text") or "")
    return c


def _emit_autoenter(parent, field):
    """<AutoEnter …flags…> + its ConstantData / Calculation children.

    The two dialects disagree in POLARITY here and it is the sharpest trap in the mapping: the DDR says
    `prohibitModification="False"`, the clip says `allowEditing="True"`. Same fact, opposite sense — copy
    it across unthinkingly and every emitted field silently flips its edit permission.

    A Calculated FIELD's AutoEnter is a different animal from a Normal field's: it carries only
    `alwaysEvaluate` and no flags at all, so the flag block is emitted only when the DDR names a @type."""
    ae = field.find("AutoEnter")
    if ae is None:
        return
    mode = ae.get("type")
    if mode is None:                               # a Calculated field's bare <AutoEnter alwaysEvaluate/>
        ET.SubElement(parent, "AutoEnter", {"alwaysEvaluate": ae.get("alwaysEvaluate") or "False"})
        return
    attrs = {"allowEditing": "False" if ae.get("prohibitModification") == "True" else "True"}
    # @value names the DDR's primary mode — except for Calculated (which omits it) and for a field with NO
    # auto-enter at all, whose DDR carries a literal `type=""`. That empty mode must emit NO @value; the
    # earlier `value=""` was invented, and FileMaker writes the attribute away entirely.
    if mode and mode not in _AUTOENTER_VALUE_OMITTED:
        attrs["value"] = _AUTOENTER_MODE.get(mode, mode)
    # ABSENT ≠ False. The DDR omits overwriteExisting/alwaysEvaluate on every mode that cannot use them
    # (no-auto-enter, CreationTimestamp, the account/name modes) and states them only on Calculated — and
    # the clip omits them in exactly the same cases. Defaulting absent→"False" here invented two
    # attributes on 13 of 39 real fields. Same absent-vs-literal trap `_attr` exists for on the fence side.
    for ddr_attr, clip_attr in (("overwriteExisting", "overwriteExistingValue"),
                                ("alwaysEvaluate", "alwaysEvaluate")):
        if ae.get(ddr_attr) is not None:
            attrs[clip_attr] = ae.get(ddr_attr)
    attrs.update({"constant": "False", "furigana": "False", "lookup": "False", "calculation": "False"})
    # The furigana flag is driven by the TOP-LEVEL <Furigana> field child, NOT an AutoEnter child (packet
    # 1099) — so it is computed from the field here, never added to _AUTOENTER_CHILD_FLAG. Capability has
    # already gated a present Furigana as well-formed by the time emit_field reaches this path.
    if field.find("Furigana") is not None:
        attrs["furigana"] = "True"
    # The flags describe WHICH BLOCKS ARE ACTIVE, not merely present: id 19 is @type="ConstantData" yet
    # carries a Calculated block too, and its clip sets constant AND calculation True.
    #
    # ...but PRESENT ≠ ACTIVE. A block can be retained-and-disabled: `<Calculated enable="False">` keeps
    # the formula while switching it off, and the clip then says calculation="False" AND STILL EMITS THE
    # <Calculation> CHILD (UMAGLOBAL::Menu.ListOfFeature). So the flag reads @enable and the child is
    # emitted regardless — reading existence alone flipped a disabled auto-enter calc back ON.
    for child, flag in _AUTOENTER_CHILD_FLAG.items():
        el = ae.find(child)
        if el is not None and el.get("enable") != "False":
            attrs[flag] = "True"
    el = ET.SubElement(parent, "AutoEnter", attrs)
    # <Serial> leads, BEFORE <ConstantData> — the one auto-enter block that does. Every other block
    # follows the constant. FileMaker's order, read off a pair; do not tidy it.
    _emit_serial(el, ae)
    const = ae.find("ConstantData")
    cd = ET.SubElement(el, "ConstantData")         # always present, empty when unset
    if const is not None:
        cd.text = const.text
    # ABSENT ≠ EMPTY, one more time (packet 1083). An ENABLED-but-EMPTY auto-enter calc — the formula box
    # left blank — is stored as `<Calculated enable="True">` wrapping a `<Calculation>` with NO <Text> child
    # (its DDRREF hash is the MD5 of the empty string). FileMaker keeps calculation="True" on the flag but
    # OMITS the <Calculation> element entirely; we used to emit `<Calculation table="…"/>`, an element FM
    # never writes. So the child is gated on the calc actually carrying text — the flag already rode off
    # @enable above, exactly as the retained-disabled case needs. Proven by Scratch1::EmptyAutoEnterCalc,
    # which shares PrimaryKey's shape and differs only in this empty calc text. Third in the absent-vs-empty
    # family, after the invented overwriteExisting/alwaysEvaluate and the invented value="".
    calc = ae.find("Calculated/Calculation")
    if calc is not None and (calc.findtext("Text") or ""):
        _calc_el(el, calc)
    _emit_lookup(el, ae)


def _emit_serial(parent, ae):
    """<Serial …/> — a serial-number auto-enter.

    Two shifts, neither a copy: the element is RENAMED (`SerialNumber` → `Serial`) and the DDR's
    lower-case `nextvalue` becomes the clip's camel-case `nextValue`. The same casing trap as
    Timestamp→TimeStamp — a straight attribute copy emits a `nextvalue` FileMaker ignores, so the pasted
    field silently restarts its serial at 1."""
    s = ae.find("SerialNumber")
    if s is None:
        return
    ET.SubElement(parent, "Serial", {"increment": s.get("increment"),
                                     "nextValue": s.get("nextvalue"),
                                     "generate": s.get("generate")})


def _emit_lookup(parent, ae):
    """<Lookup> — a looked-up-value auto-enter.

    The DDR nests the source under `<Looked_up><FieldReference><TableOccurrenceReference>` plus a separate
    `<Context>` TO; the clip FLATTENS that into a `<Table>` (the context) + a `<Field table=… id name>`
    (the source), then states the two options as valued child elements.

    ⚠ THE THIRD POLARITY FLIP in this dialect pair, and the same trap as the first two: the DDR's
    `dontCopyIfEmpty="False"` becomes the clip's `<CopyEmptyContent value="True"/>` — same fact, opposite
    sense. Copy it across and every emitted lookup inverts its don't-copy-if-empty behaviour.

    The no-match option is a PER-VALUE REMAP (_LOOKUP_NOMATCH), not a pass-through: DoNotCopy passes through
    but NextLower/NextHigher/ConstantData become CopyNextLower/CopyNextHigher/CopyConstant, and CopyConstant
    ALSO emits a `<CopyConstantValue>` child (the DDR `Looked_up/ConstantData` text) between the option and
    the empty-content element. All four proven byte-exact against the stored Scratch1 Alookup fields (packet
    1095). Grammar/cardinality is enforced upstream by _lookup_capability, so the option is guaranteed mapped
    and — for CopyConstant — the single ConstantData child is guaranteed present when this runs."""
    lu = ae.find("Looked_up")
    if lu is None:
        return
    el = ET.SubElement(parent, "Lookup")
    ctx = lu.find("Context/TableOccurrenceReference")
    if ctx is not None:
        ET.SubElement(el, "Table", {"id": ctx.get("id"), "name": ctx.get("name")})
    src = lu.find("FieldReference")
    if src is not None:
        to = src.find("TableOccurrenceReference")
        ET.SubElement(el, "Field", {"table": to.get("name") if to is not None else "",
                                    "id": src.get("id"), "name": src.get("name")})
    opt = lu.get("noMatchCopyOption")
    ET.SubElement(el, "NoMatchCopyOption", {"value": _LOOKUP_NOMATCH[opt]})
    if opt == "ConstantData":              # the constant fallback, between the option and CopyEmptyContent
        const = lu.find("ConstantData")
        ET.SubElement(el, "CopyConstantValue").text = const.text if const is not None else None
    ET.SubElement(el, "CopyEmptyContent",
                  {"value": "False" if lu.get("dontCopyIfEmpty") == "True" else "True"})


def _summary_field_target(parent, fr):
    """Flatten a DDR summary <FieldReference> to its bare clip <Field>, dispatching on the ANCHOR KIND — the
    shared helper the primary SummaryField and the AdditionalField both use so the two paths cannot drift,
    yet the two target forms stay EXPLICIT (packet 1097):
      · a `<TableOccurrenceReference>` anchor → `<Field table="<TO name>" id name/>`;
      · a `<BaseTableReference>` anchor       → `<Field id name/>` (NO table attribute).
    The @table follows the SOURCE ANCHOR, never the operation name. The source UUID and the anchor element
    itself are dropped — the clip resolves the field against the table you paste INTO. Capability guarantees
    exactly one anchor when this runs (_summary_capability)."""
    to = fr.find("TableOccurrenceReference")
    attrs = {}
    if to is not None:
        attrs["table"] = to.get("name")            # ONLY a TO anchor produces @table; leads the attributes
    attrs["id"] = fr.get("id")
    attrs["name"] = fr.get("name")
    return ET.SubElement(parent, "Field", attrs)


def _emit_summary_info(parent, field):
    """<SummaryInfo …> — a Summary field's aggregate definition, and the clip's FIRST child.

    Dialect shifts, none a copy: the DDR's `restartEachGroup` is renamed to `restartForEachSortedGroup`; the
    nested `<SummaryField><FieldReference id name UUID><…Reference/></FieldReference>` FLATTENS to a bare
    `<SummaryField><Field …/></SummaryField>` (UUID + anchor dropped); an optional `<AdditionalField>` (the
    weighted-average / running / fraction second reference, packet 1097) follows the SummaryField and flattens
    the same way — its target @table follows its own source ANCHOR KIND, not the operation; and the block
    leads the element, before <Comment>, where every other field type leads with <Comment>."""
    si = field.find("SummaryInfo")
    if si is None:
        return
    el = ET.SubElement(parent, "SummaryInfo", {
        "restartForEachSortedGroup": si.get("restartEachGroup"),
        "summarizeRepetition": si.get("summarizeRepetition"),
        "operation": si.get("operation")})
    sfe = ET.SubElement(el, "SummaryField")
    _summary_field_target(sfe, si.find("SummaryField/FieldReference"))
    add = si.find("AdditionalField")               # zero or one, AFTER the SummaryField
    if add is not None:
        adde = ET.SubElement(el, "AdditionalField")
        _summary_field_target(adde, add.find("FieldReference"))


def _emit_validation(parent, field):
    """<Validation …flags…> + its children — the full validation HOUSE (packet 1093, from the Scratch1 pair).

    The DDR carries the six switches as ATTRIBUTES and the richer facts as CHILD elements; the clip carries
    the switches as valued child ELEMENTS and hoists five DDR-child facts into top-level FLAGS. Every mapping
    below was read off the stored pair, none is a copy:

      · StrictValidation  = the DDR `allowOverride` INVERTED (the polarity flip this transform is famous for);
      · alwaysValidateCalculation = the DDR `alwaysValidate` attr, verbatim;
      · <Strict>Numeric</Strict>  → <StrictDataType value="Numeric"/>   (element→attribute, value MAPPED via
        _STRICT_DATATYPES — identity for Numeric/FourDigitYear, but DDR `Time` → clip `TimeOfDay`);
      · <MaximumSize>3</MaximumSize> → <MaxDataLength value="3"/> + the maxLength flag;
      · <Range to from/>          → <Range to from/>                    (identity);
      · <Calculated enable><Calculation> → <Calculation table…>text + the calculation flag;
      · <ValueListReference id name/> → the valuelist flag ALWAYS, and a <ValueList id name/> child ONLY when
        the reference is real (id != -1); FileMaker sets valuelist="True" even for the id=-1 "none" reference;
      · ONE DDR <MessageCalc> source FANS OUT to BOTH <ErrorMessage> (the calc text) AND <MessageCalculation>
        (the full <Calculation>), and to BOTH the message + messageCalc flags.

    Target child ORDER is FileMaker's, read off field 22/28: StrictDataType · NotEmpty · Unique · Existing ·
    ValueList · Range · Calculation · MaxDataLength · StrictValidation · ErrorMessage · MessageCalculation.
    An unknown validation value/enum or a disabled calc is refused upstream by _validation_capability, so an
    unaccounted shape never reaches here."""
    from corpusfm.core.clip_emit import _canon_calc
    val = field.find("Validation")
    if val is None:
        return
    strict = val.find("Strict")
    rng = val.find("Range")
    calc = val.find("Calculated")
    msg = val.find("MessageCalc")
    maxsize = val.find("MaximumSize")
    vlref = val.find("ValueListReference")
    calc_on = calc is not None and calc.get("enable") != "False"
    msg_on = msg is not None and msg.get("enable") != "False"
    el = ET.SubElement(parent, "Validation", {
        "messageCalc": "True" if msg_on else "False",
        "message": "True" if msg_on else "False",
        "maxLength": "True" if maxsize is not None else "False",
        "valuelist": "True" if vlref is not None else "False",
        "calculation": "True" if calc_on else "False",
        "alwaysValidateCalculation": val.get("alwaysValidate") or "False",
        "type": val.get("type")})
    if strict is not None:
        # Explicit DDR→XMFD value map (packet 1098), never raw text: DDR `Time` emits clip `TimeOfDay`.
        # _validation_capability has already gated the key, so a stray value is a fail-loud KeyError here.
        ET.SubElement(el, "StrictDataType", {"value": _STRICT_DATATYPES[(strict.text or "").strip()]})
    for ddr_attr, clip_tag in (("notEmpty", "NotEmpty"), ("unique", "Unique"), ("existing", "Existing")):
        ET.SubElement(el, clip_tag, {"value": val.get(ddr_attr) or "False"})
    if vlref is not None and vlref.get("id") != "-1":       # a real value list; id=-1 ("none") emits no child
        ET.SubElement(el, "ValueList", {"id": vlref.get("id"), "name": vlref.get("name")})
    if rng is not None:
        ET.SubElement(el, "Range", {"to": rng.get("to"), "from": rng.get("from")})
    if calc_on:
        _calc_el(el, calc.find("Calculation"))
    if maxsize is not None:
        ET.SubElement(el, "MaxDataLength", {"value": (maxsize.text or "").strip()})
    ET.SubElement(el, "StrictValidation",
                  {"value": "False" if val.get("allowOverride") == "True" else "True"})
    if msg_on:                                              # one DDR source → both clip message structures
        mcalc = msg.find("Calculation")
        ET.SubElement(el, "ErrorMessage").text = _canon_calc(mcalc.findtext("Text") or "") or None
        _calc_el(ET.SubElement(el, "MessageCalculation"), mcalc)


def _emit_storage(parent, field):
    """<Storage …/> — flat in the clip; the DDR nests the index language as a LanguageReference.

    A Calculated field stores `storeCalculationResults` and carries NO index/autoIndex; a Normal field is
    the reverse. Emit only what the DDR actually holds rather than defaulting the absent ones, so the two
    storage dialects stay distinguishable."""
    sto = field.find("Storage")
    if sto is None:
        return
    lang = sto.find("LanguageReference")
    attrs = {}
    for ddr_attr in ("storeCalculationResults", "autoIndex", "index"):
        if sto.get(ddr_attr) is not None:
            attrs[ddr_attr] = sto.get(ddr_attr)
    if lang is not None:
        attrs["indexLanguage"] = _INDEX_LANGUAGE[lang.get("name")]     # per-value remap; Unicode→Unicode_Raw
    attrs["global"] = sto.get("global")
    attrs["maxRepetition"] = sto.get("maxRepetitions")     # NB singular in the clip, plural in the DDR
    st = ET.SubElement(parent, "Storage", attrs)
    _emit_remote(st, sto)                                  # external-container Remote storage (packet 1096)


def _emit_remote(parent, sto):
    """<Remote …/> — external-container storage, appended INSIDE the emitted <Storage> after its attributes.

    Two DIFFERENT structural branches, dispatched on @type (packet 1096, from the stored Scratch1 pair) — not
    one template plus a flag:
      · Secure → `<Remote type="Secure" withFewerFolders relativeToPath relativeTo><Secure/></Remote>`
        (the empty <Secure/> marker appears ONLY in the clip; the DDR has no such child);
      · Open   → `<Remote type="Open" relativeToPath relativeTo><Location><Calculation table…>…</Calculation>
        </Location></Remote>` — NO withFewerFolders, NO <Secure/>, and the path calc through the shared
        _calc_el canonicalizer.

    The base directory is a PROJECTION: DDR `BaseDirectoryReference/@name` → clip `relativeToPath`, its `@id`
    → clip `relativeTo` (a BaseDirectoryCatalog key — NOT the Boolean `absolute`, which is intentionally
    dropped along with the reference UUID). Grammar/cardinality/the absolute bound are enforced upstream by
    _remote_capability, so @type is guaranteed Secure/Open and the required nodes are present when this runs."""
    rem = sto.find("Remote")
    if rem is None:
        return
    bdr = rem.find("BaseDirectoryReference")
    attrs = {"type": rem.get("type")}
    if rem.get("type") == "Secure":
        attrs["withFewerFolders"] = rem.get("withFewerFolders")
    attrs["relativeToPath"] = bdr.get("name")              # from the base-directory NAME
    attrs["relativeTo"] = bdr.get("id")                    # from the base-directory reference ID (catalog key)
    el = ET.SubElement(parent, "Remote", attrs)
    if rem.get("type") == "Secure":
        ET.SubElement(el, "Secure")                        # the empty clip-only marker
    else:                                                  # Open — one <Location> carrying the path calc
        loc = ET.SubElement(el, "Location")
        _calc_el(loc, rem.find("Location/Calculation"))


def _emit_furigana(parent, field):
    """<Furigana inputMode="…"><Field id baseTable name/></Furigana> — a TOP-LEVEL clip field child (packet
    1099), emitted after Storage and before Annotation.

    The DDR nests the target inside a <FieldReference> carrying a <BaseTableReference>; the clip FLATTENS
    that to one <Field id baseTable name/> — id/name from the FieldReference, baseTable from the nested
    BaseTableReference NAME (not the enclosing field/table). Source UUIDs, the base-table id, and the
    observed default repetition are dropped, like every other reference in this dialect. The input mode
    passes through unchanged. _furigana_capability has already proven the mode + the one-FieldReference /
    one-BaseTableReference cardinality, so an unaccounted shape never reaches here."""
    fu = field.find("Furigana")
    if fu is None:
        return
    el = ET.SubElement(parent, "Furigana", {"inputMode": fu.get("inputMode")})
    fr = fu.find("FieldReference")
    btr = fr.find("BaseTableReference")
    ET.SubElement(el, "Field", {"id": fr.get("id"), "baseTable": btr.get("name"), "name": fr.get("name")})


def emit_field(field):
    """One DDR <Field> → its XMFD clip <Field>, or None when the shape is outside the fence.

    Child ORDER is FileMaker's and differs by field type — a Calculated field leads with its
    <Calculation>, BEFORE <Comment>, and carries no <Validation> at all; a Summary field likewise leads
    with its <SummaryInfo> and carries neither <Validation> nor <Storage>; a Normal field leads with
    <Comment>. All three were read off captured pairs, not chosen.

    Gate (packet 1088): emits when the field is CAPABLE — every source feature is accounted for by the
    transform — regardless of whether the exact shape is captured; returns None only when
    field_generation_assessment refuses it (an unmapped value or an unaccounted child/attr). A captured
    shape emits VERIFIED, a capable-but-uncaptured one EXPERIMENTAL, but both emit here."""
    if field_generation_assessment(field).permission == "refuse":
        return None
    f = ET.Element("Field", {"id": field.get("id"), "dataType": _DATATYPE[field.get("datatype")],
                             "fieldType": field.get("fieldtype"), "name": field.get("name")})
    calc = field.find("Calculation")                       # a Calculated FIELD's own formula
    if calc is not None:
        _calc_el(f, calc)
    _emit_summary_info(f, field)                           # a Summary FIELD's aggregate — also pre-Comment
    ET.SubElement(f, "Comment").text = field.get("comment") or None
    _emit_autoenter(f, field)
    _emit_validation(f, field)
    _emit_storage(f, field)
    _emit_furigana(f, field)                               # top-level, after Storage, before Annotation
    ann = ET.SubElement(f, "Annotation")                   # DDR <Annotation/> → clip <Annotation><Text/>
    # The annotation content is the NESTED <Text> child (packet 1101 — field.findtext("Annotation") reads the
    # Annotation element's own text, which is inter-tag whitespace, NOT the nested content). Empty when absent.
    src_ann = field.find("Annotation")
    ann_text = src_ann.findtext("Text") if src_ann is not None else None
    ET.SubElement(ann, "Text").text = ann_text or None
    _emit_displaynames(f, field)                           # last child; carries the display-name calc when on
    return f


def _emit_displaynames(parent, field):
    """<DisplayNames enable="…"/> — the last clip field child; carries a flattened <Calculation> when
    enable="True" (packet 1100, from the stored round-2 pair).

    enable is copied through (bounded {True, False}, identity — proven from the pair, both values observed).
    An enable="True" DisplayNames carries a display-name calc: the DDR nests it as the ordinary
    <Calculation><TableOccurrenceReference/><DDRREF/><Text/></Calculation> wrapper, and the clip FLATTENS it
    the same way every other calc in this dialect is (TO name → @table, Text → canonicalized text, DDRREF
    dropped). _displaynames_capability has already proven the enable value + the enable↔calc coupling, so an
    unaccounted shape never reaches here."""
    dn = field.find("DisplayNames")
    el = ET.SubElement(parent, "DisplayNames", {"enable": dn.get("enable") if dn is not None else "False"})
    calc = dn.find("Calculation") if dn is not None else None
    if calc is not None:
        _calc_el(el, calc)


def emit_field_clip(fields) -> "str | None":
    """A list of DDR <Field>s → one XMFD clip string, or None if ANY field is REFUSED.

    Never a partial clip — that silent-loss failure is the whole point of the guard (packet 1086's
    whole-clip invariant restates it). Under packet 1088 the clip may contain VERIFIED and EXPERIMENTAL
    (capability-complete but uncaptured) fields together — both emit; it is withheld entirely only when
    some field is incapable (an unmapped value or an unaccounted child/attr). The caller
    (export_field_clip) reports each field's evidence state and never omits a field or offers the covered
    subset as if it satisfied the whole-table request."""
    if any(field_generation_assessment(f).permission == "refuse" for f in fields):
        return None
    out = [emit_field(f) for f in fields]
    if any(o is None for o in out):
        return None
    root = ET.Element("fmxmlsnippet", {"type": "FMObjectList"})
    for o in out:
        root.append(o)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


VERIFIED_FIELD_SHAPES = frozenset(_VERIFIED_FIELD_SIGS)


# ── The clip-side vocabulary, for the INCOMING-clip gap analyzer (clip_gap) ────────────────────────────
#
# DERIVED FROM THE LIVE FENCE, never hand-listed. Same law as detect_clip_variations: a hand-maintained
# mirror of what the emitter knows drifts from the emitter, and a drift detector that has itself drifted
# is worse than none. Widen the fence with a capture and these widen for free.
#
# The honesty limit, and it is different from the step-id check's: FileMaker publishes no catalog of field
# vocabulary, so "not in here" can NEVER mean "FileMaker changed" — only "we have no evidence for this".
# Our observed set is partial by construction (2 of FM's 13 summary operations, for instance).

CLIP_DATATYPES = frozenset(_DATATYPE.values())

# Clip-side auto-enter @value modes: the DDR modes the fence has verified, mapped through the same
# remap the emitter uses. '' (no auto-enter), '~' (absent) and the @value-omitting modes never appear.
CLIP_AUTOENTER_MODES = frozenset(
    _AUTOENTER_MODE.get(m, m)
    for m in (_sig_token_value(s, 1, "autoenter:") for s in _VERIFIED_FIELD_SIGS)
    if m and m != "~" and m not in _AUTOENTER_VALUE_OMITTED)

CLIP_SUMMARY_OPERATIONS = frozenset(
    op for op in (_sig_token_value(s, 2, "summary:") for s in _VERIFIED_FIELD_SIGS) if op != "~")

# Element tags emit_field can produce inside a clip <Field>. Guarded by
# tests/test_field_emit.py::test_clip_field_elements_matches_what_the_emitter_actually_emits, which
# fails the build if an emitter starts producing a tag that is not listed here.
CLIP_FIELD_ELEMENTS = frozenset({
    "Calculation", "SummaryInfo", "SummaryField", "Field", "Comment", "AutoEnter", "ConstantData",
    "Serial", "Lookup", "Table", "NoMatchCopyOption", "CopyEmptyContent", "Validation", "NotEmpty",
    "Unique", "Existing", "StrictValidation", "Storage", "Annotation", "Text", "DisplayNames",
    # packet 1093 — the validation-house children _emit_validation can now produce
    "StrictDataType", "ValueList", "Range", "MaxDataLength", "ErrorMessage", "MessageCalculation",
    # packet 1095 — the ConstantData no-match option's fallback child _emit_lookup can now produce
    "CopyConstantValue",
    # packet 1096 — the external-container Remote storage elements _emit_remote can now produce
    "Remote", "Secure", "Location",
    # packet 1097 — the second summary reference _emit_summary_info can now produce
    "AdditionalField",
    # packet 1099 — the top-level Furigana block _emit_furigana can now produce (its nested target is a
    # <Field>, already listed above)
    "Furigana",
})
