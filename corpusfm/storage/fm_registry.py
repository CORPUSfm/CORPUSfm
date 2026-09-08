"""The logical→physical schema map for the generic FM storage substrate.

The FM file (``CORPUSfm_DB``) is now a *frozen generic substrate*: a bank of
identical tables ``TABLE0``–``TABLE39`` (0–9 → 0–14 on 2026-06-20, → 0–39 with the Series 2 file; each =
audit fields + ``JSONOfRecord`` + typed slot banks ``TextField0-39`` /
``Number/Date/Time/TimestampField0-19`` / ``ContainerField0-19``), plus the infra tables
``SETTING`` (also ``ContainerField0-19``) / ``GLOBAL`` /
``CORPUSfm``. The schema declares NOTHING about meaning — this module IS the
meaning. Lose it and the DB is opaque.

Write model — FM-side projection (unified-artifacts §1/§8):
  ``JSONOfRecord`` is the canonical payload and the ONLY data field the app writes
  (plus ``UUID`` on create + container blobs). The app has NO write access to slot
  fields — the FM file's auto-enter CF (``CFM.TOOLS.AutoenterCalculation``) derives
  every indexed slot on commit from the projection map this module generates
  (:func:`generate_setting_calculations`, pushed into ``SETTING`` at startup),
  lowercasing text slots. So ``$filter`` / ``$orderby`` run on a real (lowercased)
  index, while reads parse ``JSONOfRecord`` directly. See ``storage.projections``.

Relationships are NOT in the FM graph (no declared join-table role) — a related row is found by
MATCHING SLOTS at query time, and joins are composed in the backend code, keyed by the slots
declared here.

  ⚠ **This paragraph used to say relationships "are ``$crossjoin`` on slots".** That named a
  mechanism the codebase has never called: as of packet 1210, ``grep -rn crossjoin`` finds only
  prose. The slots are real and load-bearing — every cross-table lookup is a keyed/indexed read on
  one (``get_many`` / ``get_by_keys`` / ``page`` / ``list_where``) — so the *design* stands; the
  *implementation* is composed in Python, not delegated to a server-side join.

  ``$crossjoin`` genuinely exists on this platform and was measured working against fms-dev
  (packet 1210), so this is not a dead end — but it carries three traps that keyed reads do not
  (``$expand`` against an EMPTY table returns HTTP 400 / FM 8309; a cross join cannot be
  ``$count``ed; both sides flatten into one row, so ``UUID``/``JSONOfRecord`` collide and only one
  side's payload can be selected). It earns its first call site when a query needs it, not before.

Conventions:
  * A logical entity maps to exactly one ``TABLEn`` (the ``TABLE`` dict).
  * Only fields the backend ``$filter``/``$orderby``/matches across tables on get a slot
    (slots are scarce, over-provisioned indexes — not a mirror of every key).
  * Adding a queried field = add a slot here (additive) + a one-time backfill of
    historical rows (auto-enter only fills on commit). See storage_migration.
"""
from __future__ import annotations

# Infra tables keep their real names; only entity tables are generic slots.
SETTING_TABLE = "SETTING"
# The generic SQL passthrough: POST {Query: <sql>} → read the unstored `Result` calc
# (= ExecuteSQL(Query)) back in the same response. The generic query engine.
QUERY_TABLE = "QUERY"

# Logical entity → generic table occurrence.
# Packet 085 seven-table model: SETTING (infra) + STORAGE · JOB · QUEUE · TAG · STORAGELINK ·
# HISTORY. TABLE7–TABLE39 are FREE in the final shape.
TABLE: dict[str, str] = {
    "STORAGE":     "TABLE0",   # the catalog — LANDED records only (QUEUE is the workspace)
    "JOB":         "TABLE1",   # automation definitions ("a Job is current")
    "QUEUE":       "TABLE2",   # the single background-work surface (ingestion/enrichment/job-run)
    "TAG":         "TABLE3",   # user tags only, canonical lowercase
    "STORAGELINK": "TABLE4",   # current-state relationships (Type="User Tag": STORAGE↔TAG)
    "HISTORY":     "TABLE5",   # append-only event mentions ("a Run is history")
    "USER":        "TABLE6",   # named accounts + per-user gates + MCP token hashes (packet 1007)
    "SERVER":      "TABLE7",   # remote FMS servers for jobs (packet 1015 — portable; secrets in a container)
    "GITREG":      "TABLE8",   # git-export credentials (packet 1009/S1-B/C — portable; secrets in a container)
    "ALERT":       "TABLE9",   # monitor alert history + suppressions (packet 1019 — portable, travels with the DB)
    "MCPTOKEN":    "TABLE10",  # many named per-user MCP tokens (packet 1029 — portable; secret hash in a container)
    "OAUTH":       "TABLE11",  # browser-login OAuth state (packet 1179 — free-spare claim; Type-discriminated; secret hashes in a container)
    # ── No transitional tables remain: JOBS/ENRICHQUEUE/TAGS/TAGASSIGN retired U2; FILETRACK U3b;
    # ACTIONHISTORY/ACTIONHISTORYLINK/RUNS retired U3c (folded into HISTORY). TABLE12–39 are FREE.
}

# Per logical entity: JSONOfRecord key → (slot field, kind). A field gets a slot ONLY if the
# backend $filter/$orderby/$crossjoins on it (audited 2026-07-03) — everything else lives in
# JSONOfRecord (read on hydrate, never indexed). Slots are contiguous + grouped by purpose. They
# are READ-ONLY to the app (packet 083): FileMaker's auto-enter CF derives every slot from the
# pushed projection map (generated from THIS table) and lowercases text; the app writes only
# JSONOfRecord. Renumbering/adding/dropping a slot is therefore a registry edit that the startup
# assertion re-pushes + re-projects — NO DB migration.
#   text      → str (the CF lowercases every text slot)
#   textlower → str.lower() calc (redundant with the CF's text-lowercasing; kept explicit for the join)
#   bool      → 1/0 (FM exposes the numeric on OData; filter `eq 1`)
#   number    → numeric passthrough
#   textlist  → CR-joined multi-value (FM indexes each line; `eq '<v>'` matches any)
# Projection-map SEMANTIC version (packet 1060) — the single value the agent bumps when EXISTING
# stored data must be reprojected/converted (a re-mapped key, a changed derivation, existing rows
# that must gain a new slot). Do NOT bump it for an ADDITIVE projection (a new slot new records pick
# up via the auto-enter CF): the map is rewritten automatically on any change, but only a version
# bump induces the file-wide sweep (CFM.SRV.RefreshIndexProjections). Distinct from the physical-
# schema `Build` (storage_migration) — this axis is backfill-able live and must never bump `Build`
# or require a fresh install.
# NOT BUMPED BY PACKET 1361-01, and the reason is the point of this note. That packet retires the
# `IsLatest` flag, so STORAGE.NumberField0 simply stops being projected — a REMOVED slot needs no
# sweep, because nothing queries it and the stale values it leaves behind are read by nothing. An
# interim revision of the packet repurposed that slot for an `IsValidJSON` projection and bumped this
# to 3 to re-derive it; the persistent catalog reads all three tables UNFILTERED, so the escape hatch
# that projection existed to provide is unnecessary and both it and the bump are gone. The "Latest
# Artifact" promotion link needs no seam either: it is minted by a startup conversion that runs
# unconditionally (`server.latest.convert_and_repair`), and its `UUIDJob` lives in the record's
# JSONOfRecord, which the catalog reads directly — no indexed slot, nothing to project, nothing to
# query. Do not bump this axis for a projection nothing reads.
# 1 → 2 (packet 1372-01): the JOB IDENTITY CONVERSION. This is the "existing stored data must be
# converted" signal doing exactly the job it was defined for. The calculation map is UNCHANGED —
# nothing about the projection itself moved — but every JOB record must be re-keyed so its native
# record key, its `JobConfig.id` and the `UUIDJob` its artifacts/history/queue rows already carry are
# one value. `projections.assert_projection` runs that conversion at the version-transition seam and
# stamps 2 only after it and the incumbent refresh both succeed. Neither `Build` nor
# `db_schema_build.txt` moves: this is not a fresh-database requirement.
PROJECTION_VERSION: int = 2

SLOTS: dict[str, dict[str, tuple[str, str]]] = {
    # STORAGE (the catalog) — classification → identity → linkage → matching → order → search → flags.
    "STORAGE": {
        "Type":              ("TextField0",  "text"),   # the visibility fence (isin VISIBLE) + facets + capability
        "PrimaryName":       ("TextField1",  "text"),   # search · alias resolution (editable human identity)
        "FileName":          ("TextField2",  "text"),   # xref/alias resolution · search (from root File=, repair-editable)
        "Origin":            ("TextField3",  "text"),   # eq facets, picker buckets
        "UUIDJob":           ("TextField4",  "text"),   # eq derived job-latest + runs-present-set
        "RootUUID":          ("TextField6",  "text"),   # eq Related (same file) FILTER only — NOT lineage/IsLatest (that's UUIDJob, 086/Ruling A)
        "ArtifactTimestamp": ("TextField7",  "text"),   # PRIMARY orderby
        "Description":       ("TextField8",  "text"),   # contains() search
        "Memory":            ("TextField9",  "text"),   # contains() search
        # NumberField0 is DELIBERATELY UNPROJECTED (packet 1361-01). It carried `IsLatest`, and
        # "which artifact of this lineage is current" is now a STORAGELINK relationship, not a
        # per-record boolean. Nothing queries the slot, so nothing re-derives it.
        "HasSummaries":      ("NumberField1", "bool"),  # eq 1 enrichment facet (blob cohabits the record)
        # JSONOfRecord-only (no slot — never queried): analyzer_failed · gap_* · provenance ·
        # icon_b64 · FMVersion/schema_version · has_name_map/has_source.
    },
    "JOB": {
        "Name":     ("TextField0", "text"),             # eq job lookup by name (case-stable in jor)
        "FileName": ("TextField1", "text"),             # eq run mutual exclusion + "other jobs on this file"
    },
    # QUEUE — one laundry-list record per unit of work (packet 086). Type is the cursor/worker step:
    # upload · pull · land · summarize · index · git_export · verify (a Job Run is a single [pull]
    # trip). Non-failed rows are short-lived; failed rows are durable (IsFailed=1) until a human
    # Restarts/Deletes.
    "QUEUE": {
        "Type":          ("TextField0", "text"),        # eq worker scans (the step cursor)
        "UUIDJob":       ("TextField1", "text"),        # eq "is this job running?" (pull records)
        "UUIDStorage":   ("TextField2", "text"),        # eq landing crash-heal + enrichment target
        "PushTokenHash": ("TextField3", "text"),        # eq push-token resolution (packet 1015 — sha256 of
                                                        #    the one-time fms_push token; the HASH, never the
                                                        #    raw token, so it is a safe indexed lookup key)
        "IsFailed":      ("NumberField0", "bool"),      # eq failed-row surface
    },
    # Tag join keys — the STORAGE↔STORAGELINK↔TAG tag-filter join runs server-side via the QUERY
    # engine on these. TAG.Name is lowercased so the join is an index-friendly exact match.
    "TAG": {
        "Name": ("TextField0", "textlower"),
    },
    "STORAGELINK": {
        "Type":        ("TextField0", "text"),          # link vocabulary ("User Tag" · "Latest Artifact")
        "UUIDStorage": ("TextField1", "text"),
        "UUIDTag":     ("TextField2", "text"),
        # A promotion link's `UUIDJob` rides in its JSONOfRecord and is read from there by the
        # catalog and by the startup repair. It gets NO slot: no query narrows on it (the promotion
        # is addressed by its deterministic record key), and an unqueried projection is a calculation
        # to maintain for nobody (packet 1361-01).
    },
    # HISTORY — append-only event mentions; display facts snapshotted into jor so deleted
    # JOB/STORAGE rows never break rendering. Age nothing.
    "HISTORY": {
        "Type":               ("TextField0", "text"),   # eq event scans
        "Timestamp":          ("TextField1", "text"),   # orderby recent
        "UUIDStorage":        ("TextField2", "text"),   # eq per-artifact history
        "UUIDRelatedStorage": ("TextField3", "text"),   # eq counterpart lookup
        "UUIDJob":            ("TextField4", "text"),   # eq per-job run history
        "ParentRootUUID":     ("TextField6", "text"),   # eq Related reverse lookup
    },
    # USER (packet 1007) — named accounts. Only NON-secret lookup keys are indexed slots; the sensitive
    # material (PBKDF2 hash+salt, MCP token-secret hash) rides the Corpus-Key-encrypted SecretData container,
    # never jor (the table-wide secret fence enforces this). Username is the case-insensitive login key;
    # TokenId is the non-secret half of a `<token_id>.<secret>` MCP token → one indexed lookup per
    # request instead of an iterate-and-decrypt over every user.
    "USER": {
        "Username": ("TextField0", "text"),             # eq login lookup (CF lowercases → case-insensitive)
        "TokenId":  ("TextField1", "text"),             # eq bearer-token lookup (non-secret token half)
        "IsActive": ("NumberField0", "bool"),           # eq active-user filter
    },
    # GITREG (packet 1009/S1-B/C) — git-export credentials. Each row is keyed by a uuid4 (like every
    # other table, so key-addressed FM OData ops resolve); the credential NAME is the indexed lookup
    # slot (get_one by name). The json_key is the lowercase ``name`` — it must match the jor key the
    # app writes (RegistrationConfig.name via asdict). The SECRETS (token_enc / ssh_key_enc) ride the
    # Corpus-Key-encrypted SecretData container, never jor (the table-wide secret fence).
    "GITREG": {
        "name": ("TextField0", "text"),
    },
    # SERVER (packet 1015) — remote FMS servers a Job can target. Keyed by a uuid4 (like every table);
    # the display NAME is the indexed lookup slot (get_one by name, GITREG-parity). The fmsadmin
    # PASSWORD rides the Corpus-Key-encrypted SecretData container, never jor (the table-wide secret fence).
    # IsEnabled is a reserved slot (kept for DB-build compatibility; unused since the 2026-07-08
    # redesign dropped the per-server enable/disable — delete a server to remove it).
    "SERVER": {
        "name":      ("TextField0", "text"),
        "IsEnabled": ("NumberField0", "bool"),
    },
    # ALERT (packet 1019) — the monitor's alert history + suppressions, one table (Type discriminates:
    # "event" rows are the append-only history; "suppress" rows are per-key acknowledgements with an
    # `until` in jor). Moved off the local monitor/ files so alert state travels with the DB like every
    # other operational table. Keyed by a uuid4; no container (plain jor, no secrets).
    "ALERT": {
        "Type":        ("TextField0", "text"),   # "event" | "suppress"
        "Timestamp":   ("TextField1", "text"),   # event orderby (newest-first)
        "SuppressKey": ("TextField2", "text"),   # suppress lookup: "<condition>:<job uuid>" (1149)
    },
    # MCPTOKEN (packet 1029) — many named per-user MCP tokens. Keyed by a uuid4 (like every table).
    # Only NON-secret lookup keys are indexed slots: TokenId (the non-secret half of a
    # `<token_id>.<secret>` bearer token → one indexed resolve per request) and Owner (the user id →
    # one indexed "list my tokens"). The token-SECRET hash rides the Corpus-Key-encrypted SecretData
    # container, never jor (the table-wide secret fence). Name + created ride jor.
    "MCPTOKEN": {
        "TokenId": ("TextField0", "text"),   # eq bearer-token resolve (non-secret token half)
        "Owner":   ("TextField1", "text"),   # eq "list this user's tokens"
    },
    # OAUTH (packet 1179) — browser-login OAuth state, ONE Type-discriminated table (free spare TABLE11).
    # Records: Type ∈ {client, txn, code, token, consent}. Every credential lookup is indexed + shape-
    # dispatched: `Handle` is the NON-SECRET lookup half (client_id for a client; the opaque handle for a
    # txn/code/token); the SECRET half's SHA-256 rides the Corpus Key SecretData container, never jor. Subject/
    # ClientId index consent lookups (subject+client) + "this user's tokens". Flags live in jor and are
    # enforced in code (fail-closed). ExpiresAt is an INDEXED numeric slot (packet 1179 review §6) so the
    # bounded cleanup sweep can order ephemeral records OLDEST-EXPIRY-FIRST — the expired rows sort into
    # the first bounded page and are reached rather than starved behind newer active records.
    "OAUTH": {
        "Type":      ("TextField0", "text"),    # eq discriminator (client|txn|code|token|consent)
        "Handle":    ("TextField1", "text"),    # eq the non-secret lookup half (ONE indexed resolve per credential)
        "Subject":   ("TextField2", "text"),    # eq consent lookup + owner-scoped token cleanup
        "ClientId":  ("TextField3", "text"),    # eq consent lookup (subject+client) + client-scoped cleanup
        "ExpiresAt": ("NumberField0", "number"),  # orderby oldest-first for the bounded expiry sweep (review §6)
    },
}

# Logical container-field name → generic ContainerFieldN, per logical entity.
# Containers never ride ordinary reads — touched only by explicit blob ops.
CONTAINERS: dict[str, dict[str, str]] = {
    "STORAGE": {
        "ArtifactData": "ContainerField0",
        "NameMapData":  "ContainerField1",
        "SourceXML":    "ContainerField2",
        "SummariesData": "ContainerField3",   # gzip(json) AI summaries blob
    },
    "JOB": {
        "CredentialData": "ContainerField0",  # Fernet(box-key) per-job file credential — read only at run time
    },
    "QUEUE": {
        "SourceXML": "ContainerField0",       # staged source blob on Artifact Ingestion rows (the workspace)
    },
    "SETTING": {
        "SealData":     "ContainerField0",    # INERT — retired seal container (packet 1246-02); the
                                              # FileMaker file is frozen, so the field stays and nothing writes it
        "AiKeys":       "ContainerField1",    # Corpus-Key-encrypted AI provider secrets blob (packet 1007)
        "NotifySecret": "ContainerField2",    # Corpus-Key-encrypted SMTP password (monitor config, packet 1009)
        "OidcSecret":   "ContainerField3",    # Corpus-Key-encrypted external-auth secrets — OIDC client_secret + LDAP bind pw (packet 1065)
        # CF4–CF9 spare (SETTING widened to 10 containers for headroom, packet 1007)
    },
    "USER": {
        "SecretData": "ContainerField0",      # Corpus-Key-encrypted {password_hash, mcp_token_secret_hash}
    },
    "GITREG": {
        "SecretData": "ContainerField0",      # Corpus-Key-encrypted {token_enc, ssh_key_enc} (packet 1009/S1-B/C)
    },
    "SERVER": {
        "SecretData": "ContainerField0",      # Corpus-Key-encrypted {password} — the fmsadmin Admin-API password (packet 1015)
    },
    "MCPTOKEN": {
        "SecretData": "ContainerField0",      # Corpus-Key-encrypted {token_secret_hash} (packet 1029)
    },
    "OAUTH": {
        "SecretData": "ContainerField0",      # Corpus-Key-encrypted {secret_hash} for code/token credentials (packet 1179)
    },
}


def table(logical: str) -> str:
    """Physical table occurrence for a logical entity (e.g. 'STORAGE' → 'TABLE0')."""
    try:
        return TABLE[logical]
    except KeyError:
        raise KeyError(f"No generic-table mapping for logical entity {logical!r}") from None


def slot(logical: str, json_key: str) -> str:
    """Slot field backing a queried logical field (e.g. ('STORAGE','Type') → 'TextField0').

    Raises KeyError if the field isn't projected into a slot — a guard against
    silently building a $filter/$orderby on an unindexed (and on the generic
    schema, non-existent) named field.
    """
    try:
        return SLOTS[logical][json_key][0]
    except KeyError:
        raise KeyError(
            f"{logical}.{json_key} has no slot — add it to fm_registry.SLOTS "
            f"(and backfill) before filtering/sorting on it."
        ) from None


def container_field(logical: str, name: str) -> str:
    """Physical container slot for a logical container name (e.g.
    ('STORAGE','ArtifactData') → 'ContainerField0'). An unmapped name (already a
    physical ContainerFieldN, or an unknown table) passes through unchanged.
    """
    return CONTAINERS.get(logical, {}).get(name, name)


# ── FM-side projection: generate the SETTING.Calculations map (unified-artifacts §1) ──
# CORPUSfm_DB's auto-enter CF (CFM.TOOLS.AutoenterCalculation) re-derives each slot on commit
# from a per-field calc string stored in SETTING.JSONOfRecord under
# "Calculations.<table>.<fieldType>.<field>". "No calculation, no overwrite" — an unmapped field
# keeps what was written (Self). Generating this map from SLOTS keeps the registry the single
# source of truth. Pushing it to SETTING + retiring app-side project_slots is a LIVE-VERIFIED
# step (the bool coercion must be confirmed against the actual JSONOfRecord representation).

_FM_FIELD_TYPE = (
    ("TextField", "Text"), ("NumberField", "Number"), ("DateField", "Date"),
    ("TimestampField", "Timestamp"), ("TimeField", "Time"), ("ContainerField", "Container"),
)


def _fm_field_type(field: str) -> str:
    for prefix, word in _FM_FIELD_TYPE:
        if field.startswith(prefix):
            return word
    return "Text"


def _projection_calc(tbl: str, json_key: str, kind: str) -> str:
    """The FM calc string that re-derives a slot from this record's JSONOfRecord.

    References are UNQUALIFIED (same-record field names, no ``TO::`` prefix) — box-proven
    2026-07-04: a TO-qualified reference resolves through the relationship graph, whose
    ``!CartesianConnector`` match field is NoAccess to the automation account, so the CF's
    Evaluate errored ('?' slots + FM-202 on every create). Unqualified names resolve in the
    record's own context, no graph walk. No explicit ``Lower()`` either — the CF's Text
    branch already lowercases every text slot (an explicit one double-lowers TAGS.Name)."""
    get = f'JSONGetElement ( JSONOfRecord ; "{json_key}" )'
    if kind == "textlist":
        return f'JSONListValues ( JSONOfRecord ; "{json_key}" )'
    if kind == "textlower":
        return get
    if kind == "bool":
        return f'If ( {get} = "true" or {get} = 1 ; 1 ; 0 )'
    if kind == "number":
        return f'GetAsNumber ( {get} )'
    return get


def generate_setting_calculations() -> dict:
    """The SETTING.Calculations projection map, generated from SLOTS (the single source).

    Shape: {"Calculations": {<table>: {<fieldType>: {<field>: <calc string>}}}}.
    """
    calcs: dict = {}
    for logical, slots in SLOTS.items():
        tbl = TABLE[logical]
        for json_key, (field, kind) in slots.items():
            ftype = _fm_field_type(field)
            calcs.setdefault(tbl, {}).setdefault(ftype, {})[field] = _projection_calc(tbl, json_key, kind)
    return {"Calculations": calcs}
