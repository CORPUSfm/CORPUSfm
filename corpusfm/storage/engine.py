"""StorageEngine — the substrate vocabulary (the one place that speaks OData / files).

The remaster's bottom layer. Repositories (entity logic,
backend-agnostic) call these primitives; the engine turns them into indexed OData (:class:`FMEngine`)
or file reads (:class:`LocalEngine`). Reads are keyed/indexed by default; ``sql()`` is the marked
escape hatch used only for key-resolution joins.

Records are raw: :class:`Row` (uuid + parsed JSONOfRecord). Repos hydrate Rows into shaped views.
Filters are expressed **semantically** — ``{json_key: value}`` — and the engine resolves each key to
its indexed slot via ``fm_registry`` and builds the OData, so callers never write OData/SQL. A key
with no slot raises (``reg.slot``) — a guard against a silent full-table filter.

During the migration :class:`FMEngine` delegates transport (session/url/containers/query) to the
existing ``FileMakerODataBackend``; the fat backend folds into the engine once callers are on repos.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol
from urllib.parse import quote as _quote

from corpusfm.storage import fm_registry as reg


# A runaway guard for list_all's nextLink loop, not a page budget: at any plausible FM page size
# this is far more rows than a table list_all should ever be pointed at.
_LIST_ALL_MAX_PAGES = 500


@dataclass(frozen=True)
class Row:
    """One raw record: its opaque backend key (FM = record UUID, SQLite = row uuid) + the parsed
    JSONOfRecord dict (never a blob). Repos address records by ``key`` without knowing which it is."""
    key: str
    jor: dict


class StorageEngine(Protocol):
    """The substrate vocabulary both engines implement. Repos depend on THIS, never on a backend.
    Reads are keyed/indexed by default; an unindexed filter key raises; blobs are opt-in; ``sql()``
    is the marked escape hatch (key-resolution / aggregates)."""
    def get_one(self, logical: str, **eq) -> Optional[Row]: ...
    def get_many(self, logical: str, key: str, values: list) -> list[Row]: ...
    def get_by_keys(self, logical: str, keys: list) -> list[Row]: ...
    def page(self, logical: str, *, eq: Optional[dict] = None, ne: Optional[dict] = None,
             isin: Optional[dict] = None, contains: Optional[dict] = None,
             exclude: Optional[dict] = None,
             orderby: Optional[str] = None, desc: bool = True,
             page: int = 1, per_page: int = 25, count: bool = False) -> tuple[list[Row], int]: ...
    def list_all(self, logical: str) -> list[Row]: ...
    def list_where(self, logical: str, *, eq: Optional[dict] = None, ne: Optional[dict] = None,
                   isin: Optional[dict] = None) -> list[Row]: ...
    def create(self, logical: str, key: str, jor: dict) -> None: ...
    def update(self, logical: str, key: str, jor: dict) -> None: ...
    def delete(self, logical: str, key: str) -> None: ...
    def blob_get(self, logical: str, key: str, field: str) -> Optional[bytes]: ...
    def blob_put(self, logical: str, key: str, field: str, data: bytes) -> None: ...
    def blob_delete(self, logical: str, key: str, field: str) -> None: ...
    def blob_exists(self, logical: str, key: str, field: str) -> Optional[bool]: ...
    def sql(self, query: str, *, columns: bool = False) -> list: ...
    def phys(self, logical: str) -> str: ...
    def sql_page_clause(self, skip: int, top: int) -> str: ...


def _slot_kind(logical: str, key: str) -> str:
    return reg.SLOTS.get(logical, {}).get(key, ("", "text"))[1]


def _clause(logical: str, key: str, value, op: str = "eq") -> str:
    """One indexed `<slot> <op> <value>` clause. Text comparands are LOWERCASED to match the
    CF-lowercased slot value — FM's `eq`/`ne` are case-sensitive (FQL semantics, box-proven
    2026-07-04), so a mixed-case literal silently matches nothing (and `ne` over-matches).
    Mirrors SqliteEngine._bind. Bool/number are bare numerics. Raises via reg.slot if the key
    isn't indexed."""
    slot = reg.slot(logical, key)
    kind = _slot_kind(logical, key)
    if kind in ("bool", "number"):
        v = (1 if value in (True, 1, "1", "true") else 0) if kind == "bool" else value
        return f"{slot} {op} {v}"
    return f"{slot} {op} '{str(value).lower().replace(chr(39), chr(39) * 2)}'"


def _and(clauses: list) -> str:
    return " and ".join(c for c in clauses if c)


class FMEngine:
    """StorageEngine over FileMaker OData. Entity-agnostic; the registry supplies the physical table
    and the indexed slots. All reads select ``UUID,JSONOfRecord`` (never the slow RecordAsJSON calc,
    never a blob)."""

    def __init__(self, backend):
        self._b = backend

    # -- URL / execution (delegated to the backend during migration) ----------
    def _url(self, logical: str, key: Optional[str] = None) -> str:
        phys = self._b._phys(logical)
        return self._b._url(f"{phys}('{key}')" if key else phys)

    @staticmethod
    def _rows(payload: dict) -> list:
        from corpusfm.storage.fm_odata import _parse_jor
        out = []
        for rec in payload.get("value", []):
            key, jor = _parse_jor(rec)
            out.append(Row(key, jor))
        return out

    def _get(self, logical: str, query: str) -> dict:
        resp = self._b._session.get(self._b._url(self._b._phys(logical)) + "?" + query)
        resp.raise_for_status()
        return resp.json()

    # -- reads (keyed / indexed by default) -----------------------------------
    def get_one(self, logical: str, **eq) -> Optional[Row]:
        """The single record matching all `eq` slot clauses (indexed, top-1), or None."""
        flt = _and([_clause(logical, k, v) for k, v in eq.items()])
        q = "$select=UUID,JSONOfRecord&$top=1" + (f"&$filter={_quote(flt, safe=chr(39))}" if flt else "")
        rows = self._rows(self._get(logical, q))
        return rows[0] if rows else None

    def get_many(self, logical: str, key: str, values: list) -> list[Row]:
        """Hydrate every record whose `key` slot is in `values` — ONE `or`-filter GET (order not
        guaranteed). Empty `values` → no call."""
        vals = [v for v in dict.fromkeys(values) if v]
        if not vals:
            return []
        ors = " or ".join(_clause(logical, key, v) for v in vals)
        q = f"$select=UUID,JSONOfRecord&$filter={_quote(ors, safe=chr(39))}"
        return self._rows(self._get(logical, q))

    def get_by_keys(self, logical: str, keys: list) -> list[Row]:
        """Hydrate records by their NATIVE record key (the UUID column — always queryable,
        no registry slot needed) — ONE `or`-filter GET. Empty `keys` → no call."""
        vals = [k for k in dict.fromkeys(keys) if k]
        if not vals:
            return []
        ors = " or ".join(f"UUID eq '{str(k).replace(chr(39), chr(39) * 2)}'" for k in vals)
        q = f"$select=UUID,JSONOfRecord&$filter={_quote(ors, safe=chr(39))}"
        return self._rows(self._get(logical, q))

    def page(self, logical: str, *, eq: Optional[dict] = None, ne: Optional[dict] = None,
             isin: Optional[dict] = None, contains: Optional[dict] = None,
             exclude: Optional[dict] = None,
             orderby: Optional[str] = None, desc: bool = True,
             page: int = 1, per_page: int = 25, count: bool = False) -> tuple[list[Row], int]:
        """A bounded, indexed page. `eq`/`ne` are `{json_key: value}` slot clauses; `isin` is
        `{json_key: [values]}` — an OR-eq group per key, AND-ed with the rest (the Type visibility
        fence); `contains` is `{json_key: needle}` case-insensitive substring (OR-ed across keys,
        AND-ed with the rest); `exclude` is a NEGATED conjunction — the one record matching ALL its
        `{json_key: value}` pairs is dropped (the picker's "not the artifact being compared");
        `orderby` is a json_key. Returns (rows, total) — total is -1 unless `count`."""
        per_page = max(1, min(int(per_page or 25), 200))
        skip = (max(1, int(page or 1)) - 1) * per_page
        clauses: list = []
        clauses += [_clause(logical, k, v) for k, v in (eq or {}).items()]
        clauses += [_clause(logical, k, v, op="ne") for k, v in (ne or {}).items()]
        for k, vals in (isin or {}).items():
            vs = [v for v in dict.fromkeys(vals) if v]
            if vs:
                clauses.append("(" + " or ".join(_clause(logical, k, v) for v in vs) + ")")
        if exclude:
            clauses.append("not (" + _and([_clause(logical, k, v) for k, v in exclude.items()]) + ")")
        if contains:
            needle = str(next(iter(contains.values()))).lower().replace("'", "''")
            ors = " or ".join(f"contains(tolower({reg.slot(logical, k)}),'{needle}')" for k in contains)
            clauses.append(f"({ors})")
        parts = ["$select=UUID,JSONOfRecord", f"$top={per_page}", f"$skip={skip}"]
        if count:
            parts.append("$count=true")
        if orderby:
            parts.append(f"$orderby={reg.slot(logical, orderby)} {'desc' if desc else 'asc'}")
        if clauses:
            # FM Server wants the comma inside contains() literal, not %2C — keep ( ) , ' literal.
            parts.append("$filter=" + _quote(_and(clauses), safe="(),'"))
        payload = self._get(logical, "&".join(parts).replace(" ", "%20"))
        # -1 means "count not requested / key absent (unknown)"; a genuine 0 must stay 0 (the old
        # `... or -1` collapsed a real empty count to -1 → a "-1" failed badge + a wrong drain count).
        total = -1
        if count:
            c = payload.get("@odata.count", payload.get("@count", None))
            total = int(c) if c is not None else -1
        return self._rows(payload), total

    def _follow(self, logical: str, query: str, *, what: str) -> list[Row]:
        """Run an UNBOUNDED read and FOLLOW ``@odata.nextLink`` to exhaustion.

        The request carries no ``$top``, so the page size is the SERVER's choice, and reading only
        ``payload["value"]`` returns whatever the server decided to send first while the caller
        believes it has everything. Under an unpaged server the loop runs exactly once and nothing
        changes; under a paging one it stops the read silently lying.

        ``nextLink`` is a SERVER-maintained cursor, which is why exhaustive reads follow it instead
        of doing ``$skip`` arithmetic: client-computed paging over a table being written to can skip
        or repeat rows between pages, and an exhaustive read is exactly where that is least
        acceptable.

        The cap is a runaway guard, not a page budget: it bounds a server that returns a nextLink
        forever. Hitting it RAISES rather than returning a short list, because a truncated result
        that looks complete is the failure being guarded against."""
        payload = self._get(logical, query)
        rows = self._rows(payload)
        for _ in range(_LIST_ALL_MAX_PAGES):
            nxt = payload.get("@odata.nextLink") or payload.get("@nextLink")
            if not nxt:
                return rows
            resp = self._b._session.get(nxt)
            resp.raise_for_status()
            payload = resp.json()
            rows += self._rows(payload)
        raise RuntimeError(
            f"{what}({logical!r}) followed {_LIST_ALL_MAX_PAGES} pages without exhausting the "
            "table. Use a bounded paged read (page(...)) for a table this size.")

    def list_all(self, logical: str) -> list[Row]:
        """Every record of a (small) table. Discouraged — prefer get_one/get_many/page/list_where;
        here for the tiny tables the registry doesn't slot."""
        return self._follow(logical, "$select=UUID,JSONOfRecord", what="list_all")

    def list_where(self, logical: str, *, eq: Optional[dict] = None, ne: Optional[dict] = None,
                   isin: Optional[dict] = None) -> list[Row]:
        """Every record MATCHING an indexed filter — ``list_all``'s exhaustive contract with the
        predicate moved to the SERVER. Same semantic ``{json_key: value}`` clauses as ``page()``;
        an unindexed key raises via ``reg.slot``.

        This is the honest primitive for a read that genuinely needs every matching row (a fold over
        one whole relationship, the catalog's visibility fence). ``page()`` cannot serve it — a
        caller wanting *all* matches would have to loop ``$skip`` and choose a page size, and would
        inherit the cross-page instability ``_follow`` exists to avoid. The alternative it replaces
        is worse than either: pull the table and discard most of it in Python.

        ``isin`` with an EMPTY value list means **matches nothing** and returns ``[]`` without a
        request. That deliberately differs from ``page()``, which drops an empty ``isin`` and so
        widens the query — tolerable for a bounded page, silently catastrophic for an exhaustive
        read, where "no constraint" is the whole table.

        Individual EMPTY VALUES inside an ``isin`` group are dropped, matching ``page()`` and
        ``get_many``. Load-bearing rather than incidental: the catalog's visibility fence is
        ``isin={"Type": VISIBLE_TYPES}``, and a mid-landing row carries an empty ``Type`` — so the
        row that must never be visible cannot be asked for even if a caller passes ``""`` as a
        wanted value (asserted by
        ``test_a_type_less_row_is_excluded_by_the_query_as_well_as_the_python_fence``)."""
        clauses: list = []
        clauses += [_clause(logical, k, v) for k, v in (eq or {}).items()]
        clauses += [_clause(logical, k, v, op="ne") for k, v in (ne or {}).items()]
        for k, vals in (isin or {}).items():
            vs = [v for v in dict.fromkeys(vals) if v]
            if not vs:
                return []
            clauses.append("(" + " or ".join(_clause(logical, k, v) for v in vs) + ")")
        parts = ["$select=UUID,JSONOfRecord"]
        if clauses:
            parts.append("$filter=" + _quote(_and(clauses), safe="(),'"))
        return self._follow(logical, "&".join(parts).replace(" ", "%20"), what="list_where")

    # -- writes (JSONOfRecord + key only; slots are FM-derived) ----------------
    def create(self, logical: str, key: str, jor: dict) -> None:
        self._b._post_json(self._url(logical), self._b._jor_payload(logical, jor, record_uuid=key)
                           ).raise_for_status()

    def update(self, logical: str, key: str, jor: dict) -> None:
        self._b._patch_json(self._url(logical, key), self._b._jor_payload(logical, jor)
                           ).raise_for_status()

    def delete(self, logical: str, key: str) -> None:
        self._b._session.delete(self._url(logical, key)).raise_for_status()

    # -- blobs (explicit, opt-in) ---------------------------------------------
    def blob_get(self, logical: str, key: str, field: str) -> Optional[bytes]:
        return self._b._download_container(key, field, table=logical)

    def blob_put(self, logical: str, key: str, field: str, data: bytes) -> None:
        self._b._upload_container(key, field, data, table=logical)

    def blob_delete(self, logical: str, key: str, field: str) -> None:
        # Clear the container blob WITHOUT deleting the record. FileMaker OData treats
        # ``DELETE .../Table('key')/Field/$value`` as deleting the whole RECORD (box-verified —
        # it removed the row, not just the container), so an empty PATCH of the container property
        # is used instead: it empties the blob and keeps the row (matches SqliteEngine.blob_delete,
        # which deletes only the _blobs entry). A DELETE here silently destroyed records — e.g.
        # clearing a Job's credential deleted the whole Job.
        cfield = reg.container_field(logical, field)
        self._b._session.patch(
            self._b._url(f"{self._b._phys(logical)}('{key}')/{cfield}"),
            data=b"",
            headers={"Content-Type": "application/octet-stream",
                     "Content-Disposition": 'attachment; filename="empty.bin"'},
        ).raise_for_status()

    def blob_exists(self, logical: str, key: str, field: str) -> Optional[bool]:
        """Cheap non-empty check WITHOUT downloading the blob: a streamed GET reads exactly one
        byte then closes (Range asked for politely, but a 200-with-full-body still costs one
        byte + a dropped connection). Returns None when the answer is uncertain — callers must
        never treat uncertainty as absence."""
        cfield = reg.container_field(logical, field)
        url = self._b._url(f"{self._b._phys(logical)}('{key}')/{cfield}/$value")
        resp = None
        try:
            resp = self._b._session.get(url, headers={"Range": "bytes=0-0"}, stream=True)
            if resp.status_code == 404:
                return False
            if resp.status_code in (200, 206):
                return bool(next(resp.iter_content(1), b""))
            return None
        except Exception:
            return None
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass

    # -- special: ExecuteSQL, key-resolution only -----------------------------
    def sql(self, query: str, *, columns: bool = False) -> list:
        return self._b.query(query, columns=columns)

    def phys(self, logical: str) -> str:
        """Table name as ``sql()`` addresses it (FM SQL speaks the physical TABLEn names)."""
        return self._b._phys(logical)

    @staticmethod
    def sql_page_clause(skip: int, top: int) -> str:
        """FM SQL paging (no LIMIT keyword) — the one dialect divergence repos must ask for."""
        return f"OFFSET {int(skip)} ROWS FETCH FIRST {int(top)} ROWS ONLY"


# ── SqliteEngine — the local StorageEngine (uniform relational model) ─────────────
# Mirrors the FM substrate in SQLite: one table per logical entity (uuid PK + jor TEXT + the
# registry's indexed slots as GENERATED columns that reproduce the FM projection CF — text
# lowercased, bool 1/0, number passthrough — so projection is defined ONCE, in fm_registry, and
# honored identically on both backends). Blobs live in a _blobs(uuid, field, data) table. Fresh
# install / no migration: a store is created from the CURRENT registry, always in sync.
import json as _json
import sqlite3 as _sqlite3
import threading as _threading
import uuid as _uuidlib


def _sqlite_slot_type(kind: str) -> str:
    return "INTEGER" if kind == "bool" else ("NUMERIC" if kind == "number" else "TEXT")


def _sqlite_slot_expr(kind: str, json_key: str) -> str:
    """The GENERATED-column expression reproducing fm_registry's projection for this slot."""
    get = f"json_extract(jor, '$.{json_key}')"
    if kind == "bool":
        return f"CASE WHEN {get} IN (1, '1', 'true') THEN 1 ELSE 0 END"
    if kind == "number":
        return get
    return f"lower({get})"   # text / textlower / textlist — the CF lowercases all text slots


class SqliteEngine:
    """StorageEngine over SQLite. Same primitive vocabulary as FMEngine, built as parameterized SQL;
    ``sql()`` is native. Thread-safe via a single WAL connection behind a lock (dev/test scale)."""

    def __init__(self, path):
        self._conn = _sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = _sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        # Separate LocalBackend instances (one per get_backend() call) each hold their own
        # connection to the same store — wait out a writer instead of raising "database is locked".
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._lock = _threading.RLock()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._lock:
            for logical in reg.TABLE:
                cols = ["uuid TEXT PRIMARY KEY", "jor TEXT NOT NULL"]
                for json_key, (slot, kind) in reg.SLOTS.get(logical, {}).items():
                    cols.append(f"{slot} {_sqlite_slot_type(kind)} "
                                f"GENERATED ALWAYS AS ({_sqlite_slot_expr(kind, json_key)}) STORED")
                self._conn.execute(f"CREATE TABLE IF NOT EXISTS {logical} ({', '.join(cols)})")
                # Reconcile a slot ADDED to an existing dev/test DB (e.g. QUEUE.PushTokenHash, packet
                # 1015). CREATE TABLE IF NOT EXISTS never alters an existing table, so a pre-existing DB
                # would lack the new column and its index build would hard-crash startup. A STORED
                # generated column can't be ALTER-added in SQLite, but a VIRTUAL one can — and is still
                # indexable — so back-fill the missing slot as VIRTUAL (computed on read, data-preserving)
                # while fresh tables keep STORED. Prod (FM backend) is unaffected (no physical slots).
                existing = {r[1] for r in self._conn.execute(f"PRAGMA table_xinfo({logical})")}
                for json_key, (slot, kind) in reg.SLOTS.get(logical, {}).items():
                    if slot not in existing:
                        self._conn.execute(
                            f"ALTER TABLE {logical} ADD COLUMN {slot} {_sqlite_slot_type(kind)} "
                            f"GENERATED ALWAYS AS ({_sqlite_slot_expr(kind, json_key)}) VIRTUAL")
                    self._conn.execute(
                        f"CREATE INDEX IF NOT EXISTS ix_{logical}_{slot} ON {logical}({slot})")
            self._conn.execute("CREATE TABLE IF NOT EXISTS _blobs "
                               "(uuid TEXT, field TEXT, data BLOB, PRIMARY KEY(uuid, field))")
            self._conn.commit()

    # -- clause building (semantic → parameterized SQL) -----------------------
    @staticmethod
    def _bind(logical: str, key: str, value):
        """(column, param) for an eq/ne on a slot. Text is lowercased to match the generated slot."""
        slot = reg.slot(logical, key)
        kind = _slot_kind(logical, key)
        if kind == "bool":
            return slot, (1 if value in (True, 1, "1", "true") else 0)
        if kind == "number":
            return slot, value
        return slot, str(value).lower()

    def _select(self, logical: str, where: str, params: list, *, order: str = "",
                limit: int = 0, offset: int = 0) -> list[Row]:
        sql = f"SELECT uuid, jor FROM {logical}"
        if where:
            sql += f" WHERE {where}"
        if order:
            sql += f" ORDER BY {order}"
        if limit:
            sql += f" LIMIT {int(limit)} OFFSET {int(offset)}"
        with self._lock:
            cur = self._conn.execute(sql, params)
            return [Row(r["uuid"], _json.loads(r["jor"])) for r in cur.fetchall()]

    # -- reads ----------------------------------------------------------------
    def get_one(self, logical: str, **eq) -> Optional[Row]:
        clauses, params = [], []
        for k, v in eq.items():
            col, p = self._bind(logical, k, v)
            clauses.append(f"{col} = ?"); params.append(p)
        rows = self._select(logical, _and(clauses), params, limit=1)
        return rows[0] if rows else None

    def get_many(self, logical: str, key: str, values: list) -> list[Row]:
        vals = [v for v in dict.fromkeys(values) if v]
        if not vals:
            return []
        binds = [self._bind(logical, key, v) for v in vals]
        col = binds[0][0]
        placeholders = ",".join("?" for _ in binds)
        return self._select(logical, f"{col} IN ({placeholders})", [p for _, p in binds])

    def get_by_keys(self, logical: str, keys: list) -> list[Row]:
        vals = [k for k in dict.fromkeys(keys) if k]
        if not vals:
            return []
        placeholders = ",".join("?" for _ in vals)
        return self._select(logical, f"uuid IN ({placeholders})", vals)

    def page(self, logical: str, *, eq: Optional[dict] = None, ne: Optional[dict] = None,
             isin: Optional[dict] = None, contains: Optional[dict] = None,
             exclude: Optional[dict] = None,
             orderby: Optional[str] = None, desc: bool = True,
             page: int = 1, per_page: int = 25, count: bool = False) -> tuple[list[Row], int]:
        per_page = max(1, min(int(per_page or 25), 200))
        offset = (max(1, int(page or 1)) - 1) * per_page
        clauses, params = [], []
        for k, v in (eq or {}).items():
            col, p = self._bind(logical, k, v); clauses.append(f"{col} = ?"); params.append(p)
        for k, v in (ne or {}).items():
            col, p = self._bind(logical, k, v); clauses.append(f"{col} <> ?"); params.append(p)
        for k, vals in (isin or {}).items():
            vs = [v for v in dict.fromkeys(vals) if v]
            if vs:
                binds = [self._bind(logical, k, v) for v in vs]
                clauses.append(f"{binds[0][0]} IN ({','.join('?' for _ in binds)})")
                params += [p for _, p in binds]
        if exclude:
            sub = []
            for k, v in exclude.items():
                col, p = self._bind(logical, k, v); sub.append(f"{col} = ?"); params.append(p)
            clauses.append("NOT (" + " AND ".join(sub) + ")")
        if contains:
            needle = str(next(iter(contains.values()))).lower()
            ors = " or ".join(f"{reg.slot(logical, k)} LIKE ?" for k in contains)
            clauses.append(f"({ors})"); params += [f"%{needle}%" for _ in contains]
        where = _and(clauses)
        total = -1
        if count:
            with self._lock:
                total = int(self._conn.execute(
                    f"SELECT COUNT(*) FROM {logical}" + (f" WHERE {where}" if where else ""),
                    params).fetchone()[0])
        order = f"{reg.slot(logical, orderby)} {'DESC' if desc else 'ASC'}" if orderby else ""
        return self._select(logical, where, params, order=order, limit=per_page, offset=offset), total

    def list_all(self, logical: str) -> list[Row]:
        return self._select(logical, "", [])

    def list_where(self, logical: str, *, eq: Optional[dict] = None, ne: Optional[dict] = None,
                   isin: Optional[dict] = None) -> list[Row]:
        """Mirror of :meth:`FMEngine.list_where` — including the empty-``isin`` rule (matches
        nothing). The two must agree: a read path that narrows on FM and stays wide on SQLite is a
        divergence the dev/test suite would never catch, because the suite runs on SQLite."""
        clauses, params = [], []
        for k, v in (eq or {}).items():
            col, p = self._bind(logical, k, v); clauses.append(f"{col} = ?"); params.append(p)
        for k, v in (ne or {}).items():
            col, p = self._bind(logical, k, v); clauses.append(f"{col} <> ?"); params.append(p)
        for k, vals in (isin or {}).items():
            vs = [v for v in dict.fromkeys(vals) if v]
            if not vs:
                return []
            binds = [self._bind(logical, k, v) for v in vs]
            clauses.append(f"{binds[0][0]} IN ({','.join('?' for _ in binds)})")
            params += [p for _, p in binds]
        return self._select(logical, _and(clauses), params)

    # -- writes (jor + key only; slots auto-generate) -------------------------
    def create(self, logical: str, key: str, jor: dict) -> None:
        with self._lock:
            self._conn.execute(f"INSERT INTO {logical}(uuid, jor) VALUES (?, ?)",
                               [key or str(_uuidlib.uuid4()), _json.dumps(jor, ensure_ascii=False)])
            self._conn.commit()

    def update(self, logical: str, key: str, jor: dict) -> None:
        with self._lock:
            self._conn.execute(f"UPDATE {logical} SET jor = ? WHERE uuid = ?",
                               [_json.dumps(jor, ensure_ascii=False), key])
            self._conn.commit()

    def delete(self, logical: str, key: str) -> None:
        with self._lock:
            self._conn.execute(f"DELETE FROM {logical} WHERE uuid = ?", [key])
            self._conn.execute("DELETE FROM _blobs WHERE uuid = ?", [key])
            self._conn.commit()

    # -- blobs ----------------------------------------------------------------
    def blob_get(self, logical: str, key: str, field: str) -> Optional[bytes]:
        with self._lock:
            row = self._conn.execute("SELECT data FROM _blobs WHERE uuid = ? AND field = ?",
                                     [key, field]).fetchone()
        return bytes(row["data"]) if row and row["data"] is not None else None

    def blob_put(self, logical: str, key: str, field: str, data: bytes) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO _blobs(uuid, field, data) VALUES (?, ?, ?)",
                               [key, field, data])
            self._conn.commit()

    def blob_delete(self, logical: str, key: str, field: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM _blobs WHERE uuid = ? AND field = ?", [key, field])
            self._conn.commit()

    def blob_exists(self, logical: str, key: str, field: str) -> Optional[bool]:
        with self._lock:
            row = self._conn.execute(
                "SELECT length(data) FROM _blobs WHERE uuid = ? AND field = ?",
                [key, field]).fetchone()
        return bool(row and row[0])

    # -- special: native SQL (returns rows as tuples) -------------------------
    def sql(self, query: str, *, columns: bool = False) -> list:
        with self._lock:
            rows = self._conn.execute(query).fetchall()
        return [tuple(r) for r in rows] if columns else [r[0] for r in rows]

    @staticmethod
    def phys(logical: str) -> str:
        """SQLite tables are named by the logical entity itself."""
        return logical

    @staticmethod
    def sql_page_clause(skip: int, top: int) -> str:
        return f"LIMIT {int(top)} OFFSET {int(skip)}"
