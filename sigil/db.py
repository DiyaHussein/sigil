"""
Storage.

The schema is shaped around the product thesis: versions are kept forever and
diffs between them are first-class rows. A registry that only stores "current
state" cannot answer the one question that matters — what changed since the
version you approved.
"""

from __future__ import annotations

import datetime as dt
import json
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS packages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT NOT NULL,
    name         TEXT NOT NULL,
    description  TEXT,
    repository   TEXT,
    author       TEXT,
    latest_version TEXT,
    score        REAL,
    grade        TEXT,
    verdict      TEXT,
    claimed_by   TEXT,
    first_seen   TEXT NOT NULL,
    last_scanned TEXT NOT NULL,
    UNIQUE(source, name)
);
CREATE INDEX IF NOT EXISTS idx_pkg_score ON packages(score DESC);
CREATE INDEX IF NOT EXISTS idx_pkg_name ON packages(name);

CREATE TABLE IF NOT EXISTS versions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id   INTEGER NOT NULL REFERENCES packages(id),
    version      TEXT NOT NULL,
    published_at TEXT,
    content_hash TEXT,
    tool_count   INTEGER NOT NULL DEFAULT 0,
    payload      TEXT NOT NULL,          -- full PackageVersion json
    scanned_at   TEXT NOT NULL,
    UNIQUE(package_id, version)
);
CREATE INDEX IF NOT EXISTS idx_ver_pkg ON versions(package_id, id);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id  INTEGER NOT NULL REFERENCES versions(id),
    package_id  INTEGER NOT NULL REFERENCES packages(id),
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    category    TEXT NOT NULL,
    confidence  REAL NOT NULL,
    payload     TEXT NOT NULL,           -- full Finding json incl. evidence
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_find_ver ON findings(version_id);
CREATE INDEX IF NOT EXISTS idx_find_sev ON findings(severity);

CREATE TABLE IF NOT EXISTS diffs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id    INTEGER NOT NULL REFERENCES packages(id),
    from_version  TEXT NOT NULL,
    to_version    TEXT NOT NULL,
    change_count  INTEGER NOT NULL DEFAULT 0,
    worst         TEXT,
    rug_pull      INTEGER NOT NULL DEFAULT 0,
    payload       TEXT NOT NULL,         -- full VersionDiff json
    created_at    TEXT NOT NULL,
    UNIQUE(package_id, from_version, to_version)
);
CREATE INDEX IF NOT EXISTS idx_diff_pkg ON diffs(package_id, id);
CREATE INDEX IF NOT EXISTS idx_diff_rug ON diffs(rug_pull, created_at);

CREATE TABLE IF NOT EXISTS scores (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL REFERENCES versions(id),
    package_id INTEGER NOT NULL REFERENCES packages(id),
    total      REAL NOT NULL,
    grade      TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_score_ver ON scores(version_id);

-- The monetised surface: "tell me when something I depend on changes".
CREATE TABLE IF NOT EXISTS watches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id  INTEGER NOT NULL REFERENCES packages(id),
    subscriber  TEXT NOT NULL,
    pinned_version TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE(package_id, subscriber)
);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id   INTEGER NOT NULL REFERENCES watches(id),
    package_id INTEGER NOT NULL REFERENCES packages(id),
    diff_id    INTEGER REFERENCES diffs(id),
    severity   TEXT NOT NULL,
    message    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    read_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_sub ON alerts(package_id, created_at);
"""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)

    @asynccontextmanager
    async def connect(self):
        """
        Context manager, not a coroutine returning a connection: an aiosqlite
        Connection is both awaitable and an async context manager, and awaiting
        it twice starts its worker thread twice.
        """
        conn = await aiosqlite.connect(self.path)
        conn.row_factory = aiosqlite.Row
        try:
            yield conn
        finally:
            await conn.close()

    async def init(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        async with self.connect() as conn:
            await conn.executescript(SCHEMA)
            await conn.commit()

    # -- writes ---------------------------------------------------------------

    async def upsert_package(self, pkg, score=None, verdict_pair=None) -> int:
        async with self.connect() as conn:
            row = await (
                await conn.execute(
                    "SELECT id FROM packages WHERE source=? AND name=?",
                    (pkg.source, pkg.name),
                )
            ).fetchone()

            fields = (
                pkg.description, pkg.repository, pkg.author, pkg.version,
                score.total if score else None,
                score.grade if score else None,
                verdict_pair[0] if verdict_pair else None,
                _now(),
            )

            if row:
                await conn.execute(
                    "UPDATE packages SET description=?, repository=?, author=?, "
                    "latest_version=?, score=?, grade=?, verdict=?, last_scanned=? "
                    "WHERE id=?",
                    (*fields, row["id"]),
                )
                await conn.commit()
                return int(row["id"])

            cur = await conn.execute(
                "INSERT INTO packages (source, name, description, repository, author, "
                "latest_version, score, grade, verdict, first_seen, last_scanned) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (pkg.source, pkg.name, *fields[:-1], _now(), _now()),
            )
            await conn.commit()
            return int(cur.lastrowid)

    async def save_scan(self, package_id: int, result, score=None, verdict_pair=None) -> int:
        pkg = result.package
        async with self.connect() as conn:
            cur = await conn.execute(
                "INSERT OR REPLACE INTO versions (package_id, version, published_at, "
                "content_hash, tool_count, payload, scanned_at) VALUES (?,?,?,?,?,?,?)",
                (
                    package_id, pkg.version,
                    pkg.published_at.isoformat() if pkg.published_at else None,
                    pkg.content_hash, len(pkg.tools),
                    pkg.model_dump_json(), _now(),
                ),
            )
            version_id = int(cur.lastrowid)

            await conn.execute("DELETE FROM findings WHERE version_id=?", (version_id,))
            for f in result.findings:
                await conn.execute(
                    "INSERT INTO findings (version_id, package_id, rule_id, title, "
                    "severity, category, confidence, payload, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        version_id, package_id, f.rule_id, f.title,
                        f.severity.value, f.category.value, f.confidence,
                        f.model_dump_json(), _now(),
                    ),
                )

            if score is not None:
                await conn.execute(
                    "INSERT INTO scores (version_id, package_id, total, grade, verdict, "
                    "payload, created_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        version_id, package_id, score.total, score.grade,
                        verdict_pair[0] if verdict_pair else "",
                        score.model_dump_json(), _now(),
                    ),
                )

            await conn.commit()
            return version_id

    async def save_diff(self, package_id: int, diff) -> int:
        async with self.connect() as conn:
            cur = await conn.execute(
                "INSERT OR REPLACE INTO diffs (package_id, from_version, to_version, "
                "change_count, worst, rug_pull, payload, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    package_id, diff.from_version, diff.to_version, len(diff.changes),
                    diff.worst.value if diff.worst else None,
                    int(diff.is_rug_pull_candidate), diff.model_dump_json(), _now(),
                ),
            )
            diff_id = int(cur.lastrowid)

            # Fan out to everyone watching this package.
            if diff.changes:
                watchers = await (
                    await conn.execute(
                        "SELECT id, subscriber FROM watches WHERE package_id=?",
                        (package_id,),
                    )
                ).fetchall()
                severity = diff.worst.value if diff.worst else "info"
                message = (
                    f"{diff.name} {diff.from_version} → {diff.to_version}: "
                    f"{len(diff.changes)} change(s)"
                    + (" including a capability escalation" if diff.escalations else "")
                )
                for w in watchers:
                    await conn.execute(
                        "INSERT INTO alerts (watch_id, package_id, diff_id, severity, "
                        "message, created_at) VALUES (?,?,?,?,?,?)",
                        (w["id"], package_id, diff_id, severity, message, _now()),
                    )

            await conn.commit()
            return diff_id

    async def add_watch(self, package_id: int, subscriber: str, pinned: str | None) -> int:
        async with self.connect() as conn:
            await conn.execute(
                "INSERT OR IGNORE INTO watches (package_id, subscriber, pinned_version, "
                "created_at) VALUES (?,?,?,?)",
                (package_id, subscriber, pinned, _now()),
            )
            await conn.commit()
            row = await (
                await conn.execute(
                    "SELECT id FROM watches WHERE package_id=? AND subscriber=?",
                    (package_id, subscriber),
                )
            ).fetchone()
            return int(row["id"])

    # -- reads ----------------------------------------------------------------

    async def get_package(self, source: str, name: str) -> dict | None:
        async with self.connect() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM packages WHERE source=? AND name=?", (source, name)
                )
            ).fetchone()
        return dict(row) if row else None

    async def search(self, q: str = "", limit: int = 50, min_score: float | None = None) -> list[dict]:
        sql = "SELECT * FROM packages WHERE 1=1"
        args: list = []
        if q:
            sql += " AND (name LIKE ? OR description LIKE ?)"
            args += [f"%{q}%", f"%{q}%"]
        if min_score is not None:
            sql += " AND score >= ?"
            args.append(min_score)
        sql += " ORDER BY score DESC NULLS LAST, name LIMIT ?"
        args.append(min(limit, 200))

        async with self.connect() as conn:
            rows = await (await conn.execute(sql, tuple(args))).fetchall()
        return [dict(r) for r in rows]

    async def versions(self, package_id: int) -> list[dict]:
        async with self.connect() as conn:
            rows = await (
                await conn.execute(
                    "SELECT id, version, published_at, tool_count, scanned_at "
                    "FROM versions WHERE package_id=? ORDER BY id DESC",
                    (package_id,),
                )
            ).fetchall()
        return [dict(r) for r in rows]

    async def latest_version_row(self, package_id: int) -> dict | None:
        async with self.connect() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM versions WHERE package_id=? ORDER BY id DESC LIMIT 1",
                    (package_id,),
                )
            ).fetchone()
        return dict(row) if row else None

    async def findings_for(self, version_id: int) -> list[dict]:
        async with self.connect() as conn:
            rows = await (
                await conn.execute(
                    "SELECT payload FROM findings WHERE version_id=? "
                    "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                    "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
                    (version_id,),
                )
            ).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    async def score_for(self, version_id: int) -> dict | None:
        async with self.connect() as conn:
            row = await (
                await conn.execute(
                    "SELECT payload, total, grade, verdict FROM scores "
                    "WHERE version_id=? ORDER BY id DESC LIMIT 1",
                    (version_id,),
                )
            ).fetchone()
        if not row:
            return None
        out = json.loads(row["payload"])
        out.update(total=row["total"], grade=row["grade"], verdict=row["verdict"])
        return out

    async def diffs_for(self, package_id: int, limit: int = 20) -> list[dict]:
        async with self.connect() as conn:
            rows = await (
                await conn.execute(
                    "SELECT payload, rug_pull, worst, created_at FROM diffs "
                    "WHERE package_id=? ORDER BY id DESC LIMIT ?",
                    (package_id, limit),
                )
            ).fetchall()
        out = []
        for r in rows:
            d = json.loads(r["payload"])
            d.update(rug_pull=bool(r["rug_pull"]), created_at=r["created_at"])
            out.append(d)
        return out

    async def recent_escalations(self, limit: int = 20) -> list[dict]:
        """The homepage feed: capability changes across the whole registry."""
        async with self.connect() as conn:
            rows = await (
                await conn.execute(
                    "SELECT d.payload, d.rug_pull, d.created_at, p.name, p.source "
                    "FROM diffs d JOIN packages p ON p.id = d.package_id "
                    "WHERE d.change_count > 0 "
                    "ORDER BY d.rug_pull DESC, d.id DESC LIMIT ?",
                    (limit,),
                )
            ).fetchall()
        out = []
        for r in rows:
            d = json.loads(r["payload"])
            d.update(
                rug_pull=bool(r["rug_pull"]), created_at=r["created_at"],
                name=r["name"], source=r["source"],
            )
            out.append(d)
        return out

    async def alerts_for(self, subscriber: str, limit: int = 50) -> list[dict]:
        async with self.connect() as conn:
            rows = await (
                await conn.execute(
                    "SELECT a.*, p.name FROM alerts a "
                    "JOIN watches w ON w.id = a.watch_id "
                    "JOIN packages p ON p.id = a.package_id "
                    "WHERE w.subscriber=? ORDER BY a.id DESC LIMIT ?",
                    (subscriber, limit),
                )
            ).fetchall()
        return [dict(r) for r in rows]

    async def stats(self) -> dict:
        async with self.connect() as conn:
            async def scalar(sql: str, args: tuple = ()) -> int:
                row = await (await conn.execute(sql, args)).fetchone()
                return int(row[0] or 0)

            return {
                "packages": await scalar("SELECT COUNT(*) FROM packages"),
                "versions": await scalar("SELECT COUNT(*) FROM versions"),
                "findings": await scalar("SELECT COUNT(*) FROM findings"),
                "critical": await scalar(
                    "SELECT COUNT(*) FROM findings WHERE severity='critical'"
                ),
                "diffs": await scalar("SELECT COUNT(*) FROM diffs"),
                "rug_pulls": await scalar("SELECT COUNT(*) FROM diffs WHERE rug_pull=1"),
                "watches": await scalar("SELECT COUNT(*) FROM watches"),
            }
