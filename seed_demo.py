#!/usr/bin/env python3
"""
Seed the registry from the bundled fixtures.

Ingests notes-mcp 1.0.0 *then* 1.1.0 in order, because the diff between them —
the rug pull — only exists if both versions pass through the pipeline. That
sequence is the demo.

    python seed_demo.py
"""

from __future__ import annotations

import asyncio

from sigil.analysis.scanner import Scanner
from sigil.config import settings
from sigil.db import Database
from sigil.service import RegistryService

# Order matters: the earlier version must be indexed first.
SEQUENCE = [
    "weather-mcp/2.1.0",
    "filesys-mcp/0.3.0",
    "notes-mcp/1.0.0",
    "notes-mcp/1.1.0",
]


async def main() -> None:
    db = Database(settings.db_path)
    await db.init()
    svc = RegistryService(db, Scanner(settings.report_threshold))

    # A watcher who pinned the clean version, so the rug pull raises a real alert.
    print()
    for rel in SEQUENCE:
        if rel == "notes-mcp/1.1.0":
            pkg = await db.get_package("npm", "notes-mcp")
            if pkg:
                await db.add_watch(pkg["id"], "diya@example.com", "1.0.0")

        r = await svc.ingest_local(settings.fixtures_dir / rel, source="npm")
        flag = "  <-- RUG PULL" if r["rug_pull"] else ""
        print(
            f"  {r['ref']:34} {r['grade']}  {r['score']:5.1f}  "
            f"{r['verdict']:15} {r['findings']} finding(s){flag}"
        )

    stats = await db.stats()
    alerts = await db.alerts_for("diya@example.com")
    print(f"\n  {stats['packages']} packages, {stats['versions']} versions, "
          f"{stats['diffs']} diffs, {stats['rug_pulls']} rug pull flag(s)")
    for a in alerts:
        print(f"  ALERT [{a['severity']}] {a['message']}")
    print("\n  Start the server and open http://127.0.0.1:8090/app/\n")


if __name__ == "__main__":
    asyncio.run(main())
