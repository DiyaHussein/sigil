"""Orchestration: ingest → scan → score → diff against the previous version."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .analysis.diff import diff_versions
from .analysis.scanner import Scanner
from .db import Database
from .models import Finding, PackageVersion, ScanResult, VersionDiff
from .scoring import score as compute_score
from .scoring import verdict as compute_verdict

log = logging.getLogger("sigil.service")


class RegistryService:
    def __init__(self, db: Database, scanner: Scanner | None = None):
        self.db = db
        self.scanner = scanner or Scanner()

    async def ingest_local(self, path: str | Path, source: str = "local") -> dict:
        from .ingest.local import load_package

        package, files = load_package(path, source=source)
        return await self._process(package, files)

    async def ingest_npm(self, name: str, version: str | None = None) -> dict:
        from .ingest.npm import fetch_version

        package, files = await fetch_version(name, version)
        return await self._process(package, files)

    async def ingest_npm_history(self, name: str, versions: list[str]) -> list[dict]:
        """
        Ingest several versions in order so the diffs between them exist.

        Backfilling history is what lets the registry answer "what did this
        gain since the version you approved" on the very first day, rather than
        only for changes observed from now on.
        """
        out = []
        for v in versions:
            try:
                out.append(await self.ingest_npm(name, v))
            except Exception as exc:
                log.warning("skipping %s@%s: %s", name, v, exc)
        return out

    # -- core -----------------------------------------------------------------

    async def _process(self, package: PackageVersion, files: dict[str, str]) -> dict:
        result = self.scanner.scan(package, files)

        package_id = await self.db.upsert_package(package)
        previous = await self._previous_version(package_id, package.version)

        diff: VersionDiff | None = None
        if previous is not None:
            prev_pkg, prev_findings = previous
            diff = diff_versions(prev_pkg, package, prev_findings, result.findings)

        history = await self._diff_history(package_id)
        if diff is not None:
            history = [*history, diff]

        versions = await self.db.versions(package_id)
        breakdown = compute_score(
            result,
            history=history,
            version_count=len(versions) + 1,
            first_published=package.published_at,
        )
        verdict_pair = compute_verdict(breakdown, result)

        version_id = await self.db.save_scan(package_id, result, breakdown, verdict_pair)
        await self.db.upsert_package(package, breakdown, verdict_pair)

        if diff is not None and diff.changes:
            await self.db.save_diff(package_id, diff)

        log.info(
            "%s scored %.1f (%s) — %d finding(s)%s",
            package.ref, breakdown.total, breakdown.grade, len(result.findings),
            f", {len(diff.changes)} change(s) vs {diff.from_version}" if diff else "",
        )

        return {
            "package_id": package_id,
            "version_id": version_id,
            "ref": package.ref,
            "score": breakdown.total,
            "grade": breakdown.grade,
            "verdict": verdict_pair[0],
            "verdict_detail": verdict_pair[1],
            "findings": len(result.findings),
            "counts": result.counts(),
            "diff": diff.model_dump(mode="json") if diff else None,
            "rug_pull": diff.is_rug_pull_candidate if diff else False,
        }

    async def _previous_version(
        self, package_id: int, current_version: str
    ) -> tuple[PackageVersion, list[Finding]] | None:
        row = await self.db.latest_version_row(package_id)
        if not row or row["version"] == current_version:
            return None
        pkg = PackageVersion.model_validate_json(row["payload"])
        raw = await self.db.findings_for(row["id"])
        return pkg, [Finding.model_validate(f) for f in raw]

    async def _diff_history(self, package_id: int) -> list[VersionDiff]:
        return [
            VersionDiff.model_validate(
                {k: v for k, v in d.items() if k in ("name", "from_version", "to_version", "changes")}
            )
            for d in await self.db.diffs_for(package_id, limit=50)
        ]

    # -- reads ----------------------------------------------------------------

    async def package_detail(self, source: str, name: str) -> dict | None:
        pkg = await self.db.get_package(source, name)
        if not pkg:
            return None

        latest = await self.db.latest_version_row(pkg["id"])
        findings = await self.db.findings_for(latest["id"]) if latest else []
        score_row = await self.db.score_for(latest["id"]) if latest else None
        tools = []
        if latest:
            tools = json.loads(latest["payload"]).get("tools", [])

        return {
            "package": pkg,
            "latest_version": latest["version"] if latest else None,
            "tools": tools,
            "findings": findings,
            "score": score_row,
            "versions": await self.db.versions(pkg["id"]),
            "diffs": await self.db.diffs_for(pkg["id"]),
        }
