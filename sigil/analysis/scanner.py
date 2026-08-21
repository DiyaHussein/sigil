"""Runs the rule set over a package and filters the noise out."""

from __future__ import annotations

import logging

from ..models import Finding, PackageVersion, ScanResult, Severity
from .rules import ALL_RULES, RuleContext, is_scannable

log = logging.getLogger("sigil.scanner")


class Scanner:
    """
    Applies every rule, then drops anything it cannot stand behind.

    `report_threshold` is the lever that separates this from the existing
    scanners in this space: a rule may speculate internally, but speculation
    never reaches a user or a maintainer's inbox.
    """

    def __init__(self, report_threshold: float = 0.5):
        self.report_threshold = report_threshold

    def scan(self, package: PackageVersion, files: dict[str, str]) -> ScanResult:
        ctx = RuleContext(package=package, files=files)
        findings: list[Finding] = []

        errors: list[str] = []
        for rule in ALL_RULES:
            try:
                findings.extend(rule(ctx))
            except Exception as exc:  # a broken rule must not sink the whole scan
                # ...but it must not vanish either. A crashed rule means this
                # package was not fully checked, and reporting "clean" on a
                # partial scan is the most dangerous thing this tool could do.
                log.exception("rule %s failed on %s: %s", rule.__name__, package.ref, exc)
                errors.append(f"{rule.__name__}: {type(exc).__name__}: {exc}")

        kept = [
            f for f in findings
            if f.confidence >= self.report_threshold and f.evidence
        ]
        dropped = len(findings) - len(kept)
        if dropped:
            log.info("%s: dropped %d low-confidence findings", package.ref, dropped)

        kept.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.rule_id))
        kept = self._deduplicate(kept)

        return ScanResult(
            package=package,
            findings=kept,
            files_scanned=sum(1 for p in files if is_scannable(p)),
            rule_errors=errors,
        )

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """
        Collapse repeats of the same rule into one finding with many evidence
        lines. Twenty copies of the same issue is a wall a maintainer ignores;
        one issue with twenty locations is a task they can do.
        """
        merged: dict[str, Finding] = {}
        for f in findings:
            key = f"{f.rule_id}|{f.title}"
            if key in merged:
                existing = merged[key]
                have = {(e.file, e.line) for e in existing.evidence}
                for e in f.evidence:
                    if (e.file, e.line) not in have:
                        existing.evidence.append(e)
                existing.confidence = max(existing.confidence, f.confidence)
            else:
                merged[key] = f.model_copy(deep=True)
        return list(merged.values())


def summarise(result: ScanResult) -> str:
    """One-line summary for logs and CLI output."""
    counts = result.counts()
    parts = [
        f"{counts[s.value]} {s.value}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        if counts[s.value]
    ]
    return f"{result.package.ref}: " + (", ".join(parts) if parts else "clean")
