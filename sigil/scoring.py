"""
Trust scoring.

Deliberately transparent: every deduction carries a stated reason shown in the
UI. An opaque score nobody can argue with is how you end up trusted by nobody —
and a maintainer who disagrees needs to be able to see exactly which line cost
them the points.
"""

from __future__ import annotations

import datetime as dt

from .models import SCORE_MAX as MAX
from .models import ScanResult, ScoreBreakdown, Severity, VersionDiff


def score(
    result: ScanResult,
    history: list[VersionDiff] | None = None,
    version_count: int = 1,
    first_published: dt.datetime | None = None,
) -> ScoreBreakdown:
    breakdown = ScoreBreakdown()
    reasons: list[str] = []

    breakdown.provenance = _provenance(result, reasons)
    breakdown.permissions = _permissions(result, reasons)
    breakdown.findings = _findings(result, reasons)
    breakdown.stability = _stability(history or [], reasons)
    breakdown.maturity = _maturity(version_count, first_published, reasons)

    breakdown.reasons = reasons
    return breakdown


def _provenance(result: ScanResult, reasons: list[str]) -> float:
    pkg = result.package
    points = MAX["provenance"]

    if not pkg.repository:
        points -= 12
        reasons.append("-12 no source repository, so the artifact cannot be reviewed")
    if not pkg.license:
        points -= 5
        reasons.append("-5 no declared license")
    if not pkg.author:
        points -= 4
        reasons.append("-4 no identifiable publisher")
    if not pkg.description:
        points -= 2
        reasons.append("-2 no package description")

    return max(0.0, points)


def _permissions(result: ScanResult, reasons: list[str]) -> float:
    points = MAX["permissions"]
    broad = [f for f in result.findings if f.rule_id == "permissions/overbroad-scope"]
    if broad:
        cost = min(20.0, 7.0 * len(broad))
        points -= cost
        reasons.append(
            f"-{cost:g} {len(broad)} tool(s) request authority far beyond their task"
        )

    tool_count = len(result.package.tools)
    if tool_count > 20:
        points -= 4
        reasons.append(
            f"-4 exposes {tool_count} tools; a large surface is harder to review"
        )

    return max(0.0, points)


def _findings(result: ScanResult, reasons: list[str]) -> float:
    """
    Findings deduct in proportion to severity *and* confidence.

    Weighting by confidence is what stops a speculative match from tanking a
    legitimate package — the thing that makes noisy scanners actively harmful.
    """
    points = MAX["findings"]
    if not result.findings:
        reasons.append("+35 no issues found above the reporting threshold")
        return points

    total = sum(f.weighted() for f in result.findings)
    # 40 weighted points of damage exhausts the whole findings budget.
    deduction = min(MAX["findings"], MAX["findings"] * (total / 40.0))
    points -= deduction

    counts = result.counts()
    parts = [
        f"{counts[s.value]} {s.value}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        if counts[s.value]
    ]
    reasons.append(f"-{deduction:.1f} findings: {', '.join(parts)}")
    return max(0.0, points)


def _stability(history: list[VersionDiff], reasons: list[str]) -> float:
    """
    Rewards a package whose capabilities stay put.

    A server that quietly grows new tools and broader scopes every release is
    riskier than one that does the same thing it did last month, even when no
    individual release looks malicious.
    """
    points = MAX["stability"]
    if not history:
        reasons.append("+10 no capability changes on record yet")
        return points

    escalations = sum(len(d.escalations) for d in history)
    rug_pulls = sum(1 for d in history if d.is_rug_pull_candidate)

    if rug_pulls:
        points -= 8
        reasons.append(
            f"-8 {rug_pulls} release(s) added significant capability without warning"
        )
    elif escalations:
        cost = min(5.0, escalations * 1.5)
        points -= cost
        reasons.append(f"-{cost:g} {escalations} capability escalation(s) across releases")
    else:
        reasons.append("+10 capabilities stable across all observed releases")

    return max(0.0, points)


def _maturity(
    version_count: int, first_published: dt.datetime | None, reasons: list[str]
) -> float:
    """
    Age and release count, capped low on purpose.

    Maturity is weak evidence — plenty of long-lived packages get taken over —
    so it is worth 10 points, not 40. It exists mainly to distinguish a package
    published yesterday from one with a track record.
    """
    points = MAX["maturity"]

    if version_count <= 1:
        points -= 5
        reasons.append("-5 only one published version, so there is no track record")

    if first_published is not None:
        now = dt.datetime.now(dt.timezone.utc)
        if first_published.tzinfo is None:
            first_published = first_published.replace(tzinfo=dt.timezone.utc)
        age_days = (now - first_published).days
        if age_days < 30:
            points -= 5
            reasons.append(f"-5 first published {age_days} days ago")
        elif age_days < 180:
            points -= 2
            reasons.append(f"-2 published {age_days} days ago")
    else:
        points -= 2
        reasons.append("-2 publication date unknown")

    return max(0.0, points)


def verdict(breakdown: ScoreBreakdown, result: ScanResult) -> tuple[str, str]:
    """
    (verdict, explanation) — the one line a person actually reads.

    A critical finding overrides the arithmetic: a package can score well on
    provenance and maturity and still be something nobody should install.
    """
    if result.by_severity(Severity.CRITICAL):
        return (
            "do-not-install",
            "A critical issue was found with direct evidence. Do not connect this "
            "to an agent that can act on anything you care about.",
        )
    if breakdown.total >= 85:
        return ("trusted", "No issues above the reporting threshold, with verifiable provenance.")
    if breakdown.total >= 70:
        return ("acceptable", "Minor issues only. Reasonable to use with normal caution.")
    if breakdown.total >= 55:
        return ("review-first", "Enough open questions that a person should read the source.")
    return (
        "high-risk",
        "Multiple unresolved issues or unverifiable provenance.",
    )
