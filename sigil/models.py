"""
Core types.

The design constraint that shapes everything here: published scanners in this
space run at roughly a 78% false-positive rate, which makes their output
unactionable. So a Finding cannot exist without *evidence* — a file, a line and
the actual source text — and it carries an explicit confidence that the trust
score respects. If we cannot point at the line, we do not report it.
"""

from __future__ import annotations

import datetime as dt
from enum import Enum
from typing import ClassVar, Literal

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            "critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0,
        }[self.value]

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Category(str, Enum):
    INJECTION = "injection"          # tool poisoning via descriptions
    FILESYSTEM = "filesystem"        # path traversal, unbounded roots
    CREDENTIALS = "credentials"      # static keys, hardcoded secrets
    EXECUTION = "execution"          # shell, eval, dynamic import
    NETWORK = "network"              # SSRF, unrestricted egress
    SUPPLY_CHAIN = "supply_chain"    # install scripts, unpinned deps
    PERMISSIONS = "permissions"      # over-broad declared scope
    PROVENANCE = "provenance"        # unsigned, unlinked, unverifiable


class Evidence(BaseModel):
    """
    Where a finding actually lives.

    A maintainer must be able to open this file at this line and see the same
    thing we saw. Without that, a finding is an accusation rather than a report.
    """

    file: str
    line: int = Field(ge=0)
    snippet: str = ""

    @field_validator("snippet")
    @classmethod
    def _trim(cls, v: str) -> str:
        v = (v or "").strip()
        # Long lines are usually minified bundles; a wall of text is not evidence.
        return v[:300]


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    category: Category
    # How sure the rule is that this is real, not that it is dangerous.
    # Anything under `Scanner.report_threshold` is dropped before it is shown.
    confidence: float = Field(ge=0.0, le=1.0)
    detail: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str = ""

    @property
    def is_actionable(self) -> bool:
        return bool(self.evidence) and self.confidence >= 0.5

    def weighted(self) -> float:
        return self.severity.weight * self.confidence


class ToolSpec(BaseModel):
    """A single tool exposed by an MCP server — the unit that gets diffed."""

    name: str
    description: str = ""
    parameters: list[str] = Field(default_factory=list)
    # Free-form scopes the manifest declares, if any.
    scopes: list[str] = Field(default_factory=list)

    def fingerprint(self) -> str:
        """Stable hash of everything that matters for a rug-pull check."""
        import hashlib

        payload = "\n".join(
            [self.name, self.description, *sorted(self.parameters), *sorted(self.scopes)]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


class PackageVersion(BaseModel):
    """One published version of one package, as ingested from a source."""

    name: str
    version: str
    source: Literal["npm", "pypi", "github", "local"] = "local"
    description: str = ""
    repository: str | None = None
    homepage: str | None = None
    license: str | None = None
    author: str | None = None
    published_at: dt.datetime | None = None
    tools: list[ToolSpec] = Field(default_factory=list)
    dependencies: dict[str, str] = Field(default_factory=dict)
    install_scripts: dict[str, str] = Field(default_factory=dict)
    file_count: int = 0
    content_hash: str = ""

    @property
    def ref(self) -> str:
        return f"{self.source}:{self.name}@{self.version}"


class ScanResult(BaseModel):
    package: PackageVersion
    findings: list[Finding] = Field(default_factory=list)
    scanned_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    files_scanned: int = 0
    # Rules that raised. Non-empty means the package was only partially
    # checked, so "no findings" cannot be read as "clean".
    rule_errors: list[str] = Field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        return not self.rule_errors

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def worst(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out


class ChangeKind(str, Enum):
    """
    Version-to-version changes.

    This enum is the product. One-shot scanners answer "is this package bad
    today", which by construction cannot catch a rug pull — a package that was
    clean for six versions and turns hostile in the seventh. These are the
    changes that matter between two versions.
    """

    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"
    DESCRIPTION_CHANGED = "description_changed"
    PARAMETERS_CHANGED = "parameters_changed"
    SCOPE_BROADENED = "scope_broadened"
    INSTALL_SCRIPT_ADDED = "install_script_added"
    DEPENDENCY_ADDED = "dependency_added"
    MAINTAINER_CHANGED = "maintainer_changed"
    REPOSITORY_CHANGED = "repository_changed"
    LICENSE_CHANGED = "license_changed"
    NEW_FINDING = "new_finding"


class Change(BaseModel):
    kind: ChangeKind
    severity: Severity
    subject: str                      # which tool / dep / field
    before: str | None = None
    after: str | None = None
    detail: str = ""

    @property
    def is_escalation(self) -> bool:
        """Changes that grant the package more power than it previously had."""
        return self.kind in {
            ChangeKind.TOOL_ADDED,
            ChangeKind.SCOPE_BROADENED,
            ChangeKind.INSTALL_SCRIPT_ADDED,
            ChangeKind.NEW_FINDING,
        }


class VersionDiff(BaseModel):
    name: str
    from_version: str
    to_version: str
    changes: list[Change] = Field(default_factory=list)

    @property
    def escalations(self) -> list[Change]:
        return [c for c in self.changes if c.is_escalation]

    @property
    def worst(self) -> Severity | None:
        if not self.changes:
            return None
        return max((c.severity for c in self.changes), key=lambda s: s.rank)

    @property
    def is_rug_pull_candidate(self) -> bool:
        """
        A quiet version that suddenly gains capability.

        Not proof of malice — it is a signal that a human should look before
        this update reaches an agent that can act on the world.
        """
        return any(
            c.severity.rank >= Severity.HIGH.rank and c.is_escalation
            for c in self.changes
        )


# How many points each component of the trust score is worth. Findings carry
# the most weight; maturity deliberately carries little, because age is weak
# evidence of safety and plenty of long-lived packages get taken over.
SCORE_MAX: dict[str, float] = {
    "provenance": 25.0,
    "permissions": 20.0,
    "findings": 35.0,
    "stability": 10.0,
    "maturity": 10.0,
}


class ScoreBreakdown(BaseModel):
    """
    Transparent scoring — every component is shown in the UI.

    An opaque number nobody can argue with is exactly how you end up trusted by
    nobody. Each component starts at its max and loses points for stated reasons.
    """

    provenance: float = 0.0
    permissions: float = 0.0
    findings: float = 0.0
    stability: float = 0.0
    maturity: float = 0.0
    reasons: list[str] = Field(default_factory=list)

    # ClassVar, not a field: annotating this as a plain dict would make pydantic
    # treat the budget as per-instance data.
    MAX: ClassVar[dict[str, float]] = SCORE_MAX

    @property
    def total(self) -> float:
        return round(
            self.provenance + self.permissions + self.findings
            + self.stability + self.maturity,
            1,
        )

    @property
    def grade(self) -> str:
        t = self.total
        if t >= 85:
            return "A"
        if t >= 70:
            return "B"
        if t >= 55:
            return "C"
        if t >= 40:
            return "D"
        return "F"
