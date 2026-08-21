"""
Version-to-version capability diffing.

This is the differentiator. Every scanner in this space answers "is this
package dangerous right now", which by construction cannot catch the dominant
attack pattern: a package that is clean for six versions, earns trust and a
place in someone's config, then turns hostile in the seventh.

The question that matters is not "is this bad" but **"what did this gain since
the version I approved?"**
"""

from __future__ import annotations

import difflib

from ..models import (
    Change,
    ChangeKind,
    Finding,
    PackageVersion,
    Severity,
    ToolSpec,
)
from .rules import _HIDDEN_CHARS, _INJECTION_PATTERNS

# Scope names ordered by how much authority they confer. A move up this ladder
# between versions is an escalation regardless of what the changelog claims.
_SCOPE_POWER = {
    "read": 1, "read_only": 1, "readonly": 1,
    "write": 3, "delete": 4, "network": 4,
    "exec": 6, "shell": 6, "admin": 7, "root": 8,
    "*": 9, "all": 9, "filesystem": 7, "fs:*": 9, "network:*": 7,
}


def _scope_power(scopes: list[str]) -> int:
    return max((_SCOPE_POWER.get(s.strip().lower(), 2) for s in scopes), default=0)


def _describes_injection(text: str) -> bool:
    import re

    if _HIDDEN_CHARS.search(text or ""):
        return True
    return any(
        re.search(p, text or "", re.IGNORECASE) for p, _human, _c in _INJECTION_PATTERNS
    )


def _summarise_text_change(before: str, after: str, limit: int = 160) -> str:
    """A compact word-level description of how a description changed."""
    diff = difflib.unified_diff(
        (before or "").split(), (after or "").split(), lineterm="", n=0
    )
    added = [ln[1:] for ln in diff if ln.startswith("+") and not ln.startswith("+++")]
    if not added:
        return "text reworded"
    joined = " ".join(added)
    return ("added: " + joined)[:limit]


def diff_versions(
    old: PackageVersion,
    new: PackageVersion,
    old_findings: list[Finding] | None = None,
    new_findings: list[Finding] | None = None,
):
    """Compare two versions and return every change that affects trust."""
    from ..models import VersionDiff

    changes: list[Change] = []
    old_tools = {t.name: t for t in old.tools}
    new_tools = {t.name: t for t in new.tools}

    changes += _diff_tools(old_tools, new_tools)
    changes += _diff_metadata(old, new)
    changes += _diff_supply_chain(old, new)
    changes += _diff_findings(old_findings or [], new_findings or [])

    changes.sort(key=lambda c: -c.severity.rank)
    return VersionDiff(
        name=new.name,
        from_version=old.version,
        to_version=new.version,
        changes=changes,
    )


def _diff_tools(old: dict[str, ToolSpec], new: dict[str, ToolSpec]) -> list[Change]:
    changes: list[Change] = []

    for name, tool in new.items():
        if name in old:
            continue
        # A new tool is new capability reaching an agent that already trusts
        # this server. Severity depends on how much power it asks for.
        power = _scope_power(tool.scopes)
        changes.append(
            Change(
                kind=ChangeKind.TOOL_ADDED,
                severity=Severity.HIGH if power >= 6 else Severity.MEDIUM,
                subject=name,
                after=tool.description[:200],
                detail=(
                    f"New tool '{name}' appeared"
                    + (f" requesting {', '.join(tool.scopes)}" if tool.scopes else "")
                ),
            )
        )

    for name in old.keys() - new.keys():
        changes.append(
            Change(
                kind=ChangeKind.TOOL_REMOVED,
                severity=Severity.LOW,
                subject=name,
                before=old[name].description[:200],
                detail=f"Tool '{name}' was removed",
            )
        )

    for name, new_tool in new.items():
        old_tool = old.get(name)
        if old_tool is None:
            continue

        if old_tool.description != new_tool.description:
            # The critical case: a description that was benign when approved
            # and now carries a directive. This is tool poisoning by update.
            poisoned = _describes_injection(new_tool.description) and not _describes_injection(
                old_tool.description
            )
            changes.append(
                Change(
                    kind=ChangeKind.DESCRIPTION_CHANGED,
                    severity=Severity.CRITICAL if poisoned else Severity.MEDIUM,
                    subject=name,
                    before=old_tool.description[:200],
                    after=new_tool.description[:200],
                    detail=(
                        f"Description of '{name}' now contains model-directed "
                        "instructions that were not there before"
                        if poisoned
                        else f"Description of '{name}' changed — "
                        + _summarise_text_change(old_tool.description, new_tool.description)
                    ),
                )
            )

        old_power, new_power = _scope_power(old_tool.scopes), _scope_power(new_tool.scopes)
        if new_power > old_power:
            changes.append(
                Change(
                    kind=ChangeKind.SCOPE_BROADENED,
                    severity=Severity.CRITICAL if new_power >= 7 else Severity.HIGH,
                    subject=name,
                    before=", ".join(old_tool.scopes) or "(none)",
                    after=", ".join(new_tool.scopes) or "(none)",
                    detail=f"Tool '{name}' now requests more authority than the previous version",
                )
            )

        added_params = set(new_tool.parameters) - set(old_tool.parameters)
        if added_params:
            changes.append(
                Change(
                    kind=ChangeKind.PARAMETERS_CHANGED,
                    severity=Severity.LOW,
                    subject=name,
                    after=", ".join(sorted(added_params)),
                    detail=f"Tool '{name}' gained parameters: {', '.join(sorted(added_params))}",
                )
            )

    return changes


def _diff_metadata(old: PackageVersion, new: PackageVersion) -> list[Change]:
    changes: list[Change] = []

    if old.author and new.author and old.author != new.author:
        # Ownership transfer is the classic prelude to a supply-chain attack:
        # trust was earned by one party and is now held by another.
        changes.append(
            Change(
                kind=ChangeKind.MAINTAINER_CHANGED,
                severity=Severity.HIGH,
                subject="author",
                before=old.author,
                after=new.author,
                detail="The publishing account changed between versions",
            )
        )

    if old.repository and new.repository and old.repository != new.repository:
        changes.append(
            Change(
                kind=ChangeKind.REPOSITORY_CHANGED,
                severity=Severity.HIGH,
                subject="repository",
                before=old.repository,
                after=new.repository,
                detail="The declared source repository moved",
            )
        )
    elif old.repository and not new.repository:
        changes.append(
            Change(
                kind=ChangeKind.REPOSITORY_CHANGED,
                severity=Severity.HIGH,
                subject="repository",
                before=old.repository,
                after=None,
                detail="The source repository link was removed, so the artifact is no longer reviewable",
            )
        )

    if old.license and new.license and old.license != new.license:
        changes.append(
            Change(
                kind=ChangeKind.LICENSE_CHANGED,
                severity=Severity.LOW,
                subject="license",
                before=old.license,
                after=new.license,
                detail="The license changed",
            )
        )

    return changes


def _diff_supply_chain(old: PackageVersion, new: PackageVersion) -> list[Change]:
    changes: list[Change] = []

    for hook, script in new.install_scripts.items():
        if hook in old.install_scripts:
            continue
        changes.append(
            Change(
                kind=ChangeKind.INSTALL_SCRIPT_ADDED,
                severity=Severity.CRITICAL,
                subject=hook,
                after=script[:200],
                detail=(
                    f"A '{hook}' hook was added — it will execute on every "
                    "machine that installs this update"
                ),
            )
        )

    added_deps = new.dependencies.keys() - old.dependencies.keys()
    if added_deps:
        changes.append(
            Change(
                kind=ChangeKind.DEPENDENCY_ADDED,
                severity=Severity.LOW if len(added_deps) < 4 else Severity.MEDIUM,
                subject="dependencies",
                after=", ".join(sorted(added_deps)[:10]),
                detail=f"{len(added_deps)} new dependencies pulled in",
            )
        )

    return changes


def _diff_findings(old: list[Finding], new: list[Finding]) -> list[Change]:
    """Findings that appeared in this version and were not in the last one."""
    old_ids = {f.rule_id for f in old}
    changes: list[Change] = []
    for f in new:
        if f.rule_id in old_ids:
            continue
        if f.severity.rank < Severity.MEDIUM.rank:
            continue
        changes.append(
            Change(
                kind=ChangeKind.NEW_FINDING,
                severity=f.severity,
                subject=f.rule_id,
                after=f.title,
                detail=f"New issue introduced in this version: {f.title}",
            )
        )
    return changes
