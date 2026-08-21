"""
The rule set.

Two hard constraints, both aimed at the false-positive problem that makes
existing scanners in this space unusable:

1. A rule may only fire with evidence — file, line, and the source text.
2. A rule states its own confidence. Pattern matches that are merely suspicious
   score low and are filtered out before display; only high-confidence findings
   move the trust score.

Rules also skip files that generate noise rather than signal: tests, examples,
docs, vendored dependencies and minified bundles.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from ..models import Category, Evidence, Finding, PackageVersion, Severity

# Files whose contents are not the package's own runtime behaviour. Scanning
# them is the single largest source of false positives: a test fixture that
# demonstrates a path traversal is not a path traversal.
SKIP_PATH = re.compile(
    r"(^|/)(test|tests|__tests__|spec|specs|example|examples|demo|demos|"
    r"docs?|fixtures?|node_modules|vendor|site-packages|dist|build|\.git)(/|$)",
    re.IGNORECASE,
)
SKIP_FILE = re.compile(
    r"(\.min\.js|\.min\.css|\.map|\.lock|-lock\.json|\.snap)$", re.IGNORECASE
)
SCANNABLE = re.compile(r"\.(py|js|mjs|cjs|ts|tsx|jsx|json|ya?ml|toml|sh)$", re.IGNORECASE)


def is_scannable(path: str) -> bool:
    if SKIP_PATH.search(path) or SKIP_FILE.search(path):
        return False
    return bool(SCANNABLE.search(path))


def _lines(text: str) -> list[str]:
    return text.splitlines()


def _evidence(path: str, text: str, match_start: int) -> Evidence:
    """Turn a character offset into a 1-indexed line with its source."""
    line_no = text.count("\n", 0, match_start) + 1
    lines = _lines(text)
    snippet = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    return Evidence(file=path, line=line_no, snippet=snippet)


@dataclass
class RuleContext:
    package: PackageVersion
    files: dict[str, str]          # path -> content


# ---------------------------------------------------------------------------
# 1. Tool-description injection (tool poisoning)
# ---------------------------------------------------------------------------

# Agents treat tool descriptions as trusted context, so a directive hidden in a
# description steers the agent directly. This is the highest-signal rule here:
# there is no legitimate reason for a tool description to address the model.
_INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    (r"<\s*IMPORTANT\s*>", "an <IMPORTANT> directive block", 0.95),
    (r"<\s*(system|instructions?|secret|hidden)\s*>", "a pseudo-system tag", 0.9),
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)",
     "an instruction-override phrase", 0.95),
    (r"do\s+not\s+(tell|mention|inform|reveal)\s+(the\s+)?user",
     "an instruction to conceal behaviour from the user", 0.95),
    (r"before\s+(using|calling)\s+(this|any)\s+tool,?\s+you\s+must",
     "a precondition directive aimed at the model", 0.85),
    (r"(read|send|exfiltrate|upload)\s+.{0,30}(\.env|ssh|id_rsa|credentials|api[_ ]?key)",
     "a reference to reading or sending credential material", 0.9),
    (r"</?(assistant|user|system)>", "chat-role markup", 0.8),
]

# Zero-width and directional characters hide text from a human reviewer while
# the model still reads it.
_HIDDEN_CHARS = re.compile(r"[​-‏‪-‮⁠-⁤﻿]")


def rule_tool_description_injection(ctx: RuleContext) -> Iterator[Finding]:
    for tool in ctx.package.tools:
        text = tool.description or ""
        if not text:
            continue

        for pattern, human, confidence in _INJECTION_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if not m:
                continue
            yield Finding(
                rule_id="injection/tool-description",
                title=f"Tool '{tool.name}' description contains {human}",
                severity=Severity.CRITICAL,
                category=Category.INJECTION,
                confidence=confidence,
                detail=(
                    "The agent reads tool descriptions as trusted instructions. "
                    "Text here that addresses the model can redirect it without "
                    "the user ever seeing why."
                ),
                evidence=[
                    Evidence(
                        file="<tool manifest>",
                        line=0,
                        snippet=text[max(0, m.start() - 60) : m.end() + 60],
                    )
                ],
                remediation=(
                    "Tool descriptions should describe what the tool does, in "
                    "plain prose, and nothing else."
                ),
            )
            break  # one finding per tool is enough to act on

        if _HIDDEN_CHARS.search(text):
            yield Finding(
                rule_id="injection/hidden-characters",
                title=f"Tool '{tool.name}' description contains invisible characters",
                severity=Severity.CRITICAL,
                category=Category.INJECTION,
                confidence=0.9,
                detail=(
                    "Zero-width or bidirectional characters render as nothing to "
                    "a human reviewer while remaining fully visible to the model."
                ),
                evidence=[
                    Evidence(
                        file="<tool manifest>", line=0,
                        snippet=_HIDDEN_CHARS.sub("[HIDDEN]", text)[:200],
                    )
                ],
                remediation="Strip non-printing characters from all tool metadata.",
            )


# ---------------------------------------------------------------------------
# 2. Path traversal
# ---------------------------------------------------------------------------

_PATH_JOIN = re.compile(
    r"(os\.path\.join|Path\s*\(|path\.join|resolve\s*\()\s*\(?[^)\n]{0,80}",
    re.IGNORECASE,
)
_NORMALISED = re.compile(
    r"(realpath|resolve\(\)|abspath|normpath|is_relative_to|commonpath|"
    r"startswith\s*\(|relative_to)",
    re.IGNORECASE,
)
_TAINT = re.compile(
    r"\b(arguments?|params?|request|input|user_?\w*|args\[|kwargs|payload|body)\b",
    re.IGNORECASE,
)


def rule_path_traversal(ctx: RuleContext) -> Iterator[Finding]:
    for path, text in ctx.files.items():
        if not is_scannable(path):
            continue
        for m in _PATH_JOIN.finditer(text):
            window = text[m.start() : m.start() + 300]
            # Only flag when caller-controlled data reaches the join AND no
            # containment check appears nearby. Both conditions matter: either
            # alone produces the noise that makes these tools ignorable.
            if not _TAINT.search(window):
                continue
            if _NORMALISED.search(window):
                continue
            yield Finding(
                rule_id="filesystem/path-traversal",
                title="File path built from caller-controlled input without containment check",
                severity=Severity.HIGH,
                category=Category.FILESYSTEM,
                confidence=0.65,
                detail=(
                    "A tool argument reaches a path construction with no "
                    "resolve-and-verify step, so '../' in an argument can escape "
                    "the intended directory."
                ),
                evidence=[_evidence(path, text, m.start())],
                remediation=(
                    "Resolve the final path and assert it is inside the allowed "
                    "root before opening it."
                ),
            )
            break  # one per file — the pattern repeats and the fix is the same


# ---------------------------------------------------------------------------
# 3. Credentials
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, str, float]] = [
    (r"sk-[A-Za-z0-9]{20,}", "an OpenAI-style secret key", 0.95),
    (r"sk-ant-[A-Za-z0-9_-]{20,}", "an Anthropic secret key", 0.95),
    (r"gh[pousr]_[A-Za-z0-9]{30,}", "a GitHub token", 0.95),
    (r"AKIA[0-9A-Z]{16}", "an AWS access key id", 0.95),
    (r"AIza[0-9A-Za-z_-]{30,}", "a Google API key", 0.9),
    (r"-----BEGIN\s+(RSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY", "a private key", 0.98),
]
_PLACEHOLDER = re.compile(
    r"(your[_-]?|example|placeholder|xxx+|<[^>]+>|\.\.\.|changeme|dummy|fake|test)",
    re.IGNORECASE,
)


def rule_hardcoded_secret(ctx: RuleContext) -> Iterator[Finding]:
    for path, text in ctx.files.items():
        if not is_scannable(path):
            continue
        for pattern, human, confidence in _SECRET_PATTERNS:
            for m in re.finditer(pattern, text):
                literal = m.group(0)
                # A key-shaped string in a docs example is not a leaked key.
                if _PLACEHOLDER.search(literal):
                    continue
                yield Finding(
                    rule_id="credentials/hardcoded-secret",
                    title=f"Source contains {human}",
                    severity=Severity.CRITICAL,
                    category=Category.CREDENTIALS,
                    confidence=confidence,
                    detail="A live credential published inside a package is compromised.",
                    evidence=[
                        Evidence(
                            file=path,
                            line=text.count("\n", 0, m.start()) + 1,
                            snippet=literal[:12] + "…[redacted]",
                        )
                    ],
                    remediation="Revoke the credential and load it from the environment.",
                )
                break


_STATIC_AUTH = re.compile(
    r"(API_?KEY|ACCESS_TOKEN|PERSONAL_ACCESS_TOKEN|AUTH_TOKEN|PAT)\b", re.IGNORECASE
)
_OAUTH = re.compile(r"(oauth|authorization_code|refresh_token|pkce|\.well-known)", re.IGNORECASE)


def rule_static_credential_auth(ctx: RuleContext) -> Iterator[Finding]:
    """
    Static long-lived keys rather than OAuth.

    Informational rather than a defect: it is the dominant pattern in this
    ecosystem. It matters because a static key cannot be scoped or revoked per
    user, so a compromised server leaks everything it was ever given.
    """
    uses_static = False
    first: tuple[str, str, int] | None = None
    for path, text in ctx.files.items():
        if not is_scannable(path):
            continue
        if _OAUTH.search(text):
            return  # OAuth present somewhere — nothing to say
        if not uses_static and (m := _STATIC_AUTH.search(text)):
            uses_static, first = True, (path, text, m.start())

    if uses_static and first:
        path, text, pos = first
        yield Finding(
            rule_id="credentials/static-auth",
            title="Authenticates with a long-lived static token rather than OAuth",
            severity=Severity.LOW,
            category=Category.CREDENTIALS,
            confidence=0.7,
            detail=(
                "A static token cannot be scoped per user or revoked "
                "individually, so the server holds broader authority than any "
                "single task needs."
            ),
            evidence=[_evidence(path, text, pos)],
            remediation="Prefer an OAuth flow with per-user, least-privilege scopes.",
        )


# ---------------------------------------------------------------------------
# 4. Execution
# ---------------------------------------------------------------------------

_EXEC_PATTERNS: list[tuple[str, str, Severity, float]] = [
    (r"subprocess\.\w+\([^)]*shell\s*=\s*True", "subprocess with shell=True",
     Severity.HIGH, 0.85),
    (r"\bos\.system\s*\(", "os.system()", Severity.HIGH, 0.85),
    (r"\bchild_process\.exec\s*\(", "child_process.exec()", Severity.HIGH, 0.85),
    (r"\beval\s*\(", "eval()", Severity.HIGH, 0.6),
    (r"\bnew\s+Function\s*\(", "new Function()", Severity.HIGH, 0.7),
    (r"\bexec\s*\(\s*(f?[\"'])", "exec() on a string", Severity.HIGH, 0.75),
]


def rule_dynamic_execution(ctx: RuleContext) -> Iterator[Finding]:
    for path, text in ctx.files.items():
        if not is_scannable(path):
            continue
        for pattern, human, severity, confidence in _EXEC_PATTERNS:
            m = re.search(pattern, text)
            if not m:
                continue
            window = text[max(0, m.start() - 200) : m.start() + 200]
            tainted = bool(_TAINT.search(window))
            yield Finding(
                rule_id="execution/dynamic",
                title=f"Uses {human}"
                + (" with caller-controlled input nearby" if tainted else ""),
                severity=Severity.CRITICAL if tainted else severity,
                category=Category.EXECUTION,
                confidence=min(0.95, confidence + (0.2 if tainted else 0.0)),
                detail=(
                    "Tool arguments originate from model output, which can be "
                    "steered by anything the model has read. Passing them to a "
                    "shell turns prompt injection into command execution."
                ),
                evidence=[_evidence(path, text, m.start())],
                remediation="Pass an argument list to a non-shell exec, and allow-list commands.",
            )
            break


# ---------------------------------------------------------------------------
# 5. Network egress
# ---------------------------------------------------------------------------

_FETCH = re.compile(
    r"(requests\.(get|post|put|delete)|httpx\.(get|post)|urlopen|fetch\s*\(|axios\.\w+)\s*\(",
    re.IGNORECASE,
)
_URL_ALLOWLIST = re.compile(
    r"(allow_?list|allowed_?hosts?|whitelist|urlparse|netloc|hostname\s*(==|in)|"
    r"validate_?url|is_?allowed)",
    re.IGNORECASE,
)


def rule_unrestricted_egress(ctx: RuleContext) -> Iterator[Finding]:
    for path, text in ctx.files.items():
        if not is_scannable(path):
            continue
        for m in _FETCH.finditer(text):
            window = text[m.start() : m.start() + 250]
            if not _TAINT.search(window):
                continue
            if _URL_ALLOWLIST.search(text):
                continue
            yield Finding(
                rule_id="network/unrestricted-egress",
                title="Fetches a caller-supplied URL with no host restriction",
                severity=Severity.HIGH,
                category=Category.NETWORK,
                confidence=0.6,
                detail=(
                    "A tool argument reaching an HTTP client unchecked lets the "
                    "server be aimed at internal addresses or cloud metadata "
                    "endpoints, and gives an injected instruction a way out."
                ),
                evidence=[_evidence(path, text, m.start())],
                remediation="Parse the URL and allow-list the scheme and host before requesting it.",
            )
            break


# ---------------------------------------------------------------------------
# 6. Supply chain
# ---------------------------------------------------------------------------

_RISKY_HOOKS = ("preinstall", "install", "postinstall")
_NET_IN_SCRIPT = re.compile(r"(curl|wget|iwr|Invoke-WebRequest|http://|https://)", re.IGNORECASE)


def rule_install_scripts(ctx: RuleContext) -> Iterator[Finding]:
    for hook, script in ctx.package.install_scripts.items():
        if hook not in _RISKY_HOOKS:
            continue
        networked = bool(_NET_IN_SCRIPT.search(script))
        yield Finding(
            rule_id="supply_chain/install-script",
            title=f"Runs a '{hook}' script"
            + (" that reaches the network" if networked else ""),
            severity=Severity.CRITICAL if networked else Severity.MEDIUM,
            category=Category.SUPPLY_CHAIN,
            confidence=0.95 if networked else 0.8,
            detail=(
                "Install hooks execute on the machine of everyone who installs "
                "the package, before any code review happens."
                + (" This one downloads and runs remote content." if networked else "")
            ),
            evidence=[Evidence(file="package.json", line=0, snippet=f"{hook}: {script}")],
            remediation="Move setup into an explicit command the user runs knowingly.",
        )


def rule_unpinned_dependencies(ctx: RuleContext) -> Iterator[Finding]:
    loose = [
        f"{n}@{v}" for n, v in ctx.package.dependencies.items()
        if isinstance(v, str) and (v.startswith(("^", "~", ">", "*")) or v in ("*", "latest"))
    ]
    if len(loose) < 3:
        return
    yield Finding(
        rule_id="supply_chain/unpinned-dependencies",
        title=f"{len(loose)} dependencies float to newer versions",
        severity=Severity.LOW,
        category=Category.SUPPLY_CHAIN,
        confidence=0.9,
        detail=(
            "Floating ranges mean the code that eventually runs is not the code "
            "that was reviewed here."
        ),
        evidence=[
            Evidence(file="package.json", line=0, snippet=", ".join(loose[:8]))
        ],
        remediation="Pin exact versions and update deliberately.",
    )


# ---------------------------------------------------------------------------
# 7. Declared permissions
# ---------------------------------------------------------------------------

_BROAD_SCOPES = {
    "*": "everything",
    "all": "everything",
    "fs:*": "the entire filesystem",
    "filesystem": "the entire filesystem",
    "shell": "arbitrary shell access",
    "exec": "arbitrary execution",
    "network:*": "unrestricted network access",
    "admin": "administrative authority",
    "root": "root authority",
}


def rule_overbroad_scope(ctx: RuleContext) -> Iterator[Finding]:
    for tool in ctx.package.tools:
        for scope in tool.scopes:
            human = _BROAD_SCOPES.get(scope.strip().lower())
            if not human:
                continue
            yield Finding(
                rule_id="permissions/overbroad-scope",
                title=f"Tool '{tool.name}' requests {human}",
                severity=Severity.HIGH,
                category=Category.PERMISSIONS,
                confidence=0.9,
                detail=(
                    "Ambient authority far beyond a single task is what turns a "
                    "small compromise into a total one."
                ),
                evidence=[
                    Evidence(file="<tool manifest>", line=0, snippet=f"{tool.name}: {scope}")
                ],
                remediation="Declare the narrowest scope the tool actually needs.",
            )


# ---------------------------------------------------------------------------
# 8. Provenance
# ---------------------------------------------------------------------------


def rule_provenance(ctx: RuleContext) -> Iterator[Finding]:
    pkg = ctx.package
    if not pkg.repository:
        yield Finding(
            rule_id="provenance/no-repository",
            title="No source repository declared",
            severity=Severity.MEDIUM,
            category=Category.PROVENANCE,
            confidence=1.0,
            detail=(
                "Without a linked repository the published artifact cannot be "
                "compared against reviewable source."
            ),
            evidence=[Evidence(file="<package metadata>", line=0, snippet="repository: (none)")],
            remediation="Publish with a repository field pointing at the real source.",
        )
    if not pkg.license:
        yield Finding(
            rule_id="provenance/no-license",
            title="No license declared",
            severity=Severity.LOW,
            category=Category.PROVENANCE,
            confidence=1.0,
            detail="Unlicensed code cannot be used safely in a commercial product.",
            evidence=[Evidence(file="<package metadata>", line=0, snippet="license: (none)")],
            remediation="Declare a license.",
        )


ALL_RULES = [
    rule_tool_description_injection,
    rule_path_traversal,
    rule_hardcoded_secret,
    rule_static_credential_auth,
    rule_dynamic_execution,
    rule_unrestricted_egress,
    rule_install_scripts,
    rule_unpinned_dependencies,
    rule_overbroad_scope,
    rule_provenance,
]
