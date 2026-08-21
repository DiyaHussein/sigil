"""
Extracting the tool surface from an MCP server.

There is no universal manifest in this ecosystem, so tools are recovered from
whichever of these a package actually provides, in order of reliability:

1. A declarative manifest (mcp.json, .mcp/tools.json, package.json "mcp").
2. Python decorators — @mcp.tool() / @server.tool(), description from docstring.
3. JS/TS registrations — server.tool("name", "description", …) and the
   ListTools handler's returned array.

Static extraction never executes package code. Running an untrusted MCP server
to ask what tools it has would defeat the entire purpose of the scan.
"""

from __future__ import annotations

import ast
import json
import logging
import re

from ..models import ToolSpec

log = logging.getLogger("sigil.manifest")

MANIFEST_NAMES = ("mcp.json", ".mcp/tools.json", "sigil.json", "tools.json")


def extract_tools(files: dict[str, str]) -> list[ToolSpec]:
    tools: dict[str, ToolSpec] = {}

    for spec in _from_manifest(files):
        tools.setdefault(spec.name, spec)
    for spec in _from_python(files):
        tools.setdefault(spec.name, spec)
    for spec in _from_javascript(files):
        tools.setdefault(spec.name, spec)

    return sorted(tools.values(), key=lambda t: t.name)


# ---------------------------------------------------------------------------
# 1. Declarative manifests
# ---------------------------------------------------------------------------


def _from_manifest(files: dict[str, str]) -> list[ToolSpec]:
    out: list[ToolSpec] = []

    for path, text in files.items():
        base = path.split("/")[-1]
        is_manifest = base in MANIFEST_NAMES or path in MANIFEST_NAMES
        is_pkg_json = base == "package.json"
        if not (is_manifest or is_pkg_json):
            continue

        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(data, dict):
            continue

        raw_tools = data.get("tools")
        if is_pkg_json:
            raw_tools = (data.get("mcp") or {}).get("tools") if isinstance(data.get("mcp"), dict) else None
        if not isinstance(raw_tools, list):
            continue

        for entry in raw_tools:
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            out.append(
                ToolSpec(
                    name=str(entry["name"]),
                    description=str(entry.get("description") or ""),
                    parameters=_param_names(entry),
                    scopes=[str(s) for s in (entry.get("scopes") or entry.get("permissions") or [])],
                )
            )

    return out


def _param_names(entry: dict) -> list[str]:
    schema = entry.get("inputSchema") or entry.get("parameters") or {}
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict):
            return sorted(str(k) for k in props)
    if isinstance(schema, list):
        return sorted(str(p) for p in schema)
    return []


# ---------------------------------------------------------------------------
# 2. Python decorators
# ---------------------------------------------------------------------------

_PY_TOOL_DECORATOR = re.compile(r"(mcp|server|app)\.tool\b")


def _from_python(files: dict[str, str]) -> list[ToolSpec]:
    out: list[ToolSpec] = []

    for path, text in files.items():
        if not path.endswith(".py") or ".tool" not in text:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(
                _PY_TOOL_DECORATOR.search(ast.unparse(d)) for d in node.decorator_list
            ):
                continue

            name, scopes = node.name, []
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                for kw in dec.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                        name = str(kw.value.value)
                    if kw.arg in ("scopes", "permissions"):
                        try:
                            value = ast.literal_eval(kw.value)
                            if isinstance(value, (list, tuple)):
                                scopes = [str(s) for s in value]
                        except (ValueError, SyntaxError):
                            pass

            out.append(
                ToolSpec(
                    name=name,
                    description=(ast.get_docstring(node) or "").strip(),
                    parameters=[a.arg for a in node.args.args if a.arg != "self"],
                    scopes=scopes,
                )
            )

    return out


# ---------------------------------------------------------------------------
# 3. JavaScript / TypeScript
# ---------------------------------------------------------------------------

# server.tool("name", "description", …)  /  registerTool("name", { description })
_JS_TOOL_CALL = re.compile(
    r"""(?:server|mcp|app)\.(?:tool|registerTool)\s*\(\s*
        (["'`])(?P<name>[^"'`]+)\1\s*,\s*
        (?:(["'`])(?P<desc>[^"'`]*)\3)?""",
    re.VERBOSE,
)
# { name: "x", description: "y" } inside a ListTools handler
_JS_TOOL_OBJECT = re.compile(
    r"""\{\s*name\s*:\s*(["'`])(?P<name>[^"'`]+)\1\s*,\s*
        description\s*:\s*(["'`])(?P<desc>[^"'`]*)\3""",
    re.VERBOSE | re.DOTALL,
)


def _from_javascript(files: dict[str, str]) -> list[ToolSpec]:
    out: list[ToolSpec] = []

    for path, text in files.items():
        if not re.search(r"\.(js|mjs|cjs|ts|tsx|jsx)$", path):
            continue

        for m in _JS_TOOL_CALL.finditer(text):
            out.append(
                ToolSpec(
                    name=m.group("name"),
                    description=(m.group("desc") or "").strip(),
                )
            )
        for m in _JS_TOOL_OBJECT.finditer(text):
            out.append(
                ToolSpec(
                    name=m.group("name"),
                    description=(m.group("desc") or "").strip(),
                )
            )

    return out
