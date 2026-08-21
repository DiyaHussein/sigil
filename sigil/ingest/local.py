"""
Read a package from a local directory.

Used by the fixtures, by `sigil scan ./path` for pre-publish checks, and as the
final step of every remote ingester once a tarball has been unpacked.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..analysis.manifest import extract_tools
from ..models import PackageVersion

# A tool that reads untrusted packages must bound what it will read: a hostile
# archive can otherwise exhaust memory before a single rule runs.
# Bundled JS routinely exceeds 1MB; a cap that silently skips the bundle
# would report 'clean' on an unread file.
MAX_FILE_BYTES = 6_000_000
MAX_FILES = 3_000

# Note what is NOT here: dist/ and build/. In a source repo those are
# generated noise, but in a published package they are the code that actually
# runs on the installer's machine. Skipping them means grading a package on its
# README, which is the worst failure mode this tool can have.
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", "site-packages",
}
TEXT_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json",
    ".yaml", ".yml", ".toml", ".md", ".txt", ".sh", ".cfg", ".ini",
}


def read_files(root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    root = Path(root)

    for path in sorted(root.rglob("*")):
        if len(files) >= MAX_FILES:
            break
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files[path.relative_to(root).as_posix()] = text

    return files


def _content_hash(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for path in sorted(files):
        h.update(path.encode())
        h.update(files[path].encode("utf-8", errors="replace"))
    return h.hexdigest()[:32]


def load_package(root: str | Path, source: str = "local") -> tuple[PackageVersion, dict[str, str]]:
    root = Path(root)
    files = read_files(root)

    meta: dict = {}
    pkg_json = files.get("package.json")
    if pkg_json:
        try:
            meta = json.loads(pkg_json)
        except json.JSONDecodeError:
            meta = {}

    repository = meta.get("repository")
    if isinstance(repository, dict):
        repository = repository.get("url")

    author = meta.get("author")
    if isinstance(author, dict):
        author = author.get("name")

    scripts = meta.get("scripts") or {}
    install_scripts = {
        k: str(v) for k, v in scripts.items()
        if k in ("preinstall", "install", "postinstall")
    } if isinstance(scripts, dict) else {}

    package = PackageVersion(
        name=str(meta.get("name") or root.name),
        version=str(meta.get("version") or "0.0.0"),
        source=source,  # type: ignore[arg-type]
        description=str(meta.get("description") or ""),
        repository=str(repository) if repository else None,
        homepage=str(meta["homepage"]) if meta.get("homepage") else None,
        license=str(meta["license"]) if meta.get("license") else None,
        author=str(author) if author else None,
        tools=extract_tools(files),
        dependencies={
            str(k): str(v) for k, v in (meta.get("dependencies") or {}).items()
        } if isinstance(meta.get("dependencies"), dict) else {},
        install_scripts=install_scripts,
        file_count=len(files),
        content_hash=_content_hash(files),
    )
    return package, files
