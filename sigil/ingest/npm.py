"""
npm registry ingester.

This is what makes the registry useful on day one with zero publisher
participation: the packages are already public, so they can be indexed and
scanned without anyone opting in. Publishers claim their listing afterwards.

Nothing from the package is executed — the tarball is unpacked to a temporary
directory, read as text, and deleted.
"""

from __future__ import annotations

import datetime as dt
import io
import logging
import tarfile
import tempfile
from pathlib import Path

import httpx

from ..models import PackageVersion
from .local import load_package

log = logging.getLogger("sigil.npm")

REGISTRY = "https://registry.npmjs.org"
SEARCH = "https://registry.npmjs.org/-/v1/search"

# A hostile tarball is an expected input here, not an edge case.
MAX_TARBALL_BYTES = 25_000_000
MAX_UNPACKED_BYTES = 120_000_000


class IngestError(RuntimeError):
    pass


async def search(query: str = "mcp server", limit: int = 50) -> list[dict]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(SEARCH, params={"text": query, "size": min(limit, 250)})
    if resp.status_code >= 400:
        raise IngestError(f"npm search {resp.status_code}: {resp.text[:200]}")

    return [
        {
            "name": o["package"]["name"],
            "version": o["package"].get("version", ""),
            "description": o["package"].get("description", ""),
            "publisher": (o["package"].get("publisher") or {}).get("username"),
            "date": o["package"].get("date"),
        }
        for o in resp.json().get("objects", [])
        if o.get("package", {}).get("name")
    ]


async def list_versions(name: str) -> list[str]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{REGISTRY}/{name}")
    if resp.status_code == 404:
        raise IngestError(f"package not found: {name}")
    if resp.status_code >= 400:
        raise IngestError(f"npm {resp.status_code}: {resp.text[:200]}")
    return list(resp.json().get("versions", {}).keys())


async def fetch_version(name: str, version: str | None = None) -> tuple[PackageVersion, dict[str, str]]:
    """Download one version and return it alongside its file contents."""
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        meta_resp = await client.get(f"{REGISTRY}/{name}")
        if meta_resp.status_code >= 400:
            raise IngestError(f"npm metadata {meta_resp.status_code} for {name}")
        meta = meta_resp.json()

        version = version or meta.get("dist-tags", {}).get("latest")
        versions = meta.get("versions", {})
        if version not in versions:
            raise IngestError(f"{name}@{version} not found")

        vmeta = versions[version]
        tarball_url = (vmeta.get("dist") or {}).get("tarball")
        if not tarball_url:
            raise IngestError(f"{name}@{version} has no tarball")

        tar_resp = await client.get(tarball_url)
        if tar_resp.status_code >= 400:
            raise IngestError(f"tarball {tar_resp.status_code} for {name}@{version}")
        blob = tar_resp.content

    if len(blob) > MAX_TARBALL_BYTES:
        raise IngestError(f"{name}@{version} tarball is {len(blob)} bytes; refusing")

    with tempfile.TemporaryDirectory(prefix="sigil-") as tmp:
        root = Path(tmp)
        _safe_extract(blob, root)
        # npm tarballs wrap everything in a single top-level directory.
        inner = next((p for p in root.iterdir() if p.is_dir()), root)
        package, files = load_package(inner, source="npm")

    package.name = name
    package.version = version
    if published := (meta.get("time") or {}).get(version):
        try:
            package.published_at = dt.datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError:
            pass
    if not package.author:
        maintainers = meta.get("maintainers") or []
        if maintainers and isinstance(maintainers[0], dict):
            package.author = maintainers[0].get("name")

    return package, files


def _safe_extract(blob: bytes, dest: Path) -> None:
    """
    Unpack a tarball without trusting it.

    Path traversal via '../' entries and absolute paths in archives is an old
    trick that still works against naive extractors, and a decompression bomb
    will happily fill a disk. Both are refused here rather than mitigated.
    """
    total = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tar:
        for member in tar.getmembers():
            if not (member.isfile() or member.isdir()):
                continue  # skip links and devices entirely

            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise IngestError(f"archive escapes its root: {member.name}")

            total += max(member.size, 0)
            if total > MAX_UNPACKED_BYTES:
                raise IngestError("archive expands beyond the size limit")

            tar.extract(member, dest, filter="data")
