"""Ingest and scan endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from ..config import settings

router = APIRouter(prefix="/api/admin", tags=["admin"])


async def require_admin(authorization: str = Header(default="")) -> None:
    """
    Bearer gate. Empty token means open, which is fine locally and is called
    out in the README as something to set before this faces a network.
    """
    if not settings.admin_token:
        return
    if authorization != f"Bearer {settings.admin_token}":
        raise HTTPException(401, "invalid or missing admin token")


def _svc(request: Request):
    return request.app.state.service


class NpmIngestIn(BaseModel):
    name: str
    version: str | None = None


class NpmHistoryIn(BaseModel):
    name: str
    versions: list[str]


class LocalIngestIn(BaseModel):
    path: str
    source: str = "local"


@router.post("/ingest/npm", dependencies=[Depends(require_admin)])
async def ingest_npm(body: NpmIngestIn, request: Request) -> dict:
    if not settings.allow_remote_ingest:
        raise HTTPException(403, "remote ingest is disabled")
    from ..ingest.npm import IngestError

    try:
        return await _svc(request).ingest_npm(body.name, body.version)
    except IngestError as exc:
        raise HTTPException(400, str(exc))


@router.post("/ingest/npm/history", dependencies=[Depends(require_admin)])
async def ingest_npm_history(body: NpmHistoryIn, request: Request) -> dict:
    if not settings.allow_remote_ingest:
        raise HTTPException(403, "remote ingest is disabled")
    results = await _svc(request).ingest_npm_history(body.name, body.versions)
    return {"ingested": len(results), "results": results}


@router.post("/ingest/local", dependencies=[Depends(require_admin)])
async def ingest_local(body: LocalIngestIn, request: Request) -> dict:
    from pathlib import Path

    path = Path(body.path)
    if not path.exists() or not path.is_dir():
        raise HTTPException(400, f"not a directory: {body.path}")
    return await _svc(request).ingest_local(path, source=body.source)


@router.get("/search/npm", dependencies=[Depends(require_admin)])
async def search_npm(request: Request, q: str = "mcp server", limit: int = 25) -> list[dict]:
    """Find candidate packages on npm to index. Discovery, not ingest."""
    if not settings.allow_remote_ingest:
        raise HTTPException(403, "remote ingest is disabled")
    from ..ingest.npm import IngestError, search

    try:
        return await search(q, limit)
    except IngestError as exc:
        raise HTTPException(400, str(exc))


@router.get("/health")
async def health(request: Request) -> dict:
    return {
        "status": "ok",
        "report_threshold": settings.report_threshold,
        "remote_ingest": settings.allow_remote_ingest,
        **await _svc(request).db.stats(),
    }
