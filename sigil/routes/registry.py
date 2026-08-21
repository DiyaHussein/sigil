"""Public registry API — search, package pages, diffs, badges."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["registry"])


def _svc(request: Request):
    return request.app.state.service


class WatchIn(BaseModel):
    subscriber: str
    pinned_version: str | None = None


@router.get("/stats")
async def stats(request: Request) -> dict:
    return await _svc(request).db.stats()


@router.get("/packages")
async def search_packages(
    request: Request, q: str = "", limit: int = 50, min_score: float | None = None
) -> list[dict]:
    return await _svc(request).db.search(q=q, limit=limit, min_score=min_score)


@router.get("/packages/{source}/{name:path}")
async def package_detail(source: str, name: str, request: Request) -> dict:
    detail = await _svc(request).package_detail(source, name)
    if not detail:
        raise HTTPException(404, f"not indexed: {source}:{name}")
    return detail


@router.get("/feed/changes")
async def change_feed(request: Request, limit: int = 25) -> list[dict]:
    """
    Registry-wide capability changes, rug-pull candidates first.

    This is the front page and the reason to come back — a directory is checked
    once, a change feed is checked weekly.
    """
    return await _svc(request).db.recent_escalations(min(limit, 100))


@router.post("/packages/{source}/{name:path}/watch")
async def watch(source: str, name: str, body: WatchIn, request: Request) -> dict:
    svc = _svc(request)
    pkg = await svc.db.get_package(source, name)
    if not pkg:
        raise HTTPException(404, f"not indexed: {source}:{name}")
    watch_id = await svc.db.add_watch(pkg["id"], body.subscriber, body.pinned_version)
    return {"watch_id": watch_id, "package": name, "pinned_version": body.pinned_version}


@router.get("/alerts/{subscriber}")
async def alerts(subscriber: str, request: Request, limit: int = 50) -> list[dict]:
    return await _svc(request).db.alerts_for(subscriber, limit)


@router.get("/badge/{source}/{name:path}")
async def badge(source: str, name: str, request: Request) -> Response:
    """
    An SVG badge for a package README.

    Distribution mechanic, not decoration: every badge is a maintainer linking
    back, which is how a registry gets discovered without paying for traffic.
    """
    pkg = await _svc(request).db.get_package(source, name)
    grade = (pkg or {}).get("grade") or "?"
    colour = {
        "A": "#22c55e", "B": "#84cc16", "C": "#eab308",
        "D": "#f97316", "F": "#ef4444",
    }.get(grade, "#6b7280")

    label, value = "sigil", grade
    lw, vw = 44, 26
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{lw + vw}" height="20" role="img" aria-label="{label}: {value}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="{lw + vw}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="20" fill="#333"/>
    <rect x="{lw}" width="{vw}" height="20" fill="{colour}"/>
    <rect width="{lw + vw}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11">
    <text x="{lw / 2}" y="14">{label}</text>
    <text x="{lw + vw / 2}" y="14">{value}</text>
  </g>
</svg>"""
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "max-age=300"},
    )
