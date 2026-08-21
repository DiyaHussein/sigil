"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse

from .analysis.scanner import Scanner
from .config import ROOT, settings
from .db import Database
from .routes import admin, registry
from .service import RegistryService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("sigil")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = Database(settings.db_path)
    await db.init()
    app.state.service = RegistryService(db, Scanner(settings.report_threshold))
    stats = await db.stats()
    log.info(
        "sigil up - %d packages, %d versions, %d findings, threshold %.2f",
        stats["packages"], stats["versions"], stats["findings"],
        settings.report_threshold,
    )
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sigil",
        description="A trust registry for MCP servers and agents.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(registry.router)
    app.include_router(admin.router)

    web = ROOT / "web"

    @app.get("/", include_in_schema=False)
    async def index():
        return RedirectResponse("/app/")

    # The registry UI is one self-contained file, so it is served directly
    # rather than through a StaticFiles mount. A mount is registered before
    # these routes and would 404 on deep links like /app/p/npm/notes-mcp
    # before the SPA ever loaded.
    @app.get("/app", include_in_schema=False)
    @app.get("/app/{path:path}", include_in_schema=False)
    async def spa(path: str = ""):
        index_html = web / "index.html"
        if not index_html.exists():
            return RedirectResponse("/docs")
        return FileResponse(index_html, media_type="text/html")

    return app


app = create_app()
