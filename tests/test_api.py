"""End-to-end API and ingest-safety tests."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("SIGIL_FIXTURES", str(FIXTURES))
    monkeypatch.delenv("SIGIL_ADMIN_TOKEN", raising=False)

    import sigil.config as config

    config.settings = config.Settings()
    import sigil.main as main
    import sigil.routes.admin as admin_routes

    admin_routes.settings = config.settings
    main.settings = config.settings

    with TestClient(main.create_app()) as c:
        yield c


def _ingest(client, rel: str):
    return client.post(
        "/api/admin/ingest/local",
        json={"path": str(FIXTURES / rel), "source": "npm"},
    )


# ---------------------------------------------------------------------------
# Ingest and scoring through the API
# ---------------------------------------------------------------------------


def test_health(client):
    body = client.get("/api/admin/health").json()
    assert body["status"] == "ok"
    assert body["packages"] == 0


def test_ingest_clean_package_scores_well(client):
    res = _ingest(client, "weather-mcp/2.1.0")
    assert res.status_code == 200
    body = res.json()
    assert body["grade"] == "A"
    assert body["verdict"] == "trusted"
    assert body["findings"] == 0


def test_ingest_rejects_missing_path(client):
    res = client.post("/api/admin/ingest/local", json={"path": str(ROOT / "nope")})
    assert res.status_code == 400


def test_sequential_ingest_produces_a_diff_and_flags_the_rug_pull(client):
    """The product thesis, end to end."""
    first = _ingest(client, "notes-mcp/1.0.0").json()
    assert first["verdict"] == "trusted"
    assert first["diff"] is None          # nothing to compare against yet

    second = _ingest(client, "notes-mcp/1.1.0").json()
    assert second["verdict"] == "do-not-install"
    assert second["rug_pull"] is True
    assert second["diff"] is not None
    assert len(second["diff"]["changes"]) > 5


def test_package_detail_exposes_evidence(client):
    _ingest(client, "notes-mcp/1.1.0")
    detail = client.get("/api/packages/npm/notes-mcp").json()

    assert detail["latest_version"] == "1.1.0"
    assert detail["score"]["verdict"] == "do-not-install"
    assert detail["score"]["reasons"]

    findings = detail["findings"]
    assert findings
    for f in findings:
        assert f["evidence"], "the UI must never show a finding without evidence"


def test_unknown_package_is_404(client):
    assert client.get("/api/packages/npm/does-not-exist").status_code == 404


def test_search_and_ranking(client):
    _ingest(client, "weather-mcp/2.1.0")
    _ingest(client, "filesys-mcp/0.3.0")

    everything = client.get("/api/packages").json()
    assert len(everything) == 2
    # Best score first — the registry's job is to make the safe choice obvious
    assert everything[0]["name"] == "weather-mcp"

    assert len(client.get("/api/packages?q=weather").json()) == 1
    assert len(client.get("/api/packages?min_score=90").json()) == 1


def test_change_feed_puts_rug_pulls_first(client):
    _ingest(client, "notes-mcp/1.0.0")
    _ingest(client, "notes-mcp/1.1.0")
    feed = client.get("/api/feed/changes").json()
    assert feed and feed[0]["rug_pull"] is True


# ---------------------------------------------------------------------------
# Watches and alerts — the monetised surface
# ---------------------------------------------------------------------------


def test_watching_a_package_generates_an_alert_on_the_next_change(client):
    _ingest(client, "notes-mcp/1.0.0")

    watch = client.post(
        "/api/packages/npm/notes-mcp/watch",
        json={"subscriber": "diya@example.com", "pinned_version": "1.0.0"},
    )
    assert watch.status_code == 200

    assert client.get("/api/alerts/diya@example.com").json() == []

    _ingest(client, "notes-mcp/1.1.0")

    alerts = client.get("/api/alerts/diya@example.com").json()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert "1.0.0" in alerts[0]["message"] and "1.1.0" in alerts[0]["message"]


def test_watch_on_unknown_package_is_404(client):
    res = client.post(
        "/api/packages/npm/nope/watch", json={"subscriber": "a@b.c"}
    )
    assert res.status_code == 404


def test_badge_renders_svg_with_the_grade(client):
    _ingest(client, "weather-mcp/2.1.0")
    res = client.get("/api/badge/npm/weather-mcp")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("image/svg+xml")
    assert ">A<" in res.text


def test_badge_for_unknown_package_shows_a_question_mark(client):
    res = client.get("/api/badge/npm/unknown-thing")
    assert res.status_code == 200
    assert ">?<" in res.text


# ---------------------------------------------------------------------------
# Admin auth
# ---------------------------------------------------------------------------


def test_admin_token_gates_ingest_but_not_public_reads(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_DB", str(tmp_path / "auth.db"))
    monkeypatch.setenv("SIGIL_ADMIN_TOKEN", "s3cret")

    import sigil.config as config

    config.settings = config.Settings()
    import sigil.main as main
    import sigil.routes.admin as admin_routes

    admin_routes.settings = config.settings
    main.settings = config.settings

    with TestClient(main.create_app()) as c:
        assert c.post("/api/admin/ingest/local", json={"path": "."}).status_code == 401
        assert c.get("/api/packages").status_code == 200      # public stays public
        ok = c.post(
            "/api/admin/ingest/local",
            json={"path": str(FIXTURES / "weather-mcp/2.1.0"), "source": "npm"},
            headers={"Authorization": "Bearer s3cret"},
        )
        assert ok.status_code == 200


# ---------------------------------------------------------------------------
# Hostile archives are an expected input, not an edge case
# ---------------------------------------------------------------------------


def _tar_with(name: str, data: bytes = b"x") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_tarball_escaping_its_root_is_refused(tmp_path):
    from sigil.ingest.npm import IngestError, _safe_extract

    with pytest.raises(IngestError, match="escapes"):
        _safe_extract(_tar_with("../../evil.js"), tmp_path)


def test_absolute_path_in_tarball_is_refused(tmp_path):
    from sigil.ingest.npm import IngestError, _safe_extract

    with pytest.raises(IngestError, match="escapes"):
        _safe_extract(_tar_with("/tmp/evil.js"), tmp_path)


def test_oversized_archive_is_refused(tmp_path, monkeypatch):
    import sigil.ingest.npm as npm

    monkeypatch.setattr(npm, "MAX_UNPACKED_BYTES", 10)
    with pytest.raises(npm.IngestError, match="size limit"):
        npm._safe_extract(_tar_with("pkg/big.js", b"y" * 500), tmp_path)


def test_normal_tarball_extracts(tmp_path):
    from sigil.ingest.npm import _safe_extract

    _safe_extract(_tar_with("package/index.js", b"console.log(1)"), tmp_path)
    assert (tmp_path / "package" / "index.js").read_bytes() == b"console.log(1)"
