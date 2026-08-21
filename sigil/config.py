"""Runtime settings, overridable from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class Settings:
    db_path: Path = field(default_factory=lambda: Path(_env("SIGIL_DB", str(ROOT / "sigil.db"))))
    fixtures_dir: Path = field(default_factory=lambda: Path(_env("SIGIL_FIXTURES", str(ROOT / "fixtures"))))
    # Findings below this confidence are never shown. This is the single most
    # important knob in the product: raising it trades recall for credibility.
    report_threshold: float = field(default_factory=lambda: float(_env("SIGIL_REPORT_THRESHOLD", "0.5")))
    admin_token: str = field(default_factory=lambda: _env("SIGIL_ADMIN_TOKEN", ""))
    allow_remote_ingest: bool = field(
        default_factory=lambda: _env("SIGIL_ALLOW_REMOTE_INGEST", "true").lower() == "true"
    )


settings = Settings()
