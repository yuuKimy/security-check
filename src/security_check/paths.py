from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Locations:
    home_dir: Path
    support_dir: Path
    log_file: Path

    @property
    def manifest_path(self) -> Path:
        return self.home_dir / "manifest.json"

    @property
    def inbox_path(self) -> Path:
        return self.home_dir / "inbox.md"

    @property
    def ignores_path(self) -> Path:
        return self.home_dir / "ignores.json"

    @property
    def host_ignores_path(self) -> Path:
        return self.home_dir / "host-ignores.json"

    @property
    def legitimate_hosts_path(self) -> Path:
        return self.home_dir / "legitimate-hosts.txt"

    @property
    def latest_report(self) -> Path:
        return self.home_dir / "latest.md"

    @property
    def dashboard_path(self) -> Path:
        return self.home_dir / "dashboard.html"

    @property
    def reports_dir(self) -> Path:
        return self.home_dir / "reports"

    @property
    def baseline_path(self) -> Path:
        return self.support_dir / "baseline.json"

    @property
    def normalized_path(self) -> Path:
        return self.support_dir / "normalized.json"

    @property
    def notify_state_path(self) -> Path:
        return self.support_dir / "notify-state.json"

    @property
    def feed_path(self) -> Path:
        return self.support_dir / "feed-observations.json"

    @property
    def urlhaus_key_path(self) -> Path:
        return self.support_dir / "urlhaus-auth-key"


def default_locations() -> Locations:
    home = Path.home()
    return Locations(
        home_dir=home / "SecurityCheck",
        support_dir=home / "Library" / "Application Support" / "security-check",
        log_file=home / "Library" / "Logs" / "security-check" / "security-check.log",
    )


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def write_private_text(path: Path, text: str) -> None:
    ensure_private_dir(path.parent)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
