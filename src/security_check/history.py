from __future__ import annotations

import ipaddress
import shutil
import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from security_check.models import HistoryResult, HostRecord, SourceStatus

SAFARI_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
WINDOW = timedelta(days=7)


def collect_history(now: datetime, home: Path | None = None) -> HistoryResult:
    root = home or Path.home()
    result = HistoryResult()
    safari = root / "Library" / "Safari" / "History.db"
    result.statuses.append(_read_source(safari, "safari", "Safari", now, result))
    chrome_root = root / "Library" / "Application Support" / "Google" / "Chrome"
    if not chrome_root.is_dir():
        result.statuses.append(SourceStatus("Google Chrome", "履歴ファイルが無い"))
    else:
        profiles = chrome_profiles(chrome_root)
        if not profiles:
            result.statuses.append(SourceStatus("Google Chrome", "通常プロファイルが無い"))
        for name, database in profiles:
            label = f"Chrome ({name})"
            result.statuses.append(_read_source(database, "chrome", label, now, result))
    result.hosts = _merge(result.hosts)
    return result


def chrome_profiles(root: Path) -> list[tuple[str, Path]]:
    profiles: list[tuple[str, Path]] = []
    try:
        children = sorted(root.iterdir())
    except OSError:
        return []
    for child in children:
        if not child.is_dir() or child.name in {"Guest Profile", "System Profile"}:
            continue
        if child.name != "Default" and not child.name.startswith("Profile "):
            continue
        if not (child / "Preferences").exists() and not (child / "History").exists():
            continue
        profiles.append((child.name, child / "History"))
    return profiles


def _read_source(database: Path, kind: str, label: str, now: datetime, result: HistoryResult) -> SourceStatus:
    if not database.is_file():
        return SourceStatus(label, "履歴ファイルが無い")
    try:
        rows = _query(database, kind, now)
    except PermissionError:
        return SourceStatus(label, "フルディスクアクセスが無い、またはファイルを読めない")
    except sqlite3.OperationalError as error:
        if "no such table" in str(error):
            return SourceStatus(label, "履歴の形式を解釈できない")
        return SourceStatus(label, "ファイルを読めない")
    except (OSError, sqlite3.Error):
        return SourceStatus(label, "ファイルを読めない")
    for url in rows:
        host = _host_from_url(url, label)
        if host is not None:
            result.hosts.append(host)
    return SourceStatus(label)


def _query(database: Path, kind: str, now: datetime) -> list[str]:
    aware = now if now.tzinfo else now.astimezone()
    cutoff_at = aware.astimezone(UTC) - WINDOW
    if kind == "safari":
        cutoff = (cutoff_at - SAFARI_EPOCH).total_seconds()
        query = """
            SELECT history_items.url
            FROM history_visits
            JOIN history_items ON history_items.id = history_visits.history_item
            WHERE history_visits.visit_time >= ?
        """
    else:
        cutoff = (cutoff_at - CHROME_EPOCH).total_seconds() * 1_000_000
        query = """
            SELECT urls.url
            FROM visits
            JOIN urls ON urls.id = visits.url
            WHERE visits.visit_time >= ?
        """
    temporary_dir = Path(tempfile.mkdtemp())
    snapshot = temporary_dir / database.name
    try:
        copy_sqlite_database(database, snapshot)
        with sqlite3.connect(f"file:{snapshot}?mode=ro", uri=True) as copied:
            return [row[0] for row in copied.execute(query, (cutoff,)) if isinstance(row[0], str)]
    finally:
        shutil.rmtree(temporary_dir, ignore_errors=True)


def copy_sqlite_database(database: Path, snapshot: Path) -> None:
    shutil.copy2(database, snapshot)
    for suffix in ("-wal", "-shm"):
        companion = Path(f"{database}{suffix}")
        if companion.is_file():
            shutil.copy2(companion, Path(f"{snapshot}{suffix}"))


def _host_from_url(url: str, source: str) -> HostRecord | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return None
    return HostRecord(
        host=host,
        sources=[source],
        http=parsed.scheme == "http",
        ip=_is_ip(host),
        punycode="xn--" in host,
    )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _merge(hosts: list[HostRecord]) -> list[HostRecord]:
    merged: dict[str, HostRecord] = {}
    for host in hosts:
        current = merged.get(host.host)
        if current is None:
            merged[host.host] = HostRecord(
                host=host.host,
                sources=list(host.sources),
                http=host.http,
                ip=host.ip,
                punycode=host.punycode,
            )
            continue
        for source in host.sources:
            if source not in current.sources:
                current.sources.append(source)
        current.http = current.http or host.http
        current.ip = current.ip or host.ip
        current.punycode = current.punycode or host.punycode
        current.lookalike = current.lookalike or host.lookalike
        current.temporary = current.temporary or host.temporary
        current.malware = current.malware or host.malware
        current.phishing = current.phishing or host.phishing
    ordered = list(merged.values())
    ordered.sort(key=lambda item: (not item.flagged(), item.host))
    return ordered
