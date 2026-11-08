from __future__ import annotations

import plistlib
import shutil
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from security_check.history import CHROME_EPOCH, WINDOW, chrome_profiles, copy_sqlite_database
from security_check.models import DownloadItem, DownloadResult, SourceStatus
from security_check.sanitize import shorten

EXECUTABLES = {
    ".dmg",
    ".pkg",
    ".mpkg",
    ".exe",
    ".msi",
    ".msix",
    ".app",
    ".apk",
    ".jar",
    ".iso",
    ".bat",
    ".cmd",
    ".ps1",
    ".sh",
    ".command",
    ".scpt",
    ".dll",
    ".so",
    ".dylib",
    ".deb",
    ".rpm",
}
ARCHIVES = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz"}
DOCUMENTS = {
    ".pdf",
    ".doc",
    ".docx",
    ".docm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".rtf",
    ".csv",
    ".odt",
    ".ods",
    ".odp",
}
MIME_CATEGORIES = {
    "application/pdf": "document",
    "application/x-apple-diskimage": "executable",
    "application/zip": "archive",
    "application/gzip": "archive",
    "application/x-gzip": "archive",
    "application/x-7z-compressed": "archive",
    "application/x-rar-compressed": "archive",
    "application/vnd.rar": "archive",
    "application/x-tar": "archive",
    "application/x-bzip2": "archive",
    "application/x-xz": "archive",
    "application/msword": "document",
    "application/vnd.ms-excel": "document",
    "application/vnd.ms-powerpoint": "document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "document",
    "application/rtf": "document",
    "text/csv": "document",
    "application/vnd.oasis.opendocument.text": "document",
    "application/vnd.oasis.opendocument.spreadsheet": "document",
    "application/vnd.oasis.opendocument.presentation": "document",
    "application/x-sh": "executable",
    "application/x-msdos-program": "executable",
    "application/x-msdownload": "executable",
    "application/vnd.microsoft.portable-executable": "executable",
    "application/java-archive": "executable",
    "application/vnd.android.package-archive": "executable",
}
GENERIC_MIME = {"", "application/octet-stream", "binary/octet-stream"}
KNOWN_DANGER = {1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}


def collect_downloads(now: datetime, home: Path | None = None) -> DownloadResult:
    root = home or Path.home()
    result = DownloadResult()
    safari = root / "Library" / "Safari" / "Downloads.plist"
    result.statuses.append(_read_safari(safari, now, result))
    chrome_root = root / "Library" / "Application Support" / "Google" / "Chrome"
    if not chrome_root.is_dir():
        result.statuses.append(SourceStatus("Google Chrome", "履歴ファイルが無い"))
    else:
        profiles = chrome_profiles(chrome_root)
        if not profiles:
            result.statuses.append(SourceStatus("Google Chrome", "通常プロファイルが無い"))
        for name, database in profiles:
            label = f"Chrome ({name})"
            result.statuses.append(_read_chrome(database, label, now, result))
    return result


def classify(name: str, mime: str) -> str | None:
    extension = Path(name).suffix.lower()
    if extension in EXECUTABLES:
        return "executable"
    if extension in ARCHIVES:
        return "archive"
    if extension in DOCUMENTS:
        return "document"
    media = _mime(mime)
    if media.startswith(("image/", "audio/", "video/")):
        return None
    mapped = MIME_CATEGORIES.get(media)
    if mapped:
        return mapped
    if extension:
        return None
    if media in GENERIC_MIME:
        return "unknown"
    return None


def danger_label(value: int) -> str:
    if value == 0:
        return ""
    if value == 6:
        return "警告を通過"
    if value in KNOWN_DANGER:
        return "Chrome が危険側に分類"
    return f"Chrome が危険側に分類（{value}）"


def _read_safari(path: Path, now: datetime, result: DownloadResult) -> SourceStatus:
    if not path.is_file():
        return SourceStatus("Safari", "履歴ファイルが無い")
    try:
        with path.open("rb") as handle:
            payload = plistlib.load(handle)
        entries = payload.get("DownloadHistory") if isinstance(payload, dict) else None
        if not isinstance(entries, list):
            return SourceStatus("Safari", "履歴の形式を解釈できない")
        for entry in entries:
            item = _safari_entry(entry, now)
            if item is not None:
                result.items.append(item)
    except PermissionError:
        return SourceStatus("Safari", "フルディスクアクセスが無い、またはファイルを読めない")
    except (OSError, plistlib.InvalidFileException, ValueError, TypeError):
        return SourceStatus("Safari", "履歴の形式を解釈できない")
    return SourceStatus("Safari")


def _safari_entry(entry: object, now: datetime) -> DownloadItem | None:
    if not isinstance(entry, dict):
        return None
    finished = _as_utc(entry.get("DownloadEntryDateFinishedKey"))
    added = _as_utc(entry.get("DownloadEntryDateAddedKey"))
    moment = finished or added
    if moment is None or moment < _cutoff(now):
        return None
    total = entry.get("DownloadEntryProgressTotalToLoad")
    loaded = entry.get("DownloadEntryProgressBytesSoFar")
    complete = finished is not None or (
        isinstance(total, int) and isinstance(loaded, int) and total > 0 and loaded >= total
    )
    if not complete:
        return None
    path = entry.get("DownloadEntryPath")
    url = entry.get("DownloadEntryURL")
    return _item(
        path if isinstance(path, str) else "",
        url if isinstance(url, str) else "",
        "",
        "Safari",
        "",
        "",
        False,
    )


def _read_chrome(database: Path, label: str, now: datetime, result: DownloadResult) -> SourceStatus:
    if not database.is_file():
        return SourceStatus(label, "履歴ファイルが無い")
    try:
        rows = _chrome_rows(database, now)
    except PermissionError:
        return SourceStatus(label, "フルディスクアクセスが無い、またはファイルを読めない")
    except sqlite3.OperationalError as error:
        if "no such table" in str(error):
            return SourceStatus(label, "履歴の形式を解釈できない")
        return SourceStatus(label, "ファイルを読めない")
    except (OSError, sqlite3.Error):
        return SourceStatus(label, "ファイルを読めない")
    for item in _chrome_items(rows, label):
        result.items.append(item)
    return SourceStatus(label)


def _chrome_rows(database: Path, now: datetime) -> list[tuple]:
    cutoff = int((_cutoff(now) - CHROME_EPOCH).total_seconds() * 1_000_000)
    query = """
        SELECT downloads.id, downloads.target_path, downloads.current_path, downloads.state,
               downloads.danger_type, downloads.opened, downloads.mime_type,
               downloads_url_chains.chain_index, downloads_url_chains.url
        FROM downloads
        LEFT JOIN downloads_url_chains ON downloads_url_chains.id = downloads.id
        WHERE downloads.start_time >= ?
        ORDER BY downloads.id, downloads_url_chains.chain_index
    """
    temporary_dir = Path(tempfile.mkdtemp())
    snapshot = temporary_dir / database.name
    try:
        copy_sqlite_database(database, snapshot)
        with sqlite3.connect(f"file:{snapshot}?mode=ro", uri=True) as copied:
            return list(copied.execute(query, (cutoff,)))
    finally:
        shutil.rmtree(temporary_dir, ignore_errors=True)


def _chrome_items(rows: list[tuple], label: str) -> list[DownloadItem]:
    grouped: dict[int, dict[str, object]] = {}
    order: list[int] = []
    for row in rows:
        identifier, target, current, state, danger, opened, mime, chain, url = row
        slot = grouped.get(identifier)
        if slot is None:
            slot = {
                "target": target if isinstance(target, str) else "",
                "current": current if isinstance(current, str) else "",
                "state": state if isinstance(state, int) else 0,
                "danger": danger if isinstance(danger, int) else 0,
                "opened": opened if isinstance(opened, int) else 0,
                "mime": mime if isinstance(mime, str) else "",
                "urls": [],
            }
            grouped[identifier] = slot
            order.append(identifier)
        if isinstance(chain, int) and isinstance(url, str):
            slot["urls"].append((chain, url))
    items = []
    for identifier in order:
        slot = grouped[identifier]
        urls = sorted(slot["urls"], key=lambda item: item[0])
        final = urls[-1][1] if urls else ""
        first = urls[0][1] if urls else ""
        danger = danger_label(slot["danger"])
        complete = slot["state"] == 1
        if not complete and not danger:
            continue
        item = _item(
            slot["target"] or slot["current"],
            final,
            first,
            label,
            slot["mime"],
            danger,
            not complete,
        )
        if item is None:
            continue
        item.opened = "開封" if slot["opened"] else "未開封"
        items.append(item)
    return items


def _item(
    path: str, final_url: str, first_url: str, source: str, mime: str, danger: str, incomplete: bool
) -> DownloadItem | None:
    name = _basename(path)
    category = classify(name, mime)
    if category is None or (category == "unknown" and incomplete and not danger):
        return None
    host, http = _endpoint(final_url)
    redirect_host, redirect_http = _endpoint(first_url)
    if redirect_host == host:
        redirect_host = ""
        redirect_http = False
    return DownloadItem(
        name=name,
        category=category,
        host=host,
        source=source,
        redirect_host=redirect_host,
        http=http,
        redirect_http=redirect_http,
        danger=danger,
        incomplete=incomplete,
    )


def _basename(path: str) -> str:
    name = Path(path).name if path else ""
    name = name.split("?", 1)[0].split("#", 1)[0]
    return shorten(name, 120) or "名前なし"


def _endpoint(url: str) -> tuple[str, bool]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return "", False
    host = (parsed.hostname or "").lower().rstrip(".")
    return host, parsed.scheme == "http"


def _mime(value: str) -> str:
    return value.split(";", 1)[0].strip().lower()


def _as_utc(value: object) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _cutoff(now: datetime) -> datetime:
    aware = now if now.tzinfo else now.astimezone()
    return aware.astimezone(UTC) - WINDOW
