from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from security_check.models import FeedSourceState, FeedState
from security_check.paths import Locations, write_private_text

MAX_BYTES = 20_000_000
WINDOW_DAYS = 6
_KEY = re.compile(r"^[^\s/?#\\]+$")
_SOURCES = ("urlhaus", "openphish")
_NAMES = {"urlhaus": "URLhaus", "openphish": "OpenPhish"}


def set_urlhaus_key(path: Path, text: str) -> None:
    key = text.strip()
    if not _KEY.fullmatch(key):
        raise ValueError("Auth-Key の形式が違います")
    write_private_text(path, key + "\n")


def refresh_feeds(locations: Locations, now: datetime, fetcher=None) -> FeedState:
    reader = fetcher or _live_fetch
    stored = _load(locations.feed_path)
    today = _date(now)
    observations = _prune(stored.get("observations", []), today)
    sources: list[FeedSourceState] = []
    for kind in _SOURCES:
        meta = stored.get(kind, {})
        if not isinstance(meta, dict):
            meta = {}
        observations, source = _refresh_one(
            kind,
            meta,
            observations,
            today,
            now,
            locations.urlhaus_key_path,
            reader,
        )
        sources.append(source)
        stored[kind] = {"last_success": source.last_success, "last_error": source.error}
    stored["observations"] = observations
    write_private_text(locations.feed_path, json.dumps(stored, ensure_ascii=False, indent=2) + "\n")
    return FeedState(sources=sources, matches=_matches(observations, _skipped(sources)))


def load_feed_state(path: Path, now: datetime) -> FeedState:
    stored = _load(path)
    observations = _prune(stored.get("observations", []), _date(now))
    sources = []
    for kind in _SOURCES:
        meta = stored.get(kind, {})
        if not isinstance(meta, dict):
            meta = {}
        last_success = meta.get("last_success") if isinstance(meta.get("last_success"), str) else None
        error = meta.get("last_error") if isinstance(meta.get("last_error"), str) else None
        if last_success and not error:
            status = "ok"
        elif error == "Auth-Key が無い":
            status = "missing_key"
        elif error:
            status = "failed"
        else:
            status = "never"
        sources.append(FeedSourceState(_NAMES[kind], status, last_success, error))
    return FeedState(sources=sources, matches=_matches(observations, _skipped(sources)))


def source_line(source: FeedSourceState) -> str:
    if source.status == "ok" and source.last_success:
        return f"{source.name}: {source.last_success} に取得"
    if source.status == "missing_key":
        return f"{source.name}: 未実施（Auth-Key が無い）"
    if source.last_success:
        return f"{source.name}: 取得に失敗した。前回の成功は {source.last_success}"
    if source.status == "failed":
        return f"{source.name}: 未実施（取得に失敗した）"
    return f"{source.name}: 未実施"


def format_feed_status(locations: Locations, now: datetime) -> str:
    present = "あり" if _read_key(locations.urlhaus_key_path) else "無し"
    state = load_feed_state(locations.feed_path, now)
    lines = [f"URLhaus のキー: {present}"]
    lines.extend(source_line(source) for source in state.sources)
    return "\n".join(lines)


def parse_hostfile(text: str) -> set[str]:
    if _looks_like_error(text):
        raise ValueError("URLhaus の一覧を解釈できない")
    hosts: set[str] = set()
    payload = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        payload = True
        parts = stripped.split()
        candidate = parts[1] if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1"} else parts[0]
        host = candidate.lower().rstrip(".")
        if host and host not in {"localhost", "0.0.0.0", "127.0.0.1"} and len(host) <= 253:
            hosts.add(host)
    if payload and not hosts:
        raise ValueError("URLhaus の一覧を解釈できない")
    return hosts


def parse_openphish(text: str) -> set[str]:
    if _looks_like_error(text):
        raise ValueError("OpenPhish の一覧を解釈できない")
    hosts: set[str] = set()
    payload = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        payload = True
        parsed = urlparse(stripped)
        if parsed.scheme not in {"http", "https"}:
            continue
        host = (parsed.hostname or "").lower().rstrip(".")
        if host and len(host) <= 253:
            hosts.add(host)
    if payload and not hosts:
        raise ValueError("OpenPhish の一覧を解釈できない")
    return hosts


def _refresh_one(
    kind, meta, observations, today, now, key_path: Path, reader
) -> tuple[list[dict[str, str]], FeedSourceState]:
    last_success = meta.get("last_success") if isinstance(meta.get("last_success"), str) else None
    name = _NAMES[kind]
    if kind == "urlhaus" and not _read_key(key_path):
        return observations, FeedSourceState(name, "missing_key", last_success, "Auth-Key が無い")
    try:
        body = reader(kind, _read_key(key_path) if kind == "urlhaus" else "")
        found = parse_hostfile(body) if kind == "urlhaus" else parse_openphish(body)
    except (OSError, RuntimeError, ValueError, urllib.error.URLError):
        return observations, FeedSourceState(name, "failed", last_success, "取得に失敗した")
    if len(found) > 500_000:
        return observations, FeedSourceState(name, "failed", last_success, "一覧が大きすぎる")
    merged = _replace_source(observations, kind, found, today)
    success = now.isoformat(timespec="seconds")
    return merged, FeedSourceState(name, "ok", success, None)


def _live_fetch(kind: str, key: str) -> str:
    if kind == "urlhaus":
        url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/hostfile.txt"
        failure = "URLhaus の取得に失敗した"
    else:
        url = "https://openphish.com/feed.txt"
        failure = "OpenPhish の取得に失敗した"
    request = urllib.request.Request(url, headers={"User-Agent": "security-check"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read(MAX_BYTES + 1)
    except (OSError, urllib.error.URLError):
        raise RuntimeError(failure) from None
    if len(payload) > MAX_BYTES:
        raise RuntimeError("一覧が大きすぎる")
    return payload.decode("utf-8", errors="replace")


def _looks_like_error(text: str) -> bool:
    sample = text.lstrip()[:800].lower()
    return sample.startswith(("<!doctype html", "<html", "{"))


def _load(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {"observations": []}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"observations": []}
    return raw if isinstance(raw, dict) else {"observations": []}


def _prune(observations: object, today) -> list[dict[str, str]]:
    if not isinstance(observations, list):
        return []
    cutoff = today - timedelta(days=WINDOW_DAYS)
    kept: list[dict[str, str]] = []
    for item in observations:
        if not isinstance(item, dict):
            continue
        host = item.get("host")
        source = item.get("source")
        seen = item.get("seen")
        if not isinstance(host, str) or source not in _SOURCES or not isinstance(seen, str):
            continue
        try:
            seen_on = datetime.fromisoformat(seen).date()
        except ValueError:
            continue
        if seen_on >= cutoff:
            kept.append({"host": host, "source": source, "seen": seen})
    return kept


def _replace_source(observations: list[dict[str, str]], source: str, hosts: set[str], today) -> list[dict[str, str]]:
    kept = [item for item in observations if not (item["source"] == source and item["host"] in hosts)]
    seen = today.isoformat()
    kept.extend({"host": host, "source": source, "seen": seen} for host in sorted(hosts))
    return kept


def _matches(observations: list[dict[str, str]], skip: set[str]) -> dict[str, set[str]]:
    matches: dict[str, set[str]] = {}
    for item in observations:
        if item["source"] in skip:
            continue
        matches.setdefault(item["host"], set()).add(item["source"])
    return matches


def _skipped(sources: list[FeedSourceState]) -> set[str]:
    skipped = set()
    if any(source.name == "URLhaus" and source.status == "missing_key" for source in sources):
        skipped.add("urlhaus")
    return skipped


def _read_key(path: Path) -> str:
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _date(now: datetime):
    aware = now if now.tzinfo else now.astimezone()
    return aware.astimezone().date()
