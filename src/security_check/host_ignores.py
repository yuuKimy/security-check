from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from security_check.hosts_check import ALLOWED_MARKS, normalize_host
from security_check.models import HostIgnoreEntry
from security_check.paths import write_private_text


def load_host_ignores(path: Path) -> tuple[list[HostIgnoreEntry], list[str]]:
    if not path.is_file():
        return [], []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], ["host-ignores.json を解釈できない"]
    if not isinstance(raw, list):
        return [], ["host-ignores.json を解釈できない"]
    valid: list[HostIgnoreEntry] = []
    invalid: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            invalid.append("理由または期限が無い項目")
            continue
        host = item.get("host")
        mark = item.get("mark")
        reason = item.get("reason")
        until = item.get("until")
        if not all(isinstance(value, str) for value in (host, mark, reason, until)):
            invalid.append("理由または期限が無い項目")
            continue
        normalized = normalize_host(host)
        if normalized is None or mark not in ALLOWED_MARKS or not reason.strip():
            invalid.append("ホストの ignore を解釈できない")
            continue
        try:
            date.fromisoformat(until)
        except ValueError:
            invalid.append(f"{normalized}: 期限の形式が違う")
            continue
        valid.append(HostIgnoreEntry(normalized, mark, reason.strip(), until))
    return valid, invalid


def write_host_ignore(path: Path, host: str, mark: str, reason: str, until: str) -> None:
    normalized = normalize_host(host)
    cleaned_reason = reason.strip()
    if normalized is None:
        raise ValueError("ホスト名の形式が違います")
    if mark not in ALLOWED_MARKS:
        raise ValueError("目印の種類が違います")
    if not cleaned_reason:
        raise ValueError("理由が必要です")
    try:
        date.fromisoformat(until)
    except ValueError as error:
        raise ValueError("期限は YYYY-MM-DD で指定してください") from error
    entries, invalid = load_host_ignores(path)
    if invalid and path.is_file():
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError("host-ignores.json を解釈できない") from error
    kept = [entry for entry in entries if not (entry.host == normalized and entry.mark == mark)]
    kept.append(HostIgnoreEntry(normalized, mark, cleaned_reason, until))
    payload = [{"host": entry.host, "mark": entry.mark, "reason": entry.reason, "until": entry.until} for entry in kept]
    write_private_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
