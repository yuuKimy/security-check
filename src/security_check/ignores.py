from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from security_check.models import IgnoreEntry
from security_check.paths import write_private_text


def load_ignores(path: Path) -> tuple[list[IgnoreEntry], list[str]]:
    if not path.is_file():
        return [], []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], ["ignores.json を解釈できない"]
    entries = raw if isinstance(raw, list) else None
    if entries is None:
        return [], ["ignores.json を解釈できない"]
    valid: list[IgnoreEntry] = []
    invalid: list[str] = []
    for item in entries:
        if not isinstance(item, dict):
            invalid.append("理由または期限が無い項目")
            continue
        advisory_id = item.get("id")
        reason = item.get("reason")
        until = item.get("until")
        if not isinstance(advisory_id, str) or not advisory_id.strip():
            invalid.append("理由または期限が無い項目")
            continue
        if not isinstance(reason, str) or not reason.strip() or not isinstance(until, str):
            invalid.append(f"{advisory_id.strip()}: 理由または期限が無い")
            continue
        try:
            date.fromisoformat(until)
        except ValueError:
            invalid.append(f"{advisory_id.strip()}: 期限の形式が違う")
            continue
        valid.append(IgnoreEntry(advisory_id=advisory_id.strip(), reason=reason.strip(), until=until))
    return valid, invalid


def active_ids(entries: list[IgnoreEntry], today: date) -> set[str]:
    active: set[str] = set()
    for entry in entries:
        if date.fromisoformat(entry.until) >= today:
            active.add(entry.advisory_id)
    return active


def write_ignore(path: Path, advisory_id: str, reason: str, until: str) -> None:
    cleaned_id = advisory_id.strip()
    cleaned_reason = reason.strip()
    if not cleaned_id or not cleaned_reason:
        raise ValueError("ID と理由が必要です")
    try:
        date.fromisoformat(until)
    except ValueError as error:
        raise ValueError("期限は YYYY-MM-DD で指定してください") from error
    entries, invalid = load_ignores(path)
    if invalid and path.is_file():
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError("ignores.json を解釈できない") from error
    kept = [entry for entry in entries if entry.advisory_id != cleaned_id]
    kept.append(IgnoreEntry(cleaned_id, cleaned_reason, until))
    payload = [{"id": entry.advisory_id, "reason": entry.reason, "until": entry.until} for entry in kept]
    write_private_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
