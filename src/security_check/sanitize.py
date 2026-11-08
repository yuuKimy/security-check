from __future__ import annotations

import re

_USERINFO = re.compile(r"://[^/\s:@]+:[^/\s@]+@")
_TOKENS = (
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
    re.compile(r"ghp_[A-Za-z0-9]+"),
    re.compile(r"sk-[A-Za-z0-9]+"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE),
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def sanitize_text(value: str) -> str:
    cleaned = _USERINFO.sub("://***@", value)
    for pattern in _TOKENS:
        cleaned = pattern.sub("***", cleaned)
    return _EMAIL.sub("***", cleaned)


def shorten(value: str, limit: int) -> str:
    cleaned = sanitize_text(value).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"
