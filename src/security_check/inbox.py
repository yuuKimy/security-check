from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlunparse

from security_check.models import InboxItem, InboxResult
from security_check.paths import write_private_text
from security_check.sanitize import sanitize_text, shorten

_URL = re.compile(r"https?://[^\s<>)\]]+")
_SECRET_QUERY = {"token", "key", "password", "secret"}
INBOX_TEMPLATE = """# セキュリティメモ

気になった URL やニュースを箇条書きで書く。週次検査は、ここから URL を取り出してレポートに載せる。

-
"""


def ensure_inbox(path: Path) -> None:
    if path.exists():
        return
    write_private_text(path, INBOX_TEMPLATE)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def display_url(url: str) -> tuple[str, list[str]]:
    flags: list[str] = []
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme == "http":
        flags.append("http")
    if host and _is_ip(host):
        flags.append("生IP")
    if "xn--" in host:
        flags.append("Punycode")
    names = {name.lower() for name in parse_qs(parsed.query)}
    if names & _SECRET_QUERY:
        flags.append("クエリに秘密らしい名前")
    cleaned = urlunparse(parsed._replace(query="", fragment=""))
    cleaned = cleaned.removesuffix("?")
    return sanitize_text(cleaned), flags


def parse_inbox(text: str) -> InboxResult:
    items: list[InboxItem] = []
    omitted = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line[2:].strip() if line.startswith(("- ", "* ")) else line
        if not body or body == "-":
            continue
        urls: list[str] = []
        flags: list[str] = []

        def replace(match: re.Match[str], urls: list[str] = urls, flags: list[str] = flags) -> str:
            shown, url_flags = display_url(match.group(0))
            urls.append(shown)
            for flag in url_flags:
                if flag not in flags:
                    flags.append(flag)
            return shown

        visible = _URL.sub(replace, body)
        if len(items) >= 50:
            omitted += 1
            continue
        items.append(InboxItem(text=shorten(visible, 500), urls=urls, flags=flags))
    return InboxResult(items=items, omitted=omitted)


def load_inbox(path: Path) -> InboxResult:
    if not path.is_file():
        return InboxResult()
    return parse_inbox(path.read_text(encoding="utf-8"))
