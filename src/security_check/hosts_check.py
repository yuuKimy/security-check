from __future__ import annotations

import ipaddress
import re
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlparse

from security_check.models import DownloadResult, HostRecord
from security_check.paths import write_private_text

LEGITIMATE_TEMPLATE = """# なりすましの基準にするホスト名を、1行に1件書く。# で始まる行はコメントで、照合には使わない
# github.com
"""
TEMPORARY_SUFFIXES = (
    "ngrok.io",
    "ngrok.app",
    "ngrok.dev",
    "ngrok-free.app",
    "ngrok-free.dev",
    "trycloudflare.com",
    "duckdns.org",
    "nip.io",
    "sslip.io",
    "localtunnel.me",
    "loca.lt",
    "serveo.net",
    "localhost.run",
)
MULTI_SUFFIXES = {
    ("co", "jp"),
    ("or", "jp"),
    ("ne", "jp"),
    ("ac", "jp"),
    ("go", "jp"),
    ("ed", "jp"),
    ("lg", "jp"),
    ("co", "uk"),
    ("org", "uk"),
    ("ac", "uk"),
    ("gov", "uk"),
    ("com", "au"),
    ("net", "au"),
    ("org", "au"),
    ("co", "nz"),
    ("com", "br"),
    ("co", "kr"),
    ("co", "in"),
    ("com", "tw"),
    ("co", "za"),
    ("com", "mx"),
    ("co", "id"),
    ("com", "sg"),
    ("com", "hk"),
    ("co", "th"),
}
MARK_FIELDS = (
    ("http", "http"),
    ("ip", "生IP"),
    ("punycode", "Punycode"),
    ("lookalike", "なりすまし"),
    ("temporary", "一時名"),
    ("malware", "マルウェア配布"),
    ("phishing", "フィッシング"),
)
ALLOWED_MARKS = {label for _, label in MARK_FIELDS}
SERIOUS_MARKS = {"なりすまし", "一時名", "マルウェア配布", "フィッシング"}
_HOST = re.compile(r"[a-z0-9.-]+")


def ensure_legitimate_hosts(path: Path) -> None:
    if path.exists():
        return
    write_private_text(path, LEGITIMATE_TEMPLATE)


def load_legitimate_hosts(path: Path) -> tuple[list[str], int]:
    if not path.is_file():
        return [], 0
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return [], 0
    hosts: list[str] = []
    invalid = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        host = normalize_host(stripped)
        if host is None:
            invalid += 1
            continue
        if host not in hosts:
            hosts.append(host)
    return hosts, invalid


def normalize_host(value: str) -> str | None:
    text = value.strip()
    if not text or any(char.isspace() for char in text):
        return None
    if "://" in text:
        host = urlparse(text).hostname
    else:
        host = text.split("/")[0].split("?")[0].split("#")[0]
    if not host:
        return None
    host = host.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not host or host.startswith(".") or ".." in host or not _HOST.fullmatch(host):
        return None
    if _is_ip(host):
        return host
    if "." not in host:
        return None
    return host


def annotate_hosts(hosts: list[HostRecord], legitimate: list[str], matches: dict[str, set[str]]) -> None:
    for host in hosts:
        _apply(host, legitimate, matches)
    hosts.sort(key=lambda item: (not item.flagged(), item.host))


def annotate_downloads(result: DownloadResult, legitimate: list[str], matches: dict[str, set[str]]) -> None:
    for item in result.items:
        marks = host_marks(item.host, http=item.http, legitimate=legitimate, matches=matches)
        if item.redirect_host:
            for mark in host_marks(item.redirect_host, http=item.redirect_http, legitimate=legitimate, matches=matches):
                if mark not in marks:
                    marks.append(mark)
        item.marks = marks


def labels_for(host: HostRecord) -> list[str]:
    values = {
        "http": host.http,
        "ip": host.ip,
        "punycode": host.punycode,
        "lookalike": host.lookalike,
        "temporary": host.temporary,
        "malware": host.malware,
        "phishing": host.phishing,
    }
    return [label for field, label in MARK_FIELDS if values[field]]


def without_ignored(host: HostRecord, ignored: set[tuple[str, str]]) -> HostRecord:
    cleared = {field: False for field, label in MARK_FIELDS if (host.host, label) in ignored and getattr(host, field)}
    if not cleared:
        return host
    return replace(host, **cleared)


def host_marks(host: str, *, http: bool, legitimate: list[str], matches: dict[str, set[str]]) -> list[str]:
    marks: list[str] = []
    if http:
        marks.append("http")
    if not host:
        return marks
    if _is_ip(host):
        marks.append("生IP")
    if "xn--" in host:
        marks.append("Punycode")
    if is_temporary(host):
        marks.append("一時名")
    if legitimate and is_lookalike(host, legitimate):
        marks.append("なりすまし")
    sources = matches.get(host, set())
    if "urlhaus" in sources:
        marks.append("マルウェア配布")
    if "openphish" in sources:
        marks.append("フィッシング")
    return marks


def is_temporary(host: str) -> bool:
    name = host.lower().rstrip(".")
    return any(name == suffix or name.endswith(f".{suffix}") for suffix in TEMPORARY_SUFFIXES)


def is_lookalike(host: str, legitimate: list[str]) -> bool:
    current = split_registrable(host)
    if current is None:
        return False
    normalized = host.lower().rstrip(".")
    listed = [item.lower().rstrip(".") for item in legitimate]
    if any(normalized == item or normalized.endswith(f".{item}") for item in listed):
        return False
    label, suffix = current
    families = [item for item in (split_registrable(entry) for entry in listed) if item is not None]
    if any(label == other and suffix == other_suffix for other, other_suffix in families):
        return False
    for other, other_suffix in families:
        if label == other and suffix != other_suffix:
            return True
        if edit_distance_is_one(label, other):
            return True
    return False


def split_registrable(host: str) -> tuple[str, str] | None:
    if _is_ip(host):
        return None
    labels = host.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return None
    if len(labels) > 2 and tuple(labels[-2:]) in MULTI_SUFFIXES:
        return labels[-3], ".".join(labels[-2:])
    return labels[-2], labels[-1]


def edit_distance_is_one(left: str, right: str) -> bool:
    if left == right or abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(char != other for char, other in zip(left, right, strict=True)) == 1
    if len(left) > len(right):
        left, right = right, left
    skips = 0
    index = 0
    for char in right:
        if index < len(left) and left[index] == char:
            index += 1
            continue
        skips += 1
        if skips > 1:
            return False
    return skips == 1 and index == len(left)


def _apply(host: HostRecord, legitimate: list[str], matches: dict[str, set[str]]) -> None:
    labels = host_marks(host.host, http=host.http, legitimate=legitimate, matches=matches)
    host.ip = "生IP" in labels
    host.punycode = "Punycode" in labels
    host.lookalike = "なりすまし" in labels
    host.temporary = "一時名" in labels
    host.malware = "マルウェア配布" in labels
    host.phishing = "フィッシング" in labels


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
