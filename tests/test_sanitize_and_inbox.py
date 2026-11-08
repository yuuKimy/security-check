from datetime import date

from security_check.ignores import active_ids, load_ignores, write_ignore
from security_check.inbox import parse_inbox
from security_check.models import IgnoreEntry
from security_check.sanitize import sanitize_text


def test_sanitize_masks_tokens_userinfo_and_email() -> None:
    raw = "https://user:ghp_abcdefghijklmnopqrst@github.com mail a@example.com sk-abc123"

    cleaned = sanitize_text(raw)

    assert "ghp_" not in cleaned
    assert "sk-abc123" not in cleaned
    assert "a@example.com" not in cleaned
    assert "://***@" in cleaned


def test_inbox_hides_query_and_marks_http() -> None:
    result = parse_inbox("- http://203.0.113.5/path?token=abc と https://xn--example-test.com/a\n")

    assert result.items[0].flags == ["http", "生IP", "クエリに秘密らしい名前", "Punycode"]
    assert result.items[0].urls[0] == "http://203.0.113.5/path"
    assert "token=" not in result.items[0].text


def test_ignore_expires(tmp_path) -> None:
    path = tmp_path / "ignores.json"
    write_ignore(path, "GHSA-0000-0000-0000", "dev only", "2026-11-01")
    write_ignore(path, "GHSA-1111-1111-1111", "waiting", "2026-12-01")

    entries, invalid = load_ignores(path)

    assert invalid == []
    assert active_ids(entries, date(2026, 11, 8)) == {"GHSA-1111-1111-1111"}
    assert entries[0] == IgnoreEntry("GHSA-0000-0000-0000", "dev only", "2026-11-01")
