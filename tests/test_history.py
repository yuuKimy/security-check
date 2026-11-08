import sqlite3
from datetime import UTC, datetime

from security_check.history import CHROME_EPOCH, SAFARI_EPOCH, collect_history


def test_collect_history_keeps_hosts_and_drops_paths(tmp_path) -> None:
    now = datetime(2026, 11, 8, 9, 0, tzinfo=UTC)
    safari = tmp_path / "Library" / "Safari" / "History.db"
    safari.parent.mkdir(parents=True)
    chrome = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "Profile 1"
    chrome.mkdir(parents=True)
    (chrome / "Preferences").write_text("{}", encoding="utf-8")
    _safari(safari, now)
    _chrome(chrome / "History", now)
    guest = chrome.parent / "Guest Profile"
    guest.mkdir()
    (guest / "Preferences").write_text("{}", encoding="utf-8")
    _chrome(guest / "History", now)

    result = collect_history(now, tmp_path)
    hosts = {host.host: host for host in result.hosts}

    assert "example.com" in hosts
    assert hosts["example.com"].http is True
    assert "203.0.113.10" in hosts
    assert hosts["203.0.113.10"].ip is True
    assert "old.example" not in hosts
    assert "guest.example" not in hosts
    assert all(status.error is None for status in result.statuses)
    assert any(host for host in result.hosts if "Chrome (Profile 1)" in host.sources)


def _safari(path, now: datetime) -> None:
    recent = (now - SAFARI_EPOCH).total_seconds()
    old = recent - 10 * 24 * 60 * 60
    with sqlite3.connect(path) as database:
        database.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT)")
        database.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL)")
        database.execute("INSERT INTO history_items VALUES (1, 'http://example.com/secret?token=1')")
        database.execute("INSERT INTO history_visits VALUES (1, 1, ?)", (recent,))
        database.execute("INSERT INTO history_items VALUES (2, 'https://old.example/a')")
        database.execute("INSERT INTO history_visits VALUES (2, 2, ?)", (old,))


def _chrome(path, now: datetime) -> None:
    recent = (now - CHROME_EPOCH).total_seconds() * 1_000_000
    with sqlite3.connect(path) as database:
        database.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)")
        database.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
        database.execute("INSERT INTO urls VALUES (1, 'https://203.0.113.10/admin')")
        database.execute("INSERT INTO visits VALUES (1, 1, ?)", (int(recent),))
        if path.parent.name == "Guest Profile":
            database.execute("UPDATE urls SET url = 'https://guest.example/secret'")
