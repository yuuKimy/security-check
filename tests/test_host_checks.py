import plistlib
import sqlite3
import stat
from datetime import UTC, datetime, timedelta

from security_check.dashboard import render_dashboard
from security_check.downloads import collect_downloads
from security_check.feeds import parse_hostfile, parse_openphish, refresh_feeds, set_urlhaus_key
from security_check.history import CHROME_EPOCH
from security_check.host_ignores import write_host_ignore
from security_check.hosts_check import annotate_hosts, is_lookalike, is_temporary
from security_check.models import DownloadItem, DownloadResult, HistoryResult, HostIgnoreEntry, HostRecord, InboxResult
from security_check.report import render_report
from security_check.run import execute


def test_dashboard_summarizes_severity_without_hostnames() -> None:
    from security_check.models import FeedState, Finding, ProjectScan

    html = render_dashboard(
        when="2026-11-08 09:00",
        projects=[ProjectScan("app", "ok", lockfile_count=1, package_count=4)],
        findings=[
            Finding(
                advisory_id="GHSA-0000-0000-0000",
                package="urllib3",
                version="1.26.5",
                fixed="1.26.18",
                severity="Critical",
                summary="example",
                ecosystem="PyPI",
                project="app",
                lockfile="requirements.txt",
                dependency_path="",
            )
        ],
        baseline_ids=set(),
        active_ignores=[],
        history=HistoryResult(hosts=[HostRecord("evil.example", ["Chrome (Default)"], http=True)]),
        downloads=DownloadResult(),
        feeds=FeedState(),
        scanner_version="osv-scanner test",
        success=True,
        failure_reason=None,
    )

    assert "新規 Critical" in html
    assert "urllib3 1.26.5" in html
    assert "evil.example" not in html
    assert "PyPI" in html


def test_lookalike_and_temporary_names() -> None:
    listed = ["github.com", "www.google.com", "example.co.jp"]

    assert is_lookalike("githud.com", listed)
    assert is_lookalike("example.com", listed)
    assert not is_lookalike("github.com", listed)
    assert not is_lookalike("www.github.com", ["github.com"])
    assert not is_lookalike("other.google.com", listed)
    assert not is_lookalike("gxxhub.com", listed)
    assert not is_lookalike("githud.com", [])
    assert is_temporary("tunnel.trycloudflare.com")
    assert is_temporary("ngrok.io")
    assert not is_temporary("notngrok.io")


def test_feed_keeps_a_week_and_drops_urls_and_keys(tmp_path) -> None:
    from security_check.paths import Locations

    locations = Locations(
        home_dir=tmp_path / "SecurityCheck",
        support_dir=tmp_path / "support",
        log_file=tmp_path / "security-check.log",
    )
    set_urlhaus_key(locations.urlhaus_key_path, "super-secret-key")
    assert stat.S_IMODE(locations.urlhaus_key_path.stat().st_mode) == 0o600
    seen: list[str] = []

    def fetcher(kind: str, key: str) -> str:
        seen.append(kind)
        if kind == "urlhaus":
            assert key == "super-secret-key"
            return "127.0.0.1 malware.example\n"
        return "https://phish.example/path?token=feed-secret\n"

    now = datetime(2026, 11, 8, 9, 0, tzinfo=UTC)
    state = refresh_feeds(locations, now, fetcher=fetcher)
    stored = locations.feed_path.read_text(encoding="utf-8")

    assert seen == ["urlhaus", "openphish"]
    assert state.matches["malware.example"] == {"urlhaus"}
    assert state.matches["phish.example"] == {"openphish"}
    assert "feed-secret" not in stored
    assert "super-secret-key" not in stored
    assert "/path" not in stored

    def failing(kind: str, key: str) -> str:
        if kind == "urlhaus":
            raise RuntimeError("URLhaus の取得に失敗した")
        return "# none\n"

    next_day = refresh_feeds(locations, now + timedelta(days=1), fetcher=failing)
    assert "malware.example" in next_day.matches
    assert next_day.sources[0].status == "failed"
    assert next_day.sources[0].last_success is not None

    aged = refresh_feeds(locations, now + timedelta(days=8), fetcher=failing)
    assert "malware.example" not in aged.matches
    assert "phish.example" not in aged.matches


def test_missing_urlhaus_key_still_reads_openphish(tmp_path) -> None:
    from security_check.paths import Locations

    locations = Locations(tmp_path / "SecurityCheck", tmp_path / "support", tmp_path / "log")
    seen: list[str] = []

    def fetcher(kind: str, key: str) -> str:
        seen.append(kind)
        return "https://phish.example/a\n"

    state = refresh_feeds(locations, datetime(2026, 11, 8, tzinfo=UTC), fetcher=fetcher)

    assert seen == ["openphish"]
    assert state.sources[0].status == "missing_key"
    assert "phish.example" in state.matches


def test_parsers_reject_html() -> None:
    assert parse_hostfile("# comment\n127.0.0.1 evil.example\n") == {"evil.example"}
    assert parse_openphish("https://evil.example/a?token=1\n") == {"evil.example"}
    try:
        parse_openphish("<html>nope</html>")
    except ValueError as error:
        assert "解釈できない" in str(error)
    else:
        raise AssertionError("html を受け入れた")


def test_downloads_keep_basename_and_drop_query(tmp_path) -> None:
    now = datetime(2026, 11, 8, 9, 0, tzinfo=UTC)
    safari = tmp_path / "Library" / "Safari" / "Downloads.plist"
    safari.parent.mkdir(parents=True)
    recent = now - timedelta(days=1)
    old = now - timedelta(days=10)
    with safari.open("wb") as handle:
        plistlib.dump(
            {
                "DownloadHistory": [
                    {
                        "DownloadEntryPath": "/Users/private/secret-folder/notes.pdf",
                        "DownloadEntryURL": "https://docs.example/a?token=safari-secret",
                        "DownloadEntryDateFinishedKey": recent,
                    },
                    {
                        "DownloadEntryPath": "/tmp/old.dmg",
                        "DownloadEntryURL": "https://old.example/old.dmg",
                        "DownloadEntryDateFinishedKey": old,
                    },
                ]
            },
            handle,
        )
    chrome = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
    chrome.mkdir(parents=True)
    (chrome / "Preferences").write_text("{}", encoding="utf-8")
    _chrome_downloads(chrome / "History", now)
    guest = chrome.parent / "Guest Profile"
    guest.mkdir()
    (guest / "Preferences").write_text("{}", encoding="utf-8")
    _chrome_downloads(guest / "History", now, host="guest.example")

    result = collect_downloads(now, tmp_path)
    rendered = " ".join(item.as_dict().values().__repr__() for item in result.items)

    assert any(item.name == "setup.dmg" and item.category == "executable" for item in result.items)
    assert any(item.name == "notes.pdf" and item.host == "docs.example" for item in result.items)
    assert any(item.danger == "警告を通過" and item.incomplete for item in result.items)
    assert all(item.host != "old.example" for item in result.items)
    assert all(item.host != "guest.example" for item in result.items)
    assert all(item.name != "photo.jpg" for item in result.items)
    assert "safari-secret" not in rendered
    assert "secret-folder" not in rendered
    assert "token=" not in rendered


def test_report_hides_ignored_host_mark_and_lists_installer() -> None:
    host = HostRecord("tunnel.trycloudflare.com", ["Chrome (Default)"], temporary=True)
    history = HistoryResult(hosts=[host])
    annotate_hosts(history.hosts, [], {})
    downloads = DownloadResult(
        items=[
            DownloadItem("setup.dmg", "executable", "tunnel.trycloudflare.com", "Chrome (Default)", marks=["一時名"]),
            DownloadItem("notes.pdf", "document", "docs.example", "Chrome (Default)"),
        ]
    )
    text = render_report(
        when="2026-11-08 09:00",
        projects=[],
        findings=[],
        baseline_ids=set(),
        active_ignores=[],
        invalid_ignores=[],
        history=history,
        inbox=InboxResult(),
        scanner_version="test",
        success=True,
        failure_reason=None,
        today=datetime(2026, 11, 8, tzinfo=UTC).date(),
        downloads=downloads,
        host_ignores=[HostIgnoreEntry("tunnel.trycloudflare.com", "一時名", "開発", "2026-12-01")],
    )

    host_line = next(line for line in text.splitlines() if line.startswith("- tunnel.trycloudflare.com"))
    assert "一時名" not in host_line
    assert "実行ファイル  `setup.dmg`" in text
    assert "一時名" in text
    assert "目印の無い文書: 1 件" in text
    assert "notes.pdf" not in text


def test_execute_records_feed_match_without_network(tmp_path) -> None:
    from security_check.models import LockfileScan
    from security_check.paths import Locations

    locations = Locations(tmp_path / "SecurityCheck", tmp_path / "support", tmp_path / "log")
    project = tmp_path / "app"
    project.mkdir()
    (project / "uv.lock").write_text("lock", encoding="utf-8")
    locations.home_dir.mkdir(parents=True)
    locations.manifest_path.write_text('{"projects":[]}\n', encoding="utf-8")
    (locations.home_dir / "legitimate-hosts.txt").write_text("github.com\n", encoding="utf-8")

    def refresher(locations, now):
        from security_check.models import FeedSourceState, FeedState

        return FeedState(
            sources=[FeedSourceState("URLhaus", "ok", "2026-11-08T09:00:00+00:00")],
            matches={"phish.example": {"openphish"}},
        )

    def history(now, home):
        return HistoryResult(hosts=[HostRecord("phish.example", ["Chrome (Default)"])])

    class Scanner:
        def available(self) -> bool:
            return True

        def version(self) -> str:
            return "test"

        def scan_lockfile(self, lockfile, timeout) -> LockfileScan:
            return LockfileScan()

    assert (
        execute(
            locations,
            scanner=Scanner(),
            now=datetime(2026, 11, 8, 9, tzinfo=UTC),
            home=tmp_path,
            history_reader=history,
            notify=False,
            feed_refresher=refresher,
            download_reader=lambda now, home: DownloadResult(),
        )
        == 0
    )
    text = locations.latest_report.read_text(encoding="utf-8")
    assert "フィッシング" in text
    assert "phish.example" in text
    normalized = (tmp_path / "support" / "normalized.json").read_text(encoding="utf-8")
    assert "phish.example" in normalized


def test_ignore_host_command_normalizes_and_replaces(tmp_path) -> None:
    path = tmp_path / "host-ignores.json"
    write_host_ignore(path, "Tunnel.TryCloudflare.com", "一時名", "開発", "2026-12-01")
    write_host_ignore(path, "tunnel.trycloudflare.com", "一時名", "まだ使う", "2026-12-15")
    text = path.read_text(encoding="utf-8")
    assert text.count("一時名") == 1
    assert "まだ使う" in text


def _chrome_downloads(path, now: datetime, host: str = "files.example") -> None:
    recent = int((now - timedelta(hours=1) - CHROME_EPOCH).total_seconds() * 1_000_000)
    with sqlite3.connect(path) as database:
        database.execute(
            """
            CREATE TABLE downloads (
                id INTEGER, target_path TEXT, current_path TEXT, start_time INTEGER,
                state INTEGER, danger_type INTEGER, opened INTEGER, mime_type TEXT
            )
            """
        )
        database.execute("CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT)")
        database.execute(
            "INSERT INTO downloads VALUES (1, ?, '', ?, 1, 0, 0, 'application/octet-stream')",
            ("/Users/private/secret-folder/setup.dmg?token=chrome-secret", recent),
        )
        database.execute(
            "INSERT INTO downloads_url_chains VALUES (1, 0, ?)",
            ("https://phish.example/start?token=chrome-secret",),
        )
        database.execute(
            "INSERT INTO downloads_url_chains VALUES (1, 1, ?)",
            (f"https://{host}/setup.dmg?token=chrome-secret",),
        )
        database.execute(
            "INSERT INTO downloads VALUES (2, '/tmp/photo.jpg', '', ?, 1, 0, 1, 'image/jpeg')",
            (recent,),
        )
        database.execute("INSERT INTO downloads_url_chains VALUES (2, 0, 'https://images.example/photo.jpg')")
        database.execute(
            "INSERT INTO downloads VALUES (3, '/tmp/warn.exe', '', ?, 2, 6, 0, 'application/octet-stream')",
            (recent,),
        )
        database.execute("INSERT INTO downloads_url_chains VALUES (3, 0, 'http://warn.example/warn.exe')")
