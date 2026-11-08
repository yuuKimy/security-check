import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

from security_check.models import FeedState, Finding, HistoryResult, InboxResult, LockfileScan
from security_check.paths import Locations
from security_check.report import render_report
from security_check.run import execute, run
from security_check.schedule import render_plist


class FakeScanner:
    def __init__(self, outcome: LockfileScan) -> None:
        self.outcome = outcome
        self.calls = 0

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return "osv-scanner test"

    def scan_lockfile(self, lockfile: Path, timeout: float) -> LockfileScan:
        self.calls += 1
        return self.outcome


def test_report_puts_counts_before_scope() -> None:
    finding = _finding()
    text = render_report(
        when="2026-11-08 09:00",
        projects=[],
        findings=[finding],
        baseline_ids=None,
        active_ignores=[],
        invalid_ignores=[],
        history=HistoryResult(),
        inbox=InboxResult(),
        scanner_version="osv-scanner test",
        success=True,
        failure_reason=None,
        today=datetime(2026, 11, 8, tzinfo=UTC).date(),
    )

    assert text.index("新規 Critical 1、High 0") < text.index("## 新規")
    assert text.index("## 新規") < text.index("## この検査の範囲")
    assert text.index("## この検査の範囲") < text.index("## 閲覧ホスト")
    assert text.index("## 閲覧ホスト") < text.index("## ダウンロード")
    assert 'security-check ignore GHSA-0000-0000-0000 --reason "理由"' in text
    assert "経路: なし" in text


def test_run_writes_private_report_and_diff(tmp_path: Path) -> None:
    locations = _locations(tmp_path)
    project = tmp_path / "app"
    project.mkdir()
    (project / "uv.lock").write_text("lock", encoding="utf-8")
    _manifest(locations, project)
    scanner = FakeScanner(LockfileScan(findings=[_finding()], package_count=4))
    moment = datetime(2026, 11, 8, 9, 0, tzinfo=UTC)

    assert execute(locations, scanner=scanner, now=moment, home=tmp_path, history_reader=_no_history, notify=False) == 0

    latest = locations.latest_report.read_text(encoding="utf-8")
    assert "初回のため" in latest
    assert "### Critical  GHSA-0000-0000-0000  urllib3 1.26.5" in latest
    assert stat.S_IMODE(locations.latest_report.stat().st_mode) == 0o600
    assert stat.S_IMODE(locations.dashboard_path.stat().st_mode) == 0o600
    assert "新規 Critical" in locations.dashboard_path.read_text(encoding="utf-8")
    assert locations.normalized_path.is_file()
    assert "SecurityCheck" not in str(locations.normalized_path.parent.name)

    scanner.outcome = LockfileScan(findings=[_finding()], package_count=4)
    later = moment + timedelta(days=7)
    assert execute(locations, scanner=scanner, now=later, home=tmp_path, history_reader=_no_history, notify=False) == 0
    second = locations.latest_report.read_text(encoding="utf-8")
    assert "継続 Critical 1、High 0" in second
    assert "## 継続\n### Critical" in second

    scanner.outcome = LockfileScan(package_count=4)
    resolved_at = later + timedelta(days=7)
    assert (
        execute(locations, scanner=scanner, now=resolved_at, home=tmp_path, history_reader=_no_history, notify=False)
        == 0
    )
    assert "- GHSA-0000-0000-0000" in locations.latest_report.read_text(encoding="utf-8")


def test_failed_scan_does_not_move_the_seven_day_gate(tmp_path: Path) -> None:
    locations = _locations(tmp_path)
    project = tmp_path / "app"
    project.mkdir()
    (project / "uv.lock").write_text("lock", encoding="utf-8")
    _manifest(locations, project)
    moment = datetime(2026, 11, 8, 9, 0, tzinfo=UTC)
    scanner = FakeScanner(LockfileScan(findings=[_finding()], package_count=1))
    execute(locations, scanner=scanner, now=moment, home=tmp_path, history_reader=_no_history, notify=False)
    before = json.loads(locations.baseline_path.read_text(encoding="utf-8"))["at"]

    scanner.outcome = LockfileScan(error="解釈できない出力: {}")
    failed = moment + timedelta(days=8)
    assert execute(locations, scanner=scanner, now=failed, home=tmp_path, history_reader=_no_history, notify=False) == 1
    assert json.loads(locations.baseline_path.read_text(encoding="utf-8"))["at"] == before
    assert "未完了" in locations.latest_report.read_text(encoding="utf-8")
    before_report = locations.latest_report.read_text(encoding="utf-8")
    feed_calls: list[datetime] = []

    def refresher(locations, moment):
        feed_calls.append(moment)
        return FeedState()

    assert (
        run(
            locations,
            scheduled=True,
            scanner=scanner,
            now=moment + timedelta(days=3),
            home=tmp_path,
            history_reader=_no_history,
            notify=False,
            feed_refresher=refresher,
        )
        == 0
    )
    assert scanner.calls == 2
    assert len(feed_calls) == 1
    assert locations.latest_report.read_text(encoding="utf-8") == before_report


def test_plist_runs_at_nine_with_homebrew_path() -> None:
    text = render_plist(Path("/tmp/security-check"), Path("/tmp/security-check.log"))

    assert "<integer>9</integer>" in text
    assert "/opt/homebrew/bin:/usr/local/bin" in text
    assert "--scheduled" in text


def _finding() -> Finding:
    return Finding(
        advisory_id="GHSA-0000-0000-0000",
        package="urllib3",
        version="1.26.5",
        fixed="1.26.18",
        severity="Critical",
        summary="example",
        ecosystem="PyPI",
        project="",
        lockfile="",
        dependency_path="",
    )


def _locations(root: Path) -> Locations:
    return Locations(
        home_dir=root / "SecurityCheck",
        support_dir=root / "Library" / "Application Support" / "security-check",
        log_file=root / "Library" / "Logs" / "security-check" / "security-check.log",
    )


def _manifest(locations: Locations, project: Path) -> None:
    locations.home_dir.mkdir(parents=True)
    locations.manifest_path.write_text(
        json.dumps({"projects": [{"name": "app", "path": str(project)}]}),
        encoding="utf-8",
    )


def _no_history(now: datetime, home: Path) -> HistoryResult:
    return HistoryResult()
