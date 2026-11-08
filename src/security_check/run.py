from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

from security_check.dashboard import render_dashboard
from security_check.discover import discover
from security_check.downloads import collect_downloads
from security_check.feeds import refresh_feeds
from security_check.history import collect_history
from security_check.host_ignores import load_host_ignores
from security_check.hosts_check import (
    annotate_downloads,
    annotate_hosts,
    ensure_legitimate_hosts,
    load_legitimate_hosts,
)
from security_check.ignores import active_ids, load_ignores
from security_check.inbox import ensure_inbox, load_inbox
from security_check.manifest import ManifestError, is_too_broad, load_manifest
from security_check.models import DownloadResult, FeedSourceState, FeedState, Finding, HistoryResult, ProjectScan
from security_check.paths import Locations, ensure_private_dir, write_private_text
from security_check.report import render_report
from security_check.scan import SCANNER_MISSING, OsvScanner


def run(
    locations: Locations,
    *,
    scheduled: bool = False,
    scanner: OsvScanner | None = None,
    now: datetime | None = None,
    home: Path | None = None,
    history_reader=None,
    notify: bool = True,
    feed_refresher=None,
    download_reader=None,
) -> int:
    moment = now or datetime.now().astimezone()
    refresher = feed_refresher or refresh_feeds
    if scheduled and _succeeded_within(locations.baseline_path, moment):
        _refresh_quietly(locations, moment, refresher)
        _log(locations, "前回の成功から7日未満のため走査しない")
        return 0
    return execute(
        locations,
        scanner=scanner or OsvScanner(),
        now=moment,
        home=home or Path.home(),
        history_reader=history_reader or collect_history,
        notify=notify,
        feed_refresher=refresher,
        download_reader=download_reader or collect_downloads,
    )


def execute(
    locations: Locations,
    *,
    scanner: OsvScanner,
    now: datetime,
    home: Path,
    history_reader,
    notify: bool,
    feed_refresher=None,
    download_reader=None,
) -> int:
    ensure_private_dir(locations.home_dir)
    ensure_inbox(locations.inbox_path)
    context = _collect_context(locations, now, home, history_reader, feed_refresher, download_reader)
    try:
        projects = load_manifest(locations.manifest_path)
    except ManifestError as error:
        _finish(
            locations,
            projects=[],
            findings=[],
            scanner_version="不明",
            success=False,
            failure_reason=str(error),
            now=now,
            notify=notify,
            **context,
        )
        return 1

    scans, findings, reasons, scanner_version = _scan_projects(projects, scanner, home)
    success = not reasons
    reason = "、".join(reasons) if reasons else None
    _finish(
        locations,
        projects=scans,
        findings=findings,
        scanner_version=scanner_version,
        success=success,
        failure_reason=reason,
        now=now,
        notify=notify,
        **context,
    )
    if any(item == SCANNER_MISSING for item in reasons):
        return 2
    return 0 if success else 1


def _scan_projects(projects, scanner: OsvScanner, home: Path):
    scans: list[ProjectScan] = []
    findings: list[Finding] = []
    reasons: list[str] = []
    pending: list[tuple[ProjectScan, object, object]] = []
    for project in projects:
        path = project.path.expanduser()
        if is_too_broad(path, home):
            scans.append(ProjectScan(name=project.name, status="too_broad"))
            _append_reason(reasons, "登録パスが広すぎる")
            continue
        if not path.exists():
            scans.append(ProjectScan(name=project.name, status="missing"))
            continue
        if not path.is_dir():
            scans.append(ProjectScan(name=project.name, status="not_directory"))
            continue
        found = discover(path)
        unpinned = [_relative(path, item) for item in found.unpinned]
        if found.too_many:
            scans.append(ProjectScan(name=project.name, status="too_many", unpinned=unpinned))
            _append_reason(reasons, "lockfile が上限を超えている")
            continue
        scan = ProjectScan(
            name=project.name,
            status="no_lockfile" if not found.lockfiles else "ok",
            lockfile_count=len(found.lockfiles),
            unpinned=unpinned,
        )
        scans.append(scan)
        if found.lockfiles:
            pending.append((scan, path, found.lockfiles))

    version = "不明"
    if pending and not scanner.available():
        _append_reason(reasons, SCANNER_MISSING)
        for scan, _root, _lockfiles in pending:
            scan.lockfile_errors.append(("(全体)", SCANNER_MISSING))
        return scans, findings, reasons, version
    if pending:
        version = scanner.version()
    for scan, root, lockfiles in pending:
        deadline = time.monotonic() + 600
        for lockfile in lockfiles:
            relative = _relative(root, lockfile)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                scan.lockfile_errors.append((relative, "時間内に終わらない"))
                _append_reason(reasons, "スキャナーが時間内に終わらない")
                continue
            outcome = scanner.scan_lockfile(lockfile, remaining)
            if outcome.error:
                scan.lockfile_errors.append((relative, outcome.error))
                _append_reason(reasons, _reason_for(outcome.error))
                continue
            scan.package_count += outcome.package_count
            for finding in outcome.findings:
                finding.project = scan.name
                finding.lockfile = relative
                findings.append(finding)
    return scans, findings, reasons, version


def _collect_context(locations, now, home, history_reader, feed_refresher, download_reader) -> dict[str, object]:
    ensure_legitimate_hosts(locations.legitimate_hosts_path)
    legitimate, invalid_hosts = load_legitimate_hosts(locations.legitimate_hosts_path)
    feeds = _safe_feeds(feed_refresher, locations, now)
    history = _safe_history(history_reader, now, home)
    history.legitimate_empty = not legitimate
    history.legitimate_invalid = invalid_hosts
    annotate_hosts(history.hosts, legitimate, feeds.matches)
    reader = download_reader or collect_downloads
    downloads = _safe_downloads(reader, now, home)
    annotate_downloads(downloads, legitimate, feeds.matches)
    return {"history": history, "downloads": downloads, "feeds": feeds}


def _finish(
    locations,
    *,
    projects,
    findings,
    history,
    downloads,
    feeds,
    scanner_version,
    success,
    failure_reason,
    now,
    notify: bool,
) -> None:
    ignores, invalid_ignores = load_ignores(locations.ignores_path)
    host_ignores, host_ignore_errors = load_host_ignores(locations.host_ignores_path)
    baseline = _load_baseline(locations.baseline_path)
    report = render_report(
        when=now.strftime("%Y-%m-%d %H:%M"),
        projects=projects,
        findings=findings,
        baseline_ids=None if baseline is None else {item.advisory_id for item in baseline},
        active_ignores=[entry for entry in ignores if entry.advisory_id in active_ids(ignores, now.date())],
        invalid_ignores=invalid_ignores,
        history=history,
        inbox=load_inbox(locations.inbox_path),
        scanner_version=scanner_version,
        success=success,
        failure_reason=failure_reason,
        today=now.date(),
        downloads=downloads,
        feeds=feeds,
        host_ignores=host_ignores,
        host_ignore_errors=host_ignore_errors,
    )
    write_private_text(locations.latest_report, report)
    write_private_text(
        locations.dashboard_path,
        render_dashboard(
            when=now.strftime("%Y-%m-%d %H:%M"),
            projects=projects,
            findings=findings,
            baseline_ids=None if baseline is None else {item.advisory_id for item in baseline},
            active_ignores=[entry for entry in ignores if entry.advisory_id in active_ids(ignores, now.date())],
            history=history,
            downloads=downloads,
            feeds=feeds,
            scanner_version=scanner_version,
            success=success,
            failure_reason=failure_reason,
        ),
    )
    write_private_text(locations.reports_dir / now.strftime("%Y%m%d-%H%M.md"), report)
    _write_normalized(locations, now, success, failure_reason, findings, history, downloads, feeds)
    if success:
        _write_baseline(locations, now, findings)
    _notify(locations, success, failure_reason, report, notify)
    _log(locations, "成功" if success else f"失敗: {failure_reason}")


def _write_normalized(
    locations,
    now,
    success,
    failure_reason,
    findings,
    history: HistoryResult,
    downloads: DownloadResult,
    feeds: FeedState,
) -> None:
    payload = {
        "at": now.isoformat(timespec="seconds"),
        "success": success,
        "failure_reason": failure_reason,
        "findings": [finding.as_dict() for finding in findings],
        "hosts": [host.as_dict() for host in history.hosts],
        "downloads": [item.as_dict() for item in downloads.items],
        "feeds": feeds.as_dict(),
    }
    write_private_text(locations.normalized_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def _write_baseline(locations, now, findings: list[Finding]) -> None:
    payload = {"at": now.isoformat(timespec="seconds"), "findings": [finding.as_dict() for finding in findings]}
    write_private_text(locations.baseline_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def _load_baseline(path: Path) -> list[Finding] | None:
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    findings = raw.get("findings") if isinstance(raw, dict) else None
    if not isinstance(findings, list):
        return None
    loaded = []
    for item in findings:
        if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]:
            loaded.append(Finding.from_dict(item))
    return loaded


def _succeeded_within(path: Path, now: datetime) -> bool:
    if not path.is_file():
        return False
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        stamp = datetime.fromisoformat(raw["at"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return False
    if stamp.tzinfo is None:
        stamp = stamp.astimezone()
    elapsed = now - stamp
    return timedelta(0) <= elapsed < timedelta(days=7)


def _safe_feeds(refresher, locations: Locations, now: datetime) -> FeedState:
    if refresher is None:
        return FeedState(
            sources=[
                FeedSourceState("URLhaus", "never"),
                FeedSourceState("OpenPhish", "never"),
            ]
        )
    try:
        return refresher(locations, now)
    except (OSError, RuntimeError, ValueError):
        return FeedState(
            sources=[
                FeedSourceState("URLhaus", "failed", error="取得に失敗した"),
                FeedSourceState("OpenPhish", "failed", error="取得に失敗した"),
            ]
        )


def _safe_downloads(reader, now: datetime, home: Path) -> DownloadResult:
    try:
        return reader(now, home)
    except (OSError, RuntimeError):
        return DownloadResult()


def _refresh_quietly(locations: Locations, now: datetime, refresher) -> None:
    try:
        refresher(locations, now)
    except (OSError, RuntimeError, ValueError) as error:
        _log(locations, f"一覧の取得に失敗した: {error}")


def _safe_history(reader, now: datetime, home: Path) -> HistoryResult:
    try:
        return reader(now, home)
    except (OSError, RuntimeError):
        return HistoryResult(statuses=[])


def _notify(locations: Locations, success: bool, reason: str | None, report: str, enabled: bool) -> None:
    if not enabled:
        return
    state = _load_notify_state(locations.notify_state_path)
    if success:
        glance = next((line for line in report.splitlines() if line.startswith("新規 ")), "検査が完了した")
        _display(f"{glance}。{locations.latest_report}。Cursor で {locations.home_dir} を開く")
        state["last_failure_reason"] = None
    elif reason and state.get("last_failure_reason") != reason:
        _display(f"{reason}。{locations.latest_report}")
        state["last_failure_reason"] = reason
    else:
        return
    write_private_text(locations.notify_state_path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def _load_notify_state(path: Path) -> dict[str, str | None]:
    if not path.is_file():
        return {"last_failure_reason": None}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"last_failure_reason": None}
    if not isinstance(raw, dict):
        return {"last_failure_reason": None}
    reason = raw.get("last_failure_reason")
    return {"last_failure_reason": reason if isinstance(reason, str) else None}


def _display(message: str) -> None:
    import subprocess

    safe = message.replace("\\", "\\\\").replace('"', "'")
    subprocess.run(
        ["osascript", "-e", f'display notification "{safe}" with title "セキュリティチェック"'],
        check=False,
    )


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _reason_for(error: str) -> str:
    if error.startswith("通信に失敗した"):
        return "通信に失敗した"
    if error == "時間内に終わらない":
        return "スキャナーが時間内に終わらない"
    if error.startswith("解釈できない出力"):
        return "lockfile を解釈できない"
    return "スキャナーが異常終了した"


def _relative(root, path: Path) -> str:
    return path.resolve().relative_to(Path(root).resolve()).as_posix()


def _log(locations: Locations, message: str) -> None:
    ensure_private_dir(locations.log_file.parent)
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    with locations.log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp} {message}\n")
