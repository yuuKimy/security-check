from __future__ import annotations

from html import escape

from security_check.feeds import source_line
from security_check.hosts_check import labels_for
from security_check.models import DownloadResult, FeedState, Finding, HistoryResult, IgnoreEntry, ProjectScan

SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")
MARK_ORDER = ("http", "生IP", "Punycode", "なりすまし", "一時名", "マルウェア配布", "フィッシング")


def render_dashboard(
    *,
    when: str,
    projects: list[ProjectScan],
    findings: list[Finding],
    baseline_ids: set[str] | None,
    active_ignores: list[IgnoreEntry],
    history: HistoryResult,
    downloads: DownloadResult,
    feeds: FeedState,
    scanner_version: str,
    success: bool,
    failure_reason: str | None,
) -> str:
    ignored = {entry.advisory_id for entry in active_ignores}
    current_ids = {finding.advisory_id for finding in findings}
    if success and baseline_ids is not None:
        new_ids = current_ids - baseline_ids
        continuing_ids = current_ids & baseline_ids
        resolved = sorted(baseline_ids - current_ids)
    else:
        new_ids = current_ids
        continuing_ids = set()
        resolved = []
    visible = [finding for finding in findings if finding.advisory_id not in ignored]
    new_findings = [finding for finding in visible if finding.advisory_id in new_ids]
    continuing_findings = [finding for finding in visible if finding.advisory_id in continuing_ids]
    attention = [
        finding
        for finding in visible
        if finding.severity in {"Critical", "High"} and finding.advisory_id in new_ids | continuing_ids
    ]
    body = [
        _header(when, projects, success, failure_reason, baseline_ids is None),
        _glance(new_findings, continuing_findings, len(resolved) if success else 0),
        _severity(visible),
        _projects(projects, visible),
        _ecosystems(visible),
        _attention(attention, new_ids),
        _context(projects, history, downloads, feeds, scanner_version),
    ]
    return _page(when, "\n".join(body))


def _page(when: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>セキュリティチェック {escape(when)}</title>
<style>
:root {{
  color-scheme: light;
  --ink: #1c1c1c;
  --muted: #5e5a54;
  --line: #e4e0d8;
  --paper: #f7f6f3;
  --card: #fffcf8;
  --critical: #9f2d2d;
  --high: #9a5b12;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 15px/1.5 "Iowan Old Style", Palatino, "Hiragino Mincho ProN", serif;
}}
main {{ max-width: 980px; margin: 0 auto; padding: 40px 24px 64px; }}
header p {{ margin: 0; color: var(--muted); }}
h1 {{ margin: 4px 0 0; font-size: 24px; font-weight: 650; letter-spacing: 0; }}
h2 {{ margin: 36px 0 12px; font-size: 18px; font-weight: 650; }}
.failure {{
  margin-top: 16px;
  padding: 10px 12px;
  border: 1px solid var(--critical);
  color: var(--critical);
}}
.glance {{
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
  margin-top: 28px;
}}
.glance article {{ background: var(--card); border: 1px solid var(--line); padding: 14px 12px 12px; }}
.glance span {{ display: block; color: var(--muted); font-size: 13px; }}
.glance strong {{ display: block; margin-top: 4px; font-size: 24px; font-weight: 650; }}
.glance .critical strong {{ color: var(--critical); }}
.glance .high strong {{ color: var(--high); }}
.bars {{ display: grid; gap: 8px; }}
.bars div {{ display: grid; grid-template-columns: 88px 1fr 36px; gap: 10px; align-items: center; }}
.bars i {{
  display: block;
  height: 8px;
  background: #8d887f;
  width: calc(var(--share) * 100%);
  min-width: 2px;
}}
.bars .Critical i {{ background: var(--critical); }}
.bars .High i {{ background: var(--high); }}
table {{ width: 100%; border-collapse: collapse; background: var(--card); }}
th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
th {{ color: var(--muted); font-weight: 650; font-size: 13px; }}
.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
caption {{ caption-side: bottom; padding-top: 8px; color: var(--muted); text-align: left; font-size: 13px; }}
.status {{ padding-left: 18px; }}
.status li {{ margin: 4px 0; }}
@media (max-width: 720px) {{
  .glance {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
}}
</style>
</head>
<body>
<main>
{body}
</main>
</body>
</html>
"""


def _header(when: str, projects: list[ProjectScan], success: bool, failure_reason: str | None, first_run: bool) -> str:
    lockfiles = sum(project.lockfile_count for project in projects)
    packages = sum(project.package_count for project in projects)
    failure = ""
    if not success:
        reason = escape(failure_reason or "検査を完了できない")
        failure = f'<p class="failure">未完了: {reason}。前回との差分は更新していません。</p>'
    first = "<p>初回のため、今回の結果はすべて新規です。</p>" if first_run else ""
    return f"""<header>
<p>セキュリティチェック</p>
<h1>{escape(when)}</h1>
<p>プロジェクト {len(projects)}、lockfile {lockfiles}、照会パッケージ {packages}</p>
{first}
{failure}
</header>"""


def _glance(new_findings: list[Finding], continuing: list[Finding], resolved: int) -> str:
    cards = [
        ("critical", "新規 Critical", _ids(new_findings, "Critical")),
        ("high", "新規 High", _ids(new_findings, "High")),
        ("critical", "継続 Critical", _ids(continuing, "Critical")),
        ("high", "継続 High", _ids(continuing, "High")),
        ("", "解消", resolved),
    ]
    articles = "\n".join(
        f'<article class="{kind}"><span>{escape(label)}</span><strong>{count}</strong></article>'
        for kind, label, count in cards
    )
    return f'<section class="glance" aria-label="前回からの差分">{articles}</section>'


def _severity(findings: list[Finding]) -> str:
    counts = {severity: _ids(findings, severity) for severity in SEVERITIES}
    total = sum(counts.values()) or 1
    rows = []
    for severity in SEVERITIES:
        count = counts[severity]
        if count == 0:
            continue
        share = f"{count / total:.4f}"
        rows.append(
            f'<div class="{severity}"><span>{severity}</span>'
            f'<b><i style="--share: {share}"></i></b><em class="num">{count}</em></div>'
        )
    if not rows:
        rows.append("<p>該当する脆弱性はありません。</p>")
    return f"""<section>
<h2>重要度</h2>
<div class="bars">{"".join(rows)}</div>
<p>件数はアドバイザリ ID の数です。</p>
</section>"""


def _projects(projects: list[ProjectScan], findings: list[Finding]) -> str:
    names = [project.name for project in projects]
    for finding in findings:
        if finding.project and finding.project not in names:
            names.append(finding.project)
    rows = []
    ordered = sorted(
        names,
        key=lambda name: (
            -_ids(_of(findings, name), "Critical"),
            -_ids(_of(findings, name), "High"),
            name,
        ),
    )
    for name in ordered:
        own = _of(findings, name)
        cells = "".join(f'<td class="num">{_ids(own, severity)}</td>' for severity in SEVERITIES)
        rows.append(f"<tr><th>{escape(name)}</th>{cells}</tr>")
    head = "".join(f"<th class='num'>{severity}</th>" for severity in SEVERITIES)
    return f"""<section>
<h2>プロジェクト</h2>
<table>
<thead><tr><th>プロジェクト</th>{head}</tr></thead>
<tbody>{"".join(rows)}</tbody>
<caption>上の差分では、同じアドバイザリ ID を 1 件と数えます。この表では、その ID が現れたプロジェクトごとに数えます。</caption>
</table>
</section>"""


def _ecosystems(findings: list[Finding]) -> str:
    names = sorted({finding.ecosystem or "不明" for finding in findings})
    if not names:
        return ""
    rows = []
    for name in names:
        own = [finding for finding in findings if (finding.ecosystem or "不明") == name]
        cells = "".join(f'<td class="num">{_ids(own, severity)}</td>' for severity in SEVERITIES)
        rows.append(f"<tr><th>{escape(name)}</th>{cells}</tr>")
    head = "".join(f"<th class='num'>{severity}</th>" for severity in SEVERITIES)
    return f"""<section>
<h2>エコシステム</h2>
<table>
<thead><tr><th>エコシステム</th>{head}</tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
</section>"""


def _attention(findings: list[Finding], new_ids: set[str]) -> str:
    grouped: dict[tuple[str, str, str, str], list[Finding]] = {}
    for finding in findings:
        grouped.setdefault((finding.severity, finding.advisory_id, finding.package, finding.version), []).append(
            finding
        )
    ordered = sorted(grouped.values(), key=lambda group: (SEVERITIES.index(group[0].severity), group[0].advisory_id))
    if not ordered:
        return "<section><h2>Critical と High</h2><p>該当する脆弱性はありません。</p></section>"
    rows = []
    for group in ordered:
        head = group[0]
        state = "新規" if head.advisory_id in new_ids else "継続"
        projects = "、".join(dict.fromkeys(item.project for item in group))
        rows.append(
            "<tr>"
            f"<td>{escape(state)}</td>"
            f"<td>{escape(head.severity)}</td>"
            f"<td>{escape(head.package)} {escape(head.version)}</td>"
            f"<td>{escape(projects)}</td>"
            f"<td>{escape(head.fixed or '不明')}</td>"
            f"<td>{escape(head.advisory_id)}</td>"
            "</tr>"
        )
    return f"""<section>
<h2>Critical と High</h2>
<table>
<thead><tr><th>差分</th><th>重要度</th><th>パッケージ</th><th>プロジェクト</th><th>修正版</th><th>ID</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
</section>"""


def _context(
    projects: list[ProjectScan],
    history: HistoryResult,
    downloads: DownloadResult,
    feeds: FeedState,
    scanner_version: str,
) -> str:
    items = [f"スキャナー: {scanner_version}"]
    items.extend(source_line(source) for source in feeds.sources)
    items.extend(_project_notes(projects))
    items.extend(_history_notes(history))
    items.extend(_download_notes(downloads))
    listed = "".join(f"<li>{escape(item)}</li>" for item in items)
    return f"<section><h2>検査の状態</h2><ul class='status'>{listed}</ul></section>"


def _project_notes(projects: list[ProjectScan]) -> list[str]:
    notes = []
    for project in projects:
        if project.status == "no_lockfile":
            notes.append(f"診断対象なし: {project.name}")
        elif project.status == "missing":
            notes.append(f"未走査: {project.name}: パスが存在しない")
        elif project.status == "too_many":
            notes.append(f"上限超過: {project.name}")
        elif project.status == "too_broad":
            notes.append(f"拒否: {project.name}")
        for lockfile, error in project.lockfile_errors:
            notes.append(f"{project.name} / {lockfile}: {error}")
    return notes


def _history_notes(history: HistoryResult) -> list[str]:
    counts = {label: 0 for label in MARK_ORDER}
    for host in history.hosts:
        for label in labels_for(host):
            counts[label] += 1
    marks = [f"{label} {count}" for label, count in counts.items() if count]
    notes = [f"閲覧ホスト {len(history.hosts)} 件" + (f"（{'、'.join(marks)}）" if marks else "")]
    if history.legitimate_empty:
        notes.append("なりすましの基準リストは空")
    elif history.legitimate_invalid:
        notes.append(f"基準リストの {history.legitimate_invalid} 行はホスト名として読めない")
    for status in history.statuses:
        if status.error:
            notes.append(f"未取得: {status.name}: {status.error}")
    return notes


def _download_notes(downloads: DownloadResult) -> list[str]:
    listed = [item for item in downloads.items if item.listed_in_report()]
    quiet = sum(1 for item in downloads.items if item.category == "document" and not item.listed_in_report())
    unknown = sum(1 for item in downloads.items if item.category == "unknown")
    notes = [f"ダウンロード {len(listed)} 件を表示、目印の無い文書 {quiet} 件"]
    if unknown:
        notes.append(f"分類できないダウンロード {unknown} 件")
    for status in downloads.statuses:
        if status.error:
            notes.append(f"未取得: {status.name}: {status.error}")
    return notes


def _of(findings: list[Finding], project: str) -> list[Finding]:
    return [finding for finding in findings if finding.project == project]


def _ids(findings: list[Finding], severity: str) -> int:
    return len({finding.advisory_id for finding in findings if finding.severity == severity})
