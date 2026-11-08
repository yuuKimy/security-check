from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    advisory_id: str
    package: str
    version: str
    fixed: str
    severity: str
    summary: str
    ecosystem: str
    project: str
    lockfile: str
    dependency_path: str

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.advisory_id,
            "package": self.package,
            "version": self.version,
            "fixed": self.fixed,
            "severity": self.severity,
            "summary": self.summary,
            "ecosystem": self.ecosystem,
            "project": self.project,
            "lockfile": self.lockfile,
            "dependency_path": self.dependency_path,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> Finding:
        def text(key: str) -> str:
            value = raw.get(key, "")
            return value if isinstance(value, str) else ""

        return cls(
            advisory_id=text("id"),
            package=text("package"),
            version=text("version"),
            fixed=text("fixed"),
            severity=text("severity") or "Unknown",
            summary=text("summary"),
            ecosystem=text("ecosystem"),
            project=text("project"),
            lockfile=text("lockfile"),
            dependency_path=text("dependency_path"),
        )


@dataclass
class LockfileScan:
    findings: list[Finding] = field(default_factory=list)
    package_count: int = 0
    error: str | None = None


@dataclass
class ProjectScan:
    name: str
    status: str
    detail: str = ""
    lockfile_count: int = 0
    package_count: int = 0
    unpinned: list[str] = field(default_factory=list)
    lockfile_errors: list[tuple[str, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class HostRecord:
    host: str
    sources: list[str]
    http: bool = False
    ip: bool = False
    punycode: bool = False
    lookalike: bool = False
    temporary: bool = False
    malware: bool = False
    phishing: bool = False

    def flagged(self) -> bool:
        return any(
            (
                self.http,
                self.ip,
                self.punycode,
                self.lookalike,
                self.temporary,
                self.malware,
                self.phishing,
            )
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "sources": self.sources,
            "http": self.http,
            "ip": self.ip,
            "punycode": self.punycode,
            "lookalike": self.lookalike,
            "temporary": self.temporary,
            "malware": self.malware,
            "phishing": self.phishing,
        }


@dataclass
class SourceStatus:
    name: str
    error: str | None = None


@dataclass
class HistoryResult:
    hosts: list[HostRecord] = field(default_factory=list)
    statuses: list[SourceStatus] = field(default_factory=list)
    legitimate_empty: bool = False
    legitimate_invalid: int = 0


@dataclass
class DownloadItem:
    name: str
    category: str
    host: str
    source: str
    redirect_host: str = ""
    http: bool = False
    redirect_http: bool = False
    danger: str = ""
    opened: str = ""
    incomplete: bool = False
    marks: list[str] = field(default_factory=list)

    def listed_in_report(self) -> bool:
        if self.category in {"executable", "archive"}:
            return True
        return self.category == "document" and bool(self.marks or self.danger or self.incomplete)

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "category": self.category,
            "host": self.host,
            "source": self.source,
            "redirect_host": self.redirect_host,
            "danger": self.danger,
            "opened": self.opened,
            "incomplete": self.incomplete,
            "marks": list(self.marks),
        }


@dataclass
class DownloadResult:
    items: list[DownloadItem] = field(default_factory=list)
    statuses: list[SourceStatus] = field(default_factory=list)


@dataclass
class FeedSourceState:
    name: str
    status: str
    last_success: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "name": self.name,
            "status": self.status,
            "last_success": self.last_success,
            "error": self.error,
        }


@dataclass
class FeedState:
    sources: list[FeedSourceState] = field(default_factory=list)
    matches: dict[str, set[str]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {"sources": [source.as_dict() for source in self.sources]}


@dataclass
class InboxItem:
    text: str
    urls: list[str]
    flags: list[str]


@dataclass
class InboxResult:
    items: list[InboxItem] = field(default_factory=list)
    omitted: int = 0


@dataclass(frozen=True)
class IgnoreEntry:
    advisory_id: str
    reason: str
    until: str


@dataclass(frozen=True)
class HostIgnoreEntry:
    host: str
    mark: str
    reason: str
    until: str
