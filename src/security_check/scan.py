from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from security_check.models import Finding, LockfileScan
from security_check.sanitize import shorten

PACKAGE_COUNT = re.compile(r"found (\d+) packages?", re.IGNORECASE)
SCANNER_MISSING = "OSV-Scanner が見つかりません。brew install osv-scanner で導入できます"
SEVERITY_LABELS = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MODERATE": "Medium",
    "MEDIUM": "Medium",
    "LOW": "Low",
}
KEPT_ENV = (
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)


def scanner_environment() -> dict[str, str]:
    environment = {"PATH": os.environ.get("PATH", ""), "HOME": str(Path.home())}
    for key in KEPT_ENV:
        if key in os.environ:
            environment[key] = os.environ[key]
    return environment


def scanner_command(binary: str, lockfile: Path) -> list[str]:
    return [binary, "scan", "source", "--lockfile", str(lockfile), "--format", "json"]


def _severity(vulnerability: dict[str, object]) -> str:
    specific = vulnerability.get("database_specific")
    if isinstance(specific, dict):
        label = specific.get("severity")
        if isinstance(label, str) and label.upper() in SEVERITY_LABELS:
            return SEVERITY_LABELS[label.upper()]
    scores = vulnerability.get("severity")
    if isinstance(scores, list):
        for item in scores:
            if not isinstance(item, dict):
                continue
            score = item.get("score")
            if isinstance(score, (int, float)):
                return _bucket(float(score))
            if isinstance(score, str):
                try:
                    return _bucket(float(score))
                except ValueError:
                    continue
    return "Unknown"


def _bucket(score: float) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def _fixed_versions(vulnerability: dict[str, object], package_name: str) -> str:
    found: list[str] = []
    affected = vulnerability.get("affected")
    if not isinstance(affected, list):
        return ""
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if isinstance(package, dict):
            name = package.get("name")
            if isinstance(name, str) and name != package_name:
                continue
        ranges = entry.get("ranges")
        if not isinstance(ranges, list):
            continue
        for span in ranges:
            if not isinstance(span, dict):
                continue
            events = span.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed = event["fixed"]
                    if fixed not in found:
                        found.append(fixed)
    return ", ".join(found)


def _dependency_path(package_obj: dict[str, object]) -> str:
    for key in ("dependency_path", "call_path"):
        value = package_obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, list) and value:
            return " -> ".join(str(item) for item in value)
    groups = package_obj.get("groups")
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, dict):
                continue
            for key in ("dependency_path", "path"):
                value = group.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def parse_scanner_output(stdout: str, stderr: str) -> LockfileScan | None:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        return None
    findings: list[Finding] = []
    package_objects = 0
    for result in payload["results"]:
        if not isinstance(result, dict):
            return None
        packages = result.get("packages", [])
        if packages is None:
            packages = []
        if not isinstance(packages, list):
            return None
        for package_obj in packages:
            if not isinstance(package_obj, dict):
                return None
            package_objects += 1
            package = package_obj.get("package")
            if not isinstance(package, dict):
                return None
            name = package.get("name")
            version = package.get("version")
            ecosystem = package.get("ecosystem")
            if not isinstance(name, str) or not isinstance(version, str):
                return None
            vulnerabilities = package_obj.get("vulnerabilities", [])
            if vulnerabilities is None:
                vulnerabilities = []
            if not isinstance(vulnerabilities, list):
                return None
            dependency_path = _dependency_path(package_obj)
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str):
                    return None
                summary = vulnerability.get("summary")
                findings.append(
                    Finding(
                        advisory_id=vulnerability["id"],
                        package=name,
                        version=version,
                        fixed=_fixed_versions(vulnerability, name),
                        severity=_severity(vulnerability),
                        summary=shorten(summary if isinstance(summary, str) else "", 400),
                        ecosystem=ecosystem if isinstance(ecosystem, str) else "",
                        project="",
                        lockfile="",
                        dependency_path=shorten(dependency_path, 400),
                    )
                )
    counted = sum(int(match) for match in PACKAGE_COUNT.findall(stderr))
    return LockfileScan(findings=findings, package_count=counted or package_objects)


class OsvScanner:
    def __init__(self, binary: str | None = None) -> None:
        self.binary = binary or shutil.which("osv-scanner", path=scanner_environment().get("PATH"))

    def available(self) -> bool:
        return self.binary is not None

    def version(self) -> str:
        if not self.binary:
            return "不明"
        try:
            completed = subprocess.run(
                [self.binary, "--version"],
                capture_output=True,
                text=True,
                env=scanner_environment(),
                timeout=30,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return "不明"
        text = (completed.stdout or completed.stderr).strip()
        return text.splitlines()[0] if text else "不明"

    def scan_lockfile(self, lockfile: Path, timeout: float) -> LockfileScan:
        if not self.binary:
            return LockfileScan(error=SCANNER_MISSING)
        try:
            completed = subprocess.run(
                scanner_command(self.binary, lockfile),
                capture_output=True,
                text=True,
                env=scanner_environment(),
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return LockfileScan(error="時間内に終わらない")
        except OSError:
            return LockfileScan(error="スキャナーを起動できない")
        parsed = parse_scanner_output(completed.stdout, completed.stderr)
        if parsed is None or completed.returncode not in (0, 1):
            detail = shorten(completed.stderr or completed.stdout or "出力を解釈できない", 300)
            if _looks_like_network(detail):
                return LockfileScan(error=f"通信に失敗した: {detail}")
            return LockfileScan(error=f"解釈できない出力: {detail}")
        return parsed


def _looks_like_network(text: str) -> bool:
    lowered = text.lower()
    hints = ("connection", "dial tcp", "no such host", "tls", "network", "timeout", "refused")
    return any(hint in lowered for hint in hints)
