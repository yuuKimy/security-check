from __future__ import annotations

import os
import subprocess
from pathlib import Path
from xml.sax.saxutils import escape

from security_check.paths import write_private_text

LABEL = "com.security-check.daily"
GUIDANCE = (
    "Cursor で開いているワークスペースに ~/SecurityCheck をフォルダ追加すると、latest.md をすぐ読めます。\n"
    "Safari と Chrome の履歴を読むには、システム設定のプライバシーとセキュリティで、"
    "フルディスクアクセスにこの実行ファイルを追加してください。\n"
    "なりすましの基準は ~/SecurityCheck/legitimate-hosts.txt に、ホスト名を1行ずつ書きます。\n"
    "URLhaus を使うときは、Auth-Key を security-check feeds set-urlhaus-key の標準入力へ渡してください。\n"
)


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def render_plist(executable: Path, log_file: Path) -> str:
    program = escape(str(executable))
    log = escape(str(log_file))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{program}</string>
    <string>run</string>
    <string>--scheduled</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>9</integer>
    <key>Minute</key>
    <integer>0</integer>
  </dict>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"""


def install(executable: Path, log_file: Path) -> str:
    destination = plist_path()
    write_private_text(destination, render_plist(executable, log_file))
    domain = f"gui/{os.getuid()}"
    subprocess.run(["launchctl", "bootout", f"{domain}/{LABEL}"], check=False)
    completed = subprocess.run(
        ["launchctl", "bootstrap", domain, str(destination)], check=False, capture_output=True, text=True
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(detail or "launchd への登録に失敗した")
    return GUIDANCE


def uninstall() -> None:
    domain = f"gui/{os.getuid()}"
    subprocess.run(["launchctl", "bootout", f"{domain}/{LABEL}"], check=False)
    path = plist_path()
    if path.exists():
        path.unlink()


def status() -> str:
    completed = subprocess.run(
        ["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return "定期実行は登録されていません"
    return completed.stdout
