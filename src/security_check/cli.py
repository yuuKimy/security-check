from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from security_check.feeds import format_feed_status, set_urlhaus_key
from security_check.host_ignores import write_host_ignore
from security_check.ignores import write_ignore
from security_check.manifest import ManifestError, add_project, remove_project
from security_check.paths import default_locations
from security_check.run import run
from security_check.schedule import install, status, uninstall


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="security-check", description="登録プロジェクト、閲覧ホスト、ダウンロードの定期確認"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="検査してレポートを書く")
    run_parser.add_argument(
        "--scheduled",
        action="store_true",
        help="前回の成功から7日未満なら、脆弱性の走査とレポートの更新をしない。URLhaus と OpenPhish の一覧の取得は行う",
    )

    add_parser = sub.add_parser("add", help="プロジェクトを登録する")
    add_parser.add_argument("path", type=Path)
    add_parser.add_argument("--name")

    remove_parser = sub.add_parser("remove", help="プロジェクトの登録を消す")
    remove_parser.add_argument("name")

    ignore_parser = sub.add_parser("ignore", help="受け入れを記録する")
    ignore_parser.add_argument("advisory_id")
    ignore_parser.add_argument("--reason", required=True)
    ignore_parser.add_argument("--until", required=True, help="YYYY-MM-DD。この日を含めて、レポートの対象から外す")

    host_ignore_parser = sub.add_parser("ignore-host", help="ホストの目印を受け入れとして記録する")
    host_ignore_parser.add_argument("host")
    host_ignore_parser.add_argument("--mark", required=True)
    host_ignore_parser.add_argument("--reason", required=True)
    host_ignore_parser.add_argument("--until", required=True, help="YYYY-MM-DD。この日を含めて、レポートの目印から外す")

    feeds = sub.add_parser("feeds", help="URLhaus と OpenPhish の一覧取得を管理する")
    feeds_sub = feeds.add_subparsers(dest="feeds_command", required=True)
    feeds_sub.add_parser("set-urlhaus-key", help="URLhaus の Auth-Key を標準入力から記録する")
    feeds_sub.add_parser("status", help="キーの有無と最終取得時刻を表示する")

    schedule = sub.add_parser("schedule", help="毎日 9:00 の実行を管理する")
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    schedule_sub.add_parser("install", help="毎日 9:00 の実行を登録する")
    schedule_sub.add_parser("uninstall", help="定期実行を外す")
    schedule_sub.add_parser("status", help="登録の有無を表示する")

    args = parser.parse_args(argv)
    locations = default_locations()
    try:
        if args.command == "run":
            raise SystemExit(run(locations, scheduled=args.scheduled))
        if args.command == "add":
            project = add_project(locations, args.path, args.name, Path.home())
            print(f"登録した: {project.name} {project.path}")
            return
        if args.command == "remove":
            remove_project(locations, args.name)
            print(f"削除した: {args.name}")
            return
        if args.command == "ignore":
            write_ignore(locations.ignores_path, args.advisory_id, args.reason, args.until)
            print(f"記録した: {args.advisory_id} 期限 {args.until}")
            return
        if args.command == "ignore-host":
            write_host_ignore(locations.host_ignores_path, args.host, args.mark, args.reason, args.until)
            print(f"記録した: {args.host} {args.mark} 期限 {args.until}")
            return
        if args.command == "feeds" and args.feeds_command == "set-urlhaus-key":
            if sys.stdin.isatty():
                print("Auth-Key を入力し、Ctrl-D で終えてください。", file=sys.stderr)
            set_urlhaus_key(locations.urlhaus_key_path, sys.stdin.read())
            print("URLhaus の Auth-Key を記録した")
            return
        if args.command == "feeds":
            print(format_feed_status(locations, datetime.now().astimezone()))
            return
        if args.schedule_command == "install":
            print(install(Path(sys.argv[0]).resolve(), locations.log_file))
            return
        if args.schedule_command == "uninstall":
            uninstall()
            print("定期実行を外した")
            return
        print(status())
    except (ManifestError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
