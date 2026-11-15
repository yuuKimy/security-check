---
name: security-check-dev
description: >-
  security-check CLI・レポート・スケジュールの実装とテスト。
  src/security_check/ や tests/ の改修、レポート形式の変更、
  OSV・ブラウザ履歴・フィード照合の挙動を触るときに使う。
  latest.md の説明だけのときは review-security-check を使う。
---

# security-check 開発

> レポートを人に説明するだけ → **`review-security-check`** または subagent **`report-reviewer`**。本 skill はリポジトリのコード用。

## 最初に読む

1. [README.md](../../../README.md) — 調査範囲と外部送信
2. [AGENTS.md](../../../AGENTS.md) — ゲートと禁止事項
3. 変更対象モジュール（`cli.py` `run.py` `report.py` `scan.py` `hosts_check.py` 等）

## 不変条件（改修時に壊さない）

- レポートは事実と件数。危険判定の文言は書かない
- テストはネットワークに接続しない（`tests/` のモック・フィクスチャを維持）
- 人向け出力は `~/SecurityCheck/`、機械向けは `~/Library/Application Support/security-check/`
- `<<<DATA` … `DATA` 区切りはレポート内の prompt-injection 対策として維持する

## 検証（完了宣言前）

```bash
uv sync --group dev
uv run pytest
uv run ruff check src tests
```

`standard` ゲート。大きな仕様変更後は subagent `design-reviewer` を起動する。

## オーケストレーション

- 親エージェントが実装。自分の差分の境界レビューは `design-reviewer` に依頼
- 完了宣言前は `verifier` または上記コマンドで PASS を確認（`verify-gate` skill 参照）