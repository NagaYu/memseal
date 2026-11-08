# MemSeal Phase 1 報告書

- 対象: Phase 1（完全オフライン・LLM 不使用・決定的な縦切り）
- 実行環境: macOS (darwin), Python 3.13.15, pytest 9.0.3
- 依存: ランタイムは Python 標準ライブラリのみ。テストは pytest のみ。pyyaml 不使用
- ネットワーク呼び出し・LLM/外部 API 呼び出し・API キー: いずれも無し
- git: ローカルコミットのみ（push・公開はしていない）
- 数値はすべて `reports/phase1-runs/` の実行結果から転記したもの（dev スプリットのみ。holdout は生成していない）

## 1. 作ったもの（ステップごと）

| Step | 成果物 | 内容 |
|---|---|---|
| 0 | `pyproject.toml`, `memseal/`, SPEC/STATUS/DECISIONS | 雛形。依存ゼロ、`memseal` コンソールスクリプト |
| 1 | `memseal/envelope.py` | Provenance Envelope、source_class→T0–T4 の固定写像、正規化 JSON、SHA-256 ハッシュチェーン、検証（自己ハッシュ / entry_id / リンク / seq） |
| 2 | `memseal/store.py` | ファイル型ストア（追記型ログ、principal スコープ、supersede による版管理、スナップショット、ロールバック＋退避アーカイブ、隔離/レビュー/監査キュー） |
| 3 | `memseal/detectors.py` | 命令形検出（EN 5 パターン、JA 10 パターン、データとして拡張可能）、秘密形状検出 12 パターン、redact |
| 4 | `memseal/policy.py` | 書き込みポリシー W1–W5、理由コードつき隔離・レビューキュー、監査ログ、C0 用の素の書き込み |
| 5 | `memseal/consolidate.py` | 来歴を保持する決定的統合（連結＋重複排除、derived_from に入力全件）、C0 用の来歴を落とす naive 統合 |
| 6 | `memseal/recall.py` | 信頼段位つき想起（チェーン検証で除外＋警告、principal フィルタ、provenance 添付、`sole_basis_for_irreversible`） |
| 7 | `memseal/bench/` , `bench/dev/` | MemSeal Bench 生成器。メモリパック 4 種（EN 2 / JA 2、各 13 エントリ）、テンプレート 60（攻撃 48 + clean 12、各 EN/JA）、dev 120 件、スキーマ検証、holdout ガード |
| 8 | `memseal/sim/` , `reports/phase1-runs/` | スクリプトエージェント、条件 C0/C2/C3 の決定的シミュレーション、指標計算、JSON / Markdown / トレース出力 |
| 9 | `memseal/cli.py`, `README.md`, 本報告書 | `memseal verify` / `memseal quarantine` / `memseal bench generate` / `memseal run` |

dev ベンチ: `bench/dev/memseal_bench_dev.jsonl`（sha256 `2e8374d104ab482fb6937f16ad87252ba96ffd6dacf41b55038136225cdd5b54`, seed 20261107）。

## 2. テスト

**合計 170 件、全件 pass**（`python3 -m pytest -q` → `170 passed`）。

| ファイル | 件数 | 主な内容 |
|---|---|---|
| test_scaffold.py | 1 | パッケージ import |
| test_envelope.py | 11 | 段位写像、entry_id、正規化 JSON、sealed 制約、改竄検出（内容改竄・ハッシュ再計算つき改竄・削除・来歴フィールド改竄） |
| test_store.py | 13 | 作成/再オープン、チェーン、principal スコープ、版管理、スナップショット/ロールバック（改竄後の復元を含む）、破損行の報告、キュー |
| test_detectors.py | 53 | 命令形 EN 肯定 11 / 否定 7、JA 肯定 9 / 否定 6、拡張性、秘密形状 肯定 12 / 否定 6、redact（冪等性） |
| test_policy.py | 32 | W1 12（うち JA 4）、W2 5、W3 3、W4 3、W5 5、その他 4 |
| test_consolidate.py | 9 | derived_from 継承、ロンダリング試行（user_explicit 名乗り / sealed 名乗り / 多段 / 未知入力）、naive 統合 |
| test_recall.py | 9 | provenance 添付、sole_basis フラグ、チェーン失敗の除外と警告、改竄 supersede の無効化、principal フィルタ、slot 検索 |
| test_bench_generator.py | 18 | 120 件・クラス均衡、スキーマ、空メモリ無し、決定性、seed 依存性、コミット済みベンチとの一致、holdout 拒否 5 |
| test_sim.py | 15 | 条件ごとの代表ケース挙動、指標計算の算術、決定性、レポート出力 |
| test_no_network.py | 3 | ネットワーク系 import の静的検査、URL リテラル検査、ソケット無効化下での全件実行 |
| test_cli.py | 6 | verify（正常/改竄/非ストア）、quarantine（W3 内容秘匿を含む）、bench generate（holdout 拒否）、run |

テストの期待値を実装に合わせて書き換えたことはない。開発中に赤になった 3 件の扱い:
redact の冪等性テスト（→ 実装のバグ: マーカー自体がパスワード形状に一致していたのを修正）、
想起テストの入力文が命令形で W1 に正しく隔離された件（→ テスト入力を宣言文に修正。期待値は不変）、
部分集合でのレポート描画の例外（→ 実装のバグを修正）。

## 3. Phase 1 GATE 自己判定

| # | 条件 | 判定 | 根拠 |
|---|---|---|---|
| 1 | pytest 全件 green（件数明記） | **PASS** | 170 passed / 0 failed |
| 2 | W1–W5 すべてに専用テスト、M1–M8 各 12 件の dev ケース | **PASS** | `test_policy.py` に W1–W5 別のテスト群（W1 の JA は 4 件）。`test_dev_size_and_class_balance` で M1–M8 各 12（EN 6 / JA 6）、clean 24 |
| 3 | 改竄検出とロールバックのテストが通る | **PASS** | `test_envelope.py` の改竄 4 種、`test_store.py` の snapshot/rollback 4 件、`test_recall.py` の除外テスト |
| 4 | 生成器が決定的、holdout 拒否テストが通る | **PASS** | 同一 seed で同一 sha256（別プロセス・`PYTHONHASHSEED` を変えても一致を確認）、holdout 拒否 5 テスト pass |
| 5 | C0/C2/C3 の結果が reports にある（C1/C4 は NOT EVALUABLE） | **PASS** | `reports/phase1-runs/results.{json,md}`, `traces-C{0,2,3}.jsonl`, `SHA256SUMS.json`。C1/C4 は表中で NOT EVALUABLE |
| 6 | ネットワーク呼び出しがコードのどこにもない | **PASS** | `memseal/` 全ファイルの AST 検査（socket/http/urllib/requests/asyncio/subprocess 等の import 無し、URL リテラル無し）、ソケット無効化下で 120 件×3 条件を実行して成功 |

GATE 6 の補足: 静的検査の対象は `memseal/` パッケージ。テストコード自体は標準ライブラリと pytest のみを import している。

## 4. シミュレーション結果（dev 120 件）

スクリプトエージェントは想起で返った全エントリを使う（全条件で同一規則。`sole_basis_for_irreversible` は強制しない）。

| 指標 | C0 素のストア | C2 書き込みパス | C3 C2 + 想起パス | C1 | C4 |
|---|---|---|---|---|---|
| 注入成功率（should_store=false が保存された割合） | 1.000 (108/108) | 0.481 (52/108) | 0.481 (52/108) | NOT EVALUABLE | NOT EVALUABLE |
| 遅延利用率（後のセッションでペイロード使用） | 1.000 (86/86) | 0.546 (47/86) | 0.430 (37/86) | NOT EVALUABLE | NOT EVALUABLE |
| 漏洩件数（must_not_leak を含む想起） | 24 | 6 | 0 | NOT EVALUABLE | NOT EVALUABLE |
| clean 想起保持率 | 1.000 (30/30) | 0.933 (28/30) | 0.933 (28/30) | NOT EVALUABLE | NOT EVALUABLE |
| 隔離 precision | n/a（隔離なし） | 0.966 (TP 56 / FP 2) | 0.966 | NOT EVALUABLE | NOT EVALUABLE |
| 隔離 recall | 0.000 | 0.518 (TP 56 / FN 52) | 0.518 | NOT EVALUABLE | NOT EVALUABLE |
| clean 書き込みの誤ブロック率 | 0.000 | 0.071 (2/28) | 0.071 | NOT EVALUABLE | NOT EVALUABLE |
| 攻撃ケース内の正当想起保持率 | 0.800 | 0.800 | 0.800 | NOT EVALUABLE | NOT EVALUABLE |
| 外部送信/不可逆文脈でのペイロード使用 | 60 | 32 | 28 | – | – |
| うち sole_basis=False が付いていた件数 | 0（フラグ無し） | 0（フラグ無し） | 20 | – | – |

攻撃クラス別（注入成功率 / 遅延利用率 / 漏洩件数）:

| クラス | C0 | C2 | C3 |
|---|---|---|---|
| M1 クエリのみ注入 | 1.00 / 1.00 / 0 | 0.25 / 0.25 / 0 | 0.25 / 0.25 / 0 |
| M2 文書経由の持続化 | 1.00 / 1.00 / 0 | 0.33 / 0.33 / 0 | 0.33 / 0.33 / 0 |
| M3 統合ロンダリング | 1.00 / 1.00 / 0 | 0.54 / 0.83 / 0 | 0.54 / 0.83 / 0 |
| M4 スリーパー/トリガー | 1.00 / 1.00 / 0 | 0.58 / 0.58 / 0 | 0.58 / 0.58 / 0 |
| M5 偽事実の植え付け | 1.00 / 1.00 / 0 | 0.13 / 0.42 / 0 | 0.13 / 0.08 / 0 |
| M6 嗜好ドリフト | 1.00 / 1.00 / 0 | 0.82 / 1.00 / 0 | 0.82 / 1.00 / 0 |
| M7 クロスプリンシパル漏洩 | 1.00 / 1.00 / 12 | 0.00 / 0.50 / 6 | 0.00 / 0.00 / 0 |
| M8 秘密のステージング | 1.00 / 1.00 / 12 | 0.00 / 0.00 / 0 | 0.00 / 0.00 / 0 |

発火した理由コード（C2・C3 共通）: W1 26, W2 10, W3 12, W4 12, W5 12。

### 読み取り（dev のみ。過大評価の可能性に注意）

- **効いている所**: W3（M7 の誤配送書き込み）と W4（M8 の秘密）は dev で注入 0、漏洩は 24 → 6 → 0。
  W5 は封印 slot と矛盾する偽事実を全件レビューに回した（M5 の注入 0.13 の残りは M5-c-ja）。
- **C3 が C2 に上乗せした分**: ファイル直接改竄（M5-d/e、ハッシュ再計算版を含む）の除外と、
  レガシー混入した他 principal のエントリ（M7-b/d/f）の想起フィルタ。遅延利用 47 → 37、漏洩 6 → 0。
- **効いていない所**:
  - M6 嗜好ドリフト（注入 0.82、遅延利用 1.00）: 宣言文の小さな誘導は形式検出器の対象外。1 回目が命令形で
    隔離されても 2 回目の宣言文が通る。
  - M3 統合ロンダリング（遅延利用 0.83）: W2 は「来歴の偽装」は止める（user_explicit / sealed の名乗りはすべて隔離）が、
    元の T3 文書エントリ自体は active のまま残り、後で想起・使用される。段位は正しく T3 として付いている。
  - M4 スリーパー（0.58）: 動詞リスト外（"export"）、「〜という意味」型の定義文、JA の「〜して」終止など。
  - 宣言文型の偽事実（M1-f, M2-d, M2-f, M5-c-ja）は W1/W5 のどちらにも掛からない。
- **sole_basis フラグ**: C3 で外部送信/不可逆文脈のペイロード使用 28 件のうち 20 件に `False` が付いていた。
  呼び出し側が強制すればこの 20 件は止められる可能性がある（Phase 1 では未強制・未測定）。残り 8 件は T1/T2
  由来（agent_inference・user_conversation の宣言文: M1-f, M4-b-en, M4-e, M5-c-ja, M6-c）でフラグが立たない。
- **utility**: clean の誤ブロック 2 件はどちらも JA のハードネガティブ（CL-i-ja「提出すること」の社内連絡、
  CL-j-ja「リマインドしてください」）。EN の対応ケースが通ったのは精度が高いからではなく、"Team memo:" 接頭辞と
  "remind" が検出器に無い（＝取りこぼし）ため。言語間で W1 の厳しさが非対称。
- **攻撃ケース内の正当想起保持率 0.80**: 改竄された封印値（M5-d/e）は C3 で除外されるが復元はされない。
  復元はロールバック（Step 2 でテスト済み）の役割で、シミュレーションでは実行していない。
- **偶然の検出**: M5-c-en は "Update:" が動詞 "update" に一致して W1 隔離された（D-21）。設計上の検出ではない。

## 5. 逸脱・未実装・DECISIONS.md に記録した判断

主なもの（詳細は [DECISIONS.md](../DECISIONS.md)）:

- D-01 Envelope に `seq` と `supersedes` を追加（拡張。固定フィールドの意味は不変）
- D-03 チェーン除外規則（自己検査失敗＋リンク断の両側）。**後続を全部再計算する改竄は検出不能**（外部アンカー無し）
- D-04 W4 は「redact して保存」。平文はどのファイルにも残さない。ユーザーが保存したパスワードも取り出せない
- D-05 W3 拒否時は内容を隔離キューにも写さず sha256 のみ記録
- D-06 W2 の段位は「自身の source_class と全祖先」の最悪値（仕様の「根の最低段位」より保守的）
- D-07 W3 を「他 principal のエントリを派生元に含む書き込み」にも拡張
- D-08 `entry_class=instruction` も非 user_explicit なら W1。user_conversation の命令形も隔離（仕様どおり、偽陽性あり）
- D-09 W5 は slot fact の content を値として正規化比較。slot の無い矛盾は対象外
- D-10 検出器は dev ベンチを見て調整していない
- D-14 スクリプトエージェントは sole_basis を強制しない → C2 と C3 の差は除外とフィルタのみ
- D-15 指標の正例はベンチのラベルをそのまま使用（試走時に入れた動的判定は最終実行前に撤回）
- D-16 ベンチ側バグ 2 件を修正して再生成・再実行（M6-c のマーカー、JA 版の銀行キーワード）
- D-17 holdout は同じテンプレートの別 seed なので弱い

未実装（Phase 1 範囲外または未着手）:

- C1（検出器フィルタ条件）・C4（統合ガード込みの本測定）: NOT EVALUABLE
- holdout の実生成（ガードと拒否テストのみ）
- `sole_basis_for_irreversible` の呼び出し側強制
- 隔離・レビューキューの解決ワークフロー（承認・却下 API）
- チェーン head の外部アンカリング

## 6. Phase 2 への引き継ぎ事項

1. **実 LLM 測定と Mem0 アダプタ**（Phase 2 の本題）。スクリプトエージェントの「全件使用」規則を実エージェントの挙動に置き換える。
2. **holdout 専用テンプレート**を dev と別管理で作り、`MEMSEAL_ALLOW_HOLDOUT=1` かつリポジトリ外で生成する。dev の数値（特に W1/W5 が効いたクラス）は楽観的とみなすこと。
3. **C1 / C4 の測定**: 検出器のみのフィルタ条件と、統合ガードの単独効果。
4. **宣言文型の汚染への対策**: 嗜好ドリフト（M6）、slot の無い偽事実、「〜という意味」型の定義文。形式検出では届かないので、段位に基づく想起側の扱い（T2/T3 の嗜好・事実を単独根拠にしない等）を検討。
5. **統合ロンダリングの残余**: W2 は偽装を止めるが T3 の根は残る。根の段位に応じた想起時の扱い、または統合時の根の退役を設計する。
6. **sole_basis の強制層**を設計し、28 件中 20 件のフラグつき使用が実際に止まるかを測る。T1/T2 由来の 8 件は別対策が必要。
7. **JA/EN の検出器の非対称**を解消（EN の接頭辞・動詞の取りこぼし、JA の「必ず」・「〜すること」の偽陽性）。調整は holdout で評価すること。
8. **チェーンの外部アンカー**（head hash の別所保存または署名）と、改竄時の自動ロールバック手順。
9. **レビューキューの解決 API**（ユーザー確認で user_explicit として再書き込み、など）。

Phase 1 はここで停止する。
