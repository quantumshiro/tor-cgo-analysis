# 論文評価アーティファクト

公開リポジトリ：<https://github.com/quantumshiro/tor-cgo-analysis>。本改訂に対応するタグと完全なコミットSHAは、提出版の公開時に固定する。

## 再現可能性の区分

公開物には生のコアダンプ、PCAP、TLS秘密、CGO秘密、復号済みレコードを含めない。そのため、次の三段階を区別する。

- **A：結果監査** — 集計JSON、個別の非秘密結果、SHA-256、解析コードを照合できる。
- **B：集計再生成** — 公開した個別の非秘密結果から、論文中の集計を再生成できる。
- **C：新規再取得** — 固定コミットの第三者ソースを別途取得または配布パッケージから展開し、隔離網で新しいコアダンプとPCAPを生成して一連の処理を再実行できる。

除外した生データが必要な「保存済み取得物そのものの完全な再解析」は公開版だけではできない。この制約をCと表記しない。

| 主張・評価 | 公開結果 | 区分 | 公開版で可能な検証 |
|---|---|---:|---|
| 144/144回路、432/432ホップ | `results/generalization/summary-arm64-replicated.json` | A/C | 集計と解析器を監査し、`run_generalization_case.sh`で新規取得 |
| 公式パッケージ版36/36回路、108/108ホップ | `results/generalization/summary-official-package-0.4.9.17.json` | B/C | 公開した3起動の非秘密結果から再集計し、公式パッケージと外部デバッグシンボルで新規取得 |
| 公式パッケージ版の一意なCGO認証6/6、DATA 5件、SENDME 1件 | `results/packaged-tor-e4e5/summary-04917-replay.json` | B/C | 公式0.4.9.17ソースから構築した再生器で6個の保存済み取得物を再評価 |
| 公式0.4.9.17再生器の由来・Build ID・SHA-256 | `results/packaged-tor-e4e5/replay-0.4.9.17-build.json` | A | 製品側ソースを変更せず、試験用入出力だけを追加してビルド |
| 旧再生器と公式0.4.9.17再生器の全36候補の一致 | `results/packaged-tor-e4e5/replay-version-comparison.json` | A | CGO認証ホップ、復元バイト列、正解情報不使用フラグを比較 |
| TLSレコードとCGO層の連続復号、10/10 | `results/open-circuit-impact/independent-v3/summary.json` | B/C | 公開した10個の評価JSONを`evaluate_full_pcap_repetitions.py`で再集計 |
| ストリームを停止せず、セル・TLS境界を観測しない固定遅延取得、6/6 | `results/uncontrolled-pcap/summary.json` | B/C | 6個の評価JSONを`evaluate_uncontrolled_pcap_repetitions.py`で再集計し、`run_uncontrolled_pcap_case.sh`で新規取得 |
| 混在回路10件をCGO専用復号処理へ渡さない | `results/real-tor-mixed/mixed-e3-admission.json` | B/C | 公開した構造解析結果と対象回路一覧を`evaluate_mixed_e3_admission.py`で再評価 |
| 所有関係・経路構造・暗号コンテキストを検証した回路一覧に対する負の対照4/4 | `results/open-circuit-impact/e3-enforcement-negative/summary.json` | A/C | 結果監査と`test_e3_enforcement.py`による新規試験入力の評価 |
| CGO状態7分類、7,168件 | `results/open-circuit-impact/negative-state-matrix-v2/summary.json` | A/C | 変更済みC試験ソースを監査し、別途ビルド後に再実行 |
| TLS負対照 | `results/open-circuit-impact/tls-negative-controls-v2/summary.json` | A/C | 結果と`run_tls_negative_controls.py`を監査し、新規取得物で再実行 |
| 実行ファイル互換性の正負対照 | `results/robustness/build-verification/` | A/C | `verify_core_executable.py`の判定と結果を監査 |
| 真に読取り不能なPT_LOAD対照 | `results/page-loss-absent/summary.json` | A/C | 欠損生成・評価スクリプトと集計を監査 |
| 直前セル0/3 | `results/open-circuit-impact/past-cell-statistics.json` | A | 集計と評価器を監査 |
| 後方向再同期攻撃後の回路終了3/3 | `results/crypto-analysis/backward-ipr-live-statistics.json` | A/C | 集計と評価器を監査し、隔離網で新規取得 |

公式パッケージ版の取得条件、ハッシュ、負の対照、限界は`research/PACKAGED_TOR_EVALUATION_ja.md`にまとめた。論文中の用語がTor仕様の語か、本稿独自の評価ラベルかを確認した結果は`research/TERMINOLOGY_AUDIT_ja.md`に記録した。

## TLSレコードとCGO層の復号における入力分離

ストリームを一時停止した10試行の個別評価JSONはスキーマ0.3で保存され、集計器が互換変換してスキーマ0.4の`summary.json`を生成する。

`postprocess_pcap_core_case.sh`が復号処理へ渡すのは、取得済みコアダンプ、対応ELF/DWARF、PCAPだけである。最初に所有関係と構造を解析し、全ホップのCGO暗号コンテキストを検証できた回路を`e3-circuit-manifest.json`へ固定する。このファイル名は過去版との対応のため維持している。CGO抽出器とTLS抽出器は同じ対象回路一覧を必須入力とし、そこにない回路を処理しない。両抽出器はControl Protocol由来の回路IDを受け取らない。再生用入力`CGR2`にはCGO状態とPCAP由来暗号文だけを格納し、正解ホップと正解平文を含めない。

ストリームを一時停止した10試行では、動的フックの`cell.json`を後処理の評価器だけが読む。セル・TLS境界を観測しない固定遅延取得による自己ビルド版6試行と公式パッケージ版6試行では動的セルフックを使わず、CGO認証により候補を一意化した後だけ評価用マーカーを確認する。公式パッケージ版の1試行では、CGO認証に成功したSENDMEセルを得たが、評価用マーカーを含まなかった。混在回路は方式分類には残すが、全ホップCGO条件を満たさないため、TLS・CGO通信復元処理の対象回路一覧へ入れない。

## 集計再生成例

```sh
python3 experiments/evaluate_uncontrolled_pcap_repetitions.py \
  --run results/uncontrolled-pcap/rep-p2-a \
  --run results/uncontrolled-pcap/rep-p2-b \
  --run results/uncontrolled-pcap/rep-p2-c \
  --run results/uncontrolled-pcap/rep-p3-a \
  --run results/uncontrolled-pcap/rep-p3-b \
  --run results/uncontrolled-pcap/rep-p3-c \
  --output /tmp/uncontrolled-summary.json

python3 experiments/evaluate_mixed_e3_admission.py \
  --scan results/real-tor-mixed/scan-v2.json \
  --manifest results/real-tor-mixed/e3-circuit-manifest.json \
  --output /tmp/mixed-e3-admission.json
```

## 固定したソース

- C Tor 0.4.9.16: `c51547ca15ea665950dd154e160051c57f5719db`
- C Tor main: `5e28464e3eabb7392283159f14492c53363fac95`
- Arti: `5a39d48e31a2a0417d8850e21e9b8fa002ed1be5`
- torspec: `d5b1ca79a35b811267783ac6555b66476fd900fc`
- Chutney: `6036fae4bd94c53e1f72967b9fb6c10d9c7fbd7e`

公開用アーカイブは`paper/build_public_supplement.sh`が`paper/public-supplement-files.txt`の固定リストから生成する。既定出力は`paper/tor-cgo-forensics-public-supplement-v6.tar.gz`である。収録ファイルのハッシュは`results/SHA256SUMS.paper-v6`に固定する。
