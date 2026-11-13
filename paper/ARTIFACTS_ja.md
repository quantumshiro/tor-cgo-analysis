# 論文評価アーティファクト

公開リポジトリ：<https://github.com/quantumshiro/tor-cgo-analysis>。論文の評価対象はリリースタグ`v0.0.2`で固定する。タグが指すコミットは`git rev-list -n 1 v0.0.2`で確認できる。

## 再現可能性の区分

公開物には生のコアダンプ、PCAP、TLS秘密、CGO秘密、復号済みrecordを含めない。そのため、次の三段階を区別する。

- **A：結果監査** — 集計JSON、個別の非秘密結果、SHA-256、解析コードを照合できる。
- **B：集計再生成** — 公開した個別の非秘密結果から、論文中の集計を再生成できる。
- **C：新規再取得** — 固定コミットの第三者ソースを別途取得・buildし、隔離網で新しいcore/PCAPを生成してパイプラインを再実行できる。

除外した生データが必要な「保存済み取得物そのものの完全replay」は公開版だけではできない。この制約をCと表記しない。

| 主張・評価 | 公開結果 | 区分 | 公開版で可能な検証 |
|---|---|---:|---|
| 144/144回路、432/432ホップ | `results/generalization/summary-arm64-replicated.json` | A/C | 集計と解析器を監査し、`run_generalization_case.sh`で新規取得 |
| 境界制御E1--E5、10/10 | `results/open-circuit-impact/independent-v3/summary.json` | B/C | 公開した10個の評価JSONを`evaluate_full_pcap_repetitions.py`で再集計 |
| stream非停止・境界非選択、6/6 | `results/uncontrolled-pcap/summary.json` | B/C | 6個の評価JSONを`evaluate_uncontrolled_pcap_repetitions.py`で再集計し、`run_uncontrolled_pcap_case.sh`で新規取得 |
| 混在回路10件を後段へ0件投入 | `results/real-tor-mixed/mixed-e3-admission.json` | B/C | 公開したscanとmanifestを`evaluate_mixed_e3_admission.py`で再評価 |
| E3強制境界の負対照4/4 | `results/open-circuit-impact/e3-enforcement-negative/summary.json` | A/C | 結果監査と`test_e3_enforcement.py`による新規fixture評価 |
| CGO状態7分類、7,168件 | `results/open-circuit-impact/negative-state-matrix-v2/summary.json` | A/C | 変更済みC test sourceを監査し、別途build後に再実行 |
| TLS負対照 | `results/open-circuit-impact/tls-negative-controls-v2/summary.json` | A/C | 結果と`run_tls_negative_controls.py`を監査し、新規取得物で再実行 |
| 実行ファイル互換性の正負対照 | `results/robustness/build-verification/` | A/C | `verify_core_executable.py`の判定と結果を監査 |
| 真に読取り不能なPT_LOAD対照 | `results/page-loss-absent/summary.json` | A/C | 欠損生成・評価スクリプトと集計を監査 |
| 直前セル0/3 | `results/open-circuit-impact/past-cell-statistics.json` | A | 集計と評価器を監査 |
| 後方向再同期攻撃後の回路終了3/3 | `results/crypto-analysis/backward-ipr-live-statistics.json` | A/C | 集計と評価器を監査し、隔離網で新規取得 |

## 二層復号の入力分離

`postprocess_pcap_core_case.sh`が復号処理へ渡すのは、取得済みcore、対応ELF/DWARF、PCAPだけである。最初に所有関係と構造を解析し、E3を通過した全ホップCGO回路を`e3-circuit-manifest.json`へ固定する。CGO抽出器とTLS抽出器は同じmanifestを必須入力とし、そこにない回路を処理しない。両抽出器はControl Protocol由来の回路IDを受け取らない。再生用入力`CGR2`にはCGO状態とPCAP由来暗号文だけを格納し、正解ホップと正解平文を含めない。

境界制御10試行では、動的フックの`cell.json`を後処理の評価器だけが読む。境界非選択6試行では動的セルフックを使わず、CGO認証により候補を一意化した後だけ評価markerを確認する。混在回路はE3の方式分類には残すが、全ホップCGO条件を満たさないためE4--E5用manifestへ入れない。

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

公開用アーカイブは`paper/build_public_supplement.sh`が`paper/public-supplement-files.txt`の固定リストから生成する。既定出力は`paper/tor-cgo-forensics-public-supplement-v4.tar.gz`である。収録ファイルのハッシュは`results/SHA256SUMS.paper-v4`に固定する。
