# 論文評価アーティファクト

論文中の主要主張と、ワークスペース内の検証可能な結果を対応付ける。

公開リポジトリ：<https://github.com/quantumshiro/tor-cgo-analysis>。論文の評価対象はリリースタグ`v0.0.1`で固定する。タグが指すコミットSHAは`git rev-list -n 1 v0.0.1`で検証できる。

| 主張・評価 | 結果ファイル | 再生成コマンド |
|---|---|---|
| 144/144回路、432/432ホップ | `results/generalization/summary-arm64-replicated.json` | `experiments/evaluate_generalization.py`を各評価ディレクトリへ適用 |
| E1--E5を連続検証し、正解情報を分離した二層復号10/10 | `results/open-circuit-impact/independent-v3/summary.json` | 各取得物に`experiments/postprocess_pcap_core_case.sh SOURCE OUTPUT`を実行後、`experiments/evaluate_full_pcap_repetitions.py`で集計 |
| E3強制境界の負対照4/4 | `results/open-circuit-impact/e3-enforcement-negative/summary.json` | `experiments/test_e3_enforcement.py` |
| CGO状態7分類、7,168件の負対照 | `results/open-circuit-impact/negative-state-matrix-v2/summary.json` | `CGO_REPLAY_NEGATIVE_MODE`を7分類、各1,024回として`crypto/cgo/cgo_external_core_replay`を実行 |
| TLS負対照 | `results/open-circuit-impact/tls-negative-controls-v2/summary.json` | `experiments/run_tls_negative_controls.py` |
| 実行ファイル互換性の正負対照 | `results/robustness/build-verification/` | `forensics/verify_core_executable.py` |
| 真に読取り不能なPT_LOAD対照 | `results/page-loss-absent/summary.json` | `experiments/remove_core_load_segment.py`と`experiments/evaluate_absent_segments.py` |
| 直前セル0/3 | `results/open-circuit-impact/past-cell-statistics.json` | `experiments/evaluate_past_cell_repetitions.py` |
| 後方向再同期攻撃後の回路終了3/3 | `results/crypto-analysis/backward-ipr-live-statistics.json` | `experiments/summarize_backward_ipr_live.py` |

## 二層復号の入力分離

`postprocess_pcap_core_case.sh`が復号処理へ渡すのは、取得済みコア、対応ELF/DWARF、PCAPだけである。最初に所有関係と構造を解析し、E3を通過した全ホップCGO回路を`e3-circuit-manifest.json`へ固定する。CGO抽出器とTLS抽出器は同じmanifestを必須入力とし、そこにない回路を処理しない。両抽出器はControl Protocol由来の回路IDを受け取らない。再生用入力`CGR2`にはCGO状態とPCAP由来暗号文だけを格納し、正解ホップと正解平文を含めない。

動的フックの`cell.json`は`evaluate_full_pcap_replay.py`だけが読み、復号処理終了後に候補、認識ホップ、493バイト本文を採点する。評価器は全候補の再生結果を読み、CGO認証に成功した候補が厳密に1件であることも成功条件に含める。10取得物すべてのE1--E5段階別結果は`independent-v3/summary.json`の`stage_success_counts`に記録した。

## 固定したソース

- C Tor 0.4.9.16: `c51547ca15ea665950dd154e160051c57f5719db`
- C Tor main: `5e28464e3eabb7392283159f14492c53363fac95`
- Arti: `5a39d48e31a2a0417d8850e21e9b8fa002ed1be5`
- torspec: `d5b1ca79a35b811267783ac6555b66476fd900fc`
- Chutney: `6036fae4bd94c53e1f72967b9fb6c10d9c7fbd7e`

生のコアダンプ、TLS秘密、CGO秘密は機微情報を含むため公開用アーカイブから除外し、再生成手順、秘密を除いた集計JSON、ハッシュ、合成隔離網の設定を補足資料とする。

公開用アーカイブは`paper/build_public_supplement.sh`が`paper/public-supplement-files.txt`の固定リストから生成する。出力は`paper/tor-cgo-forensics-public-supplement-v3.tar.gz`であり、コアダンプ、PCAP、生のTLS/CGO秘密、復号済みレコードを含めない。

上記の新規集計と中心スクリプトのSHA-256は`results/SHA256SUMS.paper-v3`に固定した。
