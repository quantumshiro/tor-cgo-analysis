# Tor Project公式Debianパッケージ版の評価

## Material Passport

- ID：`packaged-tor-0.4.9.17-debian12-arm64`
- 種別：コード実験結果
- 状態：完了
- 実施日：2026年11月14日
- 検証状態：再実行済み
- 対象範囲：回路所有関係、入口起点のホップ順、ホップ別CGO確立状態

## 結論

自己ビルドではないTor Project公式Debianパッケージでも、対応する外部デバッグシンボルがあれば、回路所有関係、入口からのホップ順、各ホップのCGO確立状態を復元できた。独立した3個のTorプロセスで36/36回路と108/108ホップを復元した。

この評価はE1からE3までを対象とする。配布パッケージ版を用いたTLSレコードとCGO層の連続復号は、今回の分母へ含めていない。

## 評価対象

公式索引：<https://deb.torproject.org/torproject.org/dists/bookworm/main/binary-arm64/Packages>

| 項目 | 値 |
|---|---|
| オペレーティングシステム | Debian GNU/Linux 12 (bookworm) |
| アーキテクチャ | arm64 / AArch64 |
| Torパッケージ | `tor 0.4.9.17-1~d12.bookworm+1` |
| デバッグシンボル | `tor-dbgsym 0.4.9.17-1~d12.bookworm+1` |
| Tor実行ファイル | ELF64 PIE、動的リンク、ストリップ済み |
| Tor実行ファイルのGNU Build ID | `59de31afcb999ddd92cadb0ff80978b35ac38a9f` |
| OpenSSL | 3.0.22 |

パッケージファイルのSHA-256は、公式索引の値と一致した。

| パッケージ | SHA-256 |
|---|---|
| `tor` | `120aeb1578d88bf87bde41874b112e9471a4510587597700c2cbb9401cf378c2` |
| `tor-dbgsym` | `e92251cf817736d803546e09ff20a358a41c724a4f01b25d4b6783d0e60df8d9` |

外部デバッグファイルのGNU Build IDはTor実行ファイルと一致した。GDBから`origin_circuit_t`の型と`global_origin_circuit_list`の位置を解決できることも、回路生成前に確認した。

## 実験手順

各試行でChutney隔離網を新規作成した。第三者のTor通信は使用していない。

1. Tor Project公式パッケージから`tor`と`tor-gencert`を展開した。
2. 同一バージョンの`tor-dbgsym`から、GNU Build IDに対応する外部デバッグファイルを展開した。
3. 公式パッケージのTorだけを用いて、隔離網の認証局、リレー、クライアントを起動した。
4. 入口、中継、出口を指定した3ホップ回路を12件作成した。
5. Control Protocolから取得前後の回路一覧と経路を保存した。
6. クライアントを停止し、`gcore`でコアダンプを取得した後に再開した。
7. ストリップ済み実行ファイル、対応する外部デバッグシンボル、コアダンプだけを用いて静的解析した。
8. 解析後に、制御下12回路の識別子と経路をControl Protocolの記録と比較した。

## 結果

| 独立起動 | 制御下回路 | 所有回路として復元 | 入口起点経路が一致 | CGO確立ホップ | 解析エラー |
|---:|---:|---:|---:|---:|---:|
| 1 | 12 | 12 | 12 | 36 | 0 |
| 2 | 12 | 12 | 12 | 36 | 0 |
| 3 | 12 | 12 | 12 | 36 | 0 |
| 合計 | 36 | 36 | 36 | 108 | 0 |

独立単位をTorプロセスとした成功数は3/3である。二側95% Wilsonスコア区間は43.85--100%である。この区間は固定した一つの配布条件での成立確認を表す。異なるディストリビューションや将来バージョンにおける成功率を推定するものではない。

## 負の対照

### 外部デバッグシンボルなし

GDBのデバッグファイル探索先を空の場所へ限定した。解析器は型情報の欠如を報告し、終了状態3で終了した。回路は出力されなかった。

### 異なるBuild IDのデバッグファイル

別ビルドのTor実行ファイルを、正しい外部デバッグファイルの場所へ配置した。GDBはBuild IDが異なるという警告を出し、そのファイルを読み込まなかった。解析器は回路を出力しなかった。

### 異なる実行ファイル

正しい配布実行ファイルは、コアダンプ内で比較可能な368,640バイトのうち352,300バイトが一致した。一致率は95.57%であり、設定した75%の条件を満たした。別ビルドのTor 0.4.9.16は146,039バイトだけが一致した。一致率は39.62%であり、型解析を始める前に拒否された。

## 解釈

配布Torの実行ファイルがストリップ済みであること自体は、解析を不可能にしない。必要なのは、取得した実行ファイルと同じGNU Build IDを持つ外部デバッグシンボルである。

実務上は、コアダンプだけでなく、実行ファイル、共有ライブラリ、パッケージ版、GNU Build ID、外部デバッグシンボルを一緒に保全する必要がある。外部デバッグシンボルを後日取得する場合は、取得時のパッケージと完全に同じ版が配布元に残っていることを確認する必要がある。

## 限界

- Tor Project公式Debian 12 arm64パッケージ一種類だけを評価した。
- 3個の独立プロセスは成立確認にはなるが、一般的な成功率を精密に推定できない。
- 配布パッケージ版ではE1からE3だけを評価した。TLSレコードとCGO層の連続復号は未評価である。
- デバッグシンボルを入手できない取得物へ、型情報を自動推定する方法は示していない。
- OpenSSLの内部構造が異なる場合は、秘密抽出用プロファイルを別途検証する必要がある。

## 成果物

- 集計：`results/generalization/summary-official-package-0.4.9.17.json`
- パッケージ由来情報：`results/generalization/official-package-provenance.json`
- 外部デバッグシンボルなし：`results/generalization/official-package-no-debug-symbols.json`
- Build ID不一致：`results/generalization/official-package-wrong-debug-symbols.json`
- 正しい実行ファイルの対応検査：`results/generalization/official-package-executable-positive.json`
- 誤った実行ファイルの対応検査：`results/generalization/official-package-executable-wrong.json`
- パッケージ由来情報の記録器：`experiments/record_packaged_tor_metadata.py`
