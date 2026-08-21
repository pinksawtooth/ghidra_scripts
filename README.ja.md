# Ghidra Scripts

[English](README.md)

Ghidraでのリバースエンジニアリングやマルウェア解析を支援する、PythonおよびJavaスクリプト集です。

## ApplySig.py

IDA FLIRTの`.sig`ファイルを読み込み、現在のプログラム内の関数と照合します。一致した既定名の`FUN_`関数をシグネチャ内の名前へ変更します。**Tools > Function ID > ApplySig**から実行できます。

## ApplyFlirtSignatures.java

`ApplySig.py`を拡張した、より厳密で包括的なFLIRT解析を行うネイティブJava実装です。Rizinやサイドカーファイルを必要とせず、バイナリIDASGNバージョン5から10を直接読み込みます。プログラムを変更する前にパターン、CRC、末尾バイトを検証し、未定義の関数候補を検出して作成することもできます。曖昧な一致は推測で適用せず、コメントやブックマークで記録します。ドライランとJSONレポートにも対応しています。**Tools > FLIRT > Apply FLIRT Signatures**から実行できます。

## findcrypt.py

既知の暗号関連定数を、完全一致する配列、疎な配列、即値オペランドから検索し、一致箇所へラベルやコメントを追加します。

## shellcode_hash_search.py

即値やDWORD配列をシェルコードAPIハッシュDBで検索します。解決したAPI名をコメントとして追加し、連続する一致箇所から構造体を作成することもできます。

## struct_typer.py

構造体メンバーまたはスタック変数の名前を、開いているデータ型マネージャー内の関数定義と照合し、対応する関数ポインター型を適用します。照合前に正規表現で名前のプレフィックスを除去することもできます。

## make_sc_hash_db.py

指定ディレクトリ内のPEファイルからエクスポートを読み取り、代表的なシェルコードAPIハッシュを計算して、`shellcode_hash_search.py`用のSQLite DBを生成する単体Pythonツールです。`pefile`パッケージが必要です。

## consts.py

`findcrypt.py`が使用する定数データベースです。直接実行すると、対応しているアルゴリズムと定数名を表示します。

## 同梱データ

`sc_hashes.zip`には、`shellcode_hash_search.py`が使用する構築済みの`sc_hashes.db`が含まれています。`sc_hashes.db`をスクリプトと同じディレクトリへ展開するか、実行時のダイアログでDBを選択してください。

手元のPEファイルからDBを作成する場合は、次のコマンドを実行します。

```text
python make_sc_hash_db.py <db_path> <dll_dir>
```

## ライセンス

[LICENSE](LICENSE)を参照してください。
