# YARA Rule Creator

セキュリティエンジニア向けのYARAルール作成支援デスクトップアプリケーション

## 機能

### 1. ルールテンプレート生成
- **Basic**: シンプルなルールテンプレート
- **Strings**: 文字列ベースの検出ルール
- **PE Imports**: PEインポートベースの検出ルール
- **Behavioral**: 振る舞いパターン検出ルール

### 2. 構文チェック・バリデーション
- yara-pythonによるコンパイルチェック
- plyaraによる品質チェック（警告）
  - メタデータの欠落
  - 短すぎる文字列
  - 汎用的すぎるパターン

### 3. ファイルからの文字列抽出
- ASCII/Unicode文字列の抽出
- PE情報の解析（インポート、エクスポート、セクション）
- 文字列の自動分類
  - URL, IPアドレス, メール
  - レジストリキー, ファイルパス
  - API呼び出し, DLL名
  - Mutex, コマンド
- YARA文字列定義の自動生成

### 4. ルールテスト
- ファイルアップロードでのテスト
- ディレクトリ指定でのスキャン
- マッチ結果の詳細表示

## インストール

```bash
# 依存関係のインストール
pip install -r requirements.txt

# アプリケーションの起動
python -m yara_creator.main

# サーバーモードで起動（ブラウザからアクセス）
python -m yara_creator.main --server
```

## ビルド（exe化）

```bash
# PyInstallerのインストール
pip install pyinstaller

# ビルド実行
python build.py

# クリーンビルド
python build.py rebuild
```

ビルド完了後、`dist/YaraRuleCreator/` フォルダ内に実行ファイルが生成されます。

## 技術スタック

- **バックエンド**: Python + FastAPI
- **フロントエンド**: HTML/CSS/JavaScript + CodeMirror
- **デスクトップ化**: PyWebView
- **YARA処理**: yara-python, plyara, pefile

## ディレクトリ構造

```
yara_creator/
├── __init__.py
├── main.py              # エントリーポイント
├── config.py            # 設定
├── api/
│   ├── routes/          # APIエンドポイント
│   │   ├── templates.py
│   │   ├── validation.py
│   │   ├── extraction.py
│   │   └── testing.py
│   └── models/          # Pydanticモデル
│       ├── requests.py
│       └── responses.py
├── core/
│   └── services/        # ビジネスロジック
│       ├── template_service.py
│       ├── validation_service.py
│       ├── extraction_service.py
│       └── testing_service.py
└── frontend/
    ├── static/
    │   ├── css/main.css
    │   └── js/app.js
    └── templates/index.html
```

## キーボードショートカット

- `Ctrl+S`: ルールを保存
- `Ctrl+Enter`: バリデーション実行

## ライセンス

MIT License
