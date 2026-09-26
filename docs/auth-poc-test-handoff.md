# NUTMEG 共通認証基盤 — 開発引き継ぎ手順書

このドキュメントは、Claude.aiでの設計相談の内容をまとめ、Claude Codeでの実装作業にそのまま引き継ぐためのものです。冒頭の「Claude Codeで最初にやること」から着手してください。

---

## 0. Claude Codeで最初にやること

1. 作業ディレクトリを作成し、`git init`する
2. GitHub CLIの認証状態を確認する

   ```bash
   gh auth status
   ```

   - 未認証の場合は `gh auth login` を対話的に実行し、あなた自身のGitHubアカウントでログインする（これはClaude自身では代行できません。ブラウザでの認証操作が必要です）
3. 認証済みになったら、公開リポジトリを作成してpushする

   ```bash
   gh repo create <リポジトリ名> --public --source=. --remote=origin
   git add .
   git commit -m "docs: 認証基盤設計メモを追加"
   git push -u origin main
   ```

   `<リポジトリ名>` は例えば `nutmeg-auth-platform` など、わかりやすい名前にしてください。
4. このMarkdownファイル（`nutmeg-auth-platform-handoff.md`）をリポジトリ直下（または`docs/`配下）に配置してコミットする

---

## 1. 背景・目的

- NUTMEG関連の各プロダクト（nutfesBingo、FinanSu、GM2 等）で個別に実装されているログイン認証を、共通の認証基盤にまとめたい
- **認可（authz）は各プロダクト側に残す**。認証基盤の役割は「このユーザーは誰か」を答えることだけに絞る
- 各プロダクトの既存`users`テーブルには、認証基盤が発行する固有ID（外部キー的な値）を持たせる方針

## 2. これまでに確定した方針

### 2.1 Google Workspaceについて
- 学生団体単体ではGoogle Workspace for Education／for Nonprofitsのいずれも対象外で、無料取得は現実的ではない
- Google Drive権限の一元化は今回のスコープ外とし、当面は現状の運用（メールアドレスベースの手動管理）を維持する

### 2.2 認証方式の2つの選択肢 → **案A（Firebase Authentication）に決定**

2026-09-16、案Aで進めることを決定。ホワイトリスト機構（2.3節）はFirebase標準機能では実現できないため、独自実装（DBでの承認管理＋バックエンドでのID Token検証後チェック）とする方針も合わせて確定。

**案A: Firebase Authentication（無印）を軸にする**
- 既存のパスワードログインとGoogle SSOの両方をFirebase Auth上に統合
- 既存ユーザーの移行は Admin SDKの`importUsers()`で一括インポート（bcrypt等の既存ハッシュアルゴリズムを指定すれば、パスワードリセットを強制せず移行可能）
- **Identity Platformへのアップグレードは絶対に踏まない**こと（MFA・ブロッキング関数・SAML/OIDCプロバイダ機能を有効化すると自動的に不可逆でアップグレードされ、無料枠が「無制限」→「1日3,000アクティブユーザー」等に制限された上で課金対象になる）
- フロントエンドはFirebase Client SDKで`signInWithPopup`等を呼ぶだけの薄い受け口に留め、ID Tokenの検証・whitelist照合・セッション発行はすべてバックエンド（認証基盤API）側で行う
- **注意**: Firebase Admin SDKの公式対応言語はNode.js / Java / Python / Go / C#で、**Rubyは非対応**。Railsからは`ruby-jwt`等でID Tokenを自前検証するか、Identity Toolkit REST APIを直接叩く実装が必要になる。認証基盤API自体をGoで書くなら公式SDKがそのまま使える

**案B: Firebaseを使わず、生のGoogle OAuth（サーバーフロー）を自前実装する**
- フロントエンドにJS SDKは一切不要。「Googleでログイン」は単なるリンクで、クリックしたらバックエンドがGoogleの認証URLへリダイレクトし、コールバックの受け取り・トークン交換・ID Token検証まで全部バックエンドで完結する
- Rails: `omniauth-google-oauth2` gemでほぼそのまま実現可能
- Go: `golang.org/x/oauth2/google` パッケージで実現可能
- Firebase自体を使わないため、Admin SDKの言語対応問題は発生しない
- 一方で、Firebaseの一括パスワード移行機能のような便利機能は使えないため、既存パスワードの扱いは現状の各プロダクトの実装を踏襲する設計が必要

### 2.3 Google公式ドキュメントで確認した技術的事実
- ユーザーの一意識別子には`email`ではなく`sub`クレームを使うこと（emailは変更されうる）
- `hd`（Hosted Domain）クレームは、Google WorkspaceまたはCloud組織に属するアカウントにのみ付与される。**個人のgmail.comアカウントには付与されない**ため、「`.nutfes@gmail.com`のようなメール命名規則での絞り込み」はGoogle側の機能では実現できず、**自作のwhitelist機構（アプリ側ロジック）が必須**
- サフィックスパターン一致のみだと「誰でも同じ命名規則のgmailアドレスを自作できてしまう」ため、実効的なアクセス制御にはならない。真に絞り込みたいなら**ホワイトリスト方式（許可済みメールアドレスをDB管理）が本命**。運用負荷を抑えたいなら「パターン一致で一次受付→運営承認でapproved」のハイブリッドも現実的

### 2.4 運用方針（2026-09-26決定）
- Googleログインの対象はNUTMEGメンバー（実行委員）のみ。GM2の参加団体は従来のパスワードログインのまま
- ホワイトリストは**事前登録制**。運営が許可するメールアドレスを登録し、載っていない人は拒否するだけ（承認申請・承認待ちの仕組みは持たない）
- 名簿に載っているがプロダクトにアカウントがない人は、そのプロダクトの新規登録画面へ。メールはGoogleのもので固定し、残りの項目を入力して登録する。ロールは各プロダクトの一番低いものから始め、権限は各プロダクトで上げる

## 3. テーブル設計（たたき台）

### 認証基盤側

| テーブル | カラム | 備考 |
|---|---|---|
| `users` | `id`(uuid, PK) / `google_sub`(unique) / `email`(nullable, キャッシュ用) / `display_name` / `created_at` / `updated_at` | ※案Aを採用しFirebaseに全面移行する場合、このテーブルは不要になりFirebaseの`uid`をそのまま使う |
| `clients` | `id`(uuid, PK) / `client_id`(unique) / `client_secret_hash` / `name`（例: "nutfesBingo"） / `redirect_uris` / `is_active` | 「どのサービスからのリクエストを受け付けるか」の管理台帳 |
| `user_client_links` | `user_id`(FK) / `client_id`(FK) / `first_seen_at` / `last_seen_at` | ユーザーとプロダクトの多対多の利用ログ |
| `allowed_emails`（ホワイトリスト） | `email`(PK, 小文字で保存) / `added_by` / `created_at` | ログイン許可の実体。運営が事前登録したメールだけを通す（2026-09-26決定。承認申請の仕組みは持たない） |

### 各プロダクト側（既存usersテーブルへの追加）

| カラム | 備考 |
|---|---|
| `auth_platform_user_id` | 認証基盤発行の固有ID（Firebase採用時は`firebase_uid`）。unique制約推奨 |
| 既存の役割・権限カラム | 認可はプロダクト側の責務のまま変更しない |

## 4. 全体アーキテクチャ（案Aの場合）

```
[各プロダクト]
   ├─ 既存パスワードログインフォーム ──┐
   └─ 「Googleでログイン」ボタン ──────┤
                                     ↓
                Firebase Auth（共有プロジェクト・両プロバイダ有効）
                                     ↓ ID Token
                自作の認証基盤API（Go/Rails・トークン検証＋whitelist照合）
                                     ↓
                       各プロダクトへ独自セッション発行
```

## 5. 次のアクション（Claude Codeでの作業候補）

1. ~~案A・案Bどちらで進めるか決定する~~ → **案A（Firebase Authentication）に決定済み**
2. 認証基盤API自体の実装言語を決定する（Go推奨。理由: Firebase Admin SDK公式対応）
3. リポジトリのディレクトリ構成を作る（例: `cmd/`, `internal/`, `docs/`）
4. Firebaseプロジェクトの新規作成、Sign-in method有効化（メール/パスワード・Google）はFirebaseコンソールでの手動操作が必要
5. 上記テーブル設計をもとにマイグレーションファイルを作成（`whitelist`テーブルは独自実装として必須）
6. 認証基盤APIのエンドポイント設計（トークン検証エンドポイント、whitelist承認用の管理エンドポイント等）に着手

---

*このファイルは Claude.ai での設計相談セッションの内容を要約したものです。実装の詳細判断はClaude Codeでのセッションで詰めてください。*
