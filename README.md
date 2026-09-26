# auth-poc-test

NUTMEG関連プロダクトの共通認証基盤の個人PoC。設計の背景と決定事項は
[docs/auth-poc-test-handoff.md](docs/auth-poc-test-handoff.md) を参照。

- 対象: NUTMEGメンバー（実行委員）のみ。GM2の参加団体は従来のパスワードログインのまま
- 認証: Firebase Authentication（無印。Identity Platformへは絶対にアップグレードしない）
- 認可: 各プロダクト側の責務のまま。このAPIは「このユーザーは誰か」だけを答える
- ホワイトリスト: 運営が事前登録したメールアドレスだけを通す名簿（Firebase標準機能では実現できないため独自実装）

## 全体の流れ

```
運営: 名簿（ホワイトリスト）にメンバーのメールアドレスを登録しておく
  ↓
メンバー: 各プロダクトで「Googleでログイン」
  ↓
認証基盤: ID Tokenを検証し、名簿に載っているか確認
  ├ 載っていない → 拒否（申請や承認待ちの仕組みはない）
  └ 載っている
      ↓
各プロダクト: そのメールアドレスのアカウントがあるか
  ├ ある → ログイン完了（初回はメールで既存アカウントに自動で紐付け）
  └ ない → 新規登録画面へ。メールはGoogleのもので固定、残りの項目を入力して登録 → ログイン完了
```

## セットアップ

1. Firebaseコンソールで新規プロジェクトを作成し、Sign-in method で
   メール/パスワード・Google を有効化する（手動作業。Admin SDK・Client SDKからは自動化不可）
2. プロジェクト設定 > サービスアカウント からサービスアカウントキー(JSON)を発行し、
   リポジトリ直下に `service-account.json` として配置する（`.gitignore`済み）
3. `.env.example` を `.env` にコピーし、`AUTH_PLATFORM_ADMIN_KEY` を任意のランダム文字列に変更する
4. 依存を取得して起動する

   ```bash
   go mod tidy
   go run ./cmd/server
   ```

## ホワイトリスト（名簿）

- 運営が、ログインを許可するメールアドレスを事前に登録する。載っているかどうかだけを見る
- 名簿にない人がログインしようとしても拒否するだけで、名簿には何も追加しない
- メールアドレスは大文字・小文字を区別しない
- 名簿から削除すると、次のログインから拒否される（各プロダクトで発行済みのセッションは、各プロダクト側の有効期限まで残る）
- 名簿の操作には、`.env` の `AUTH_PLATFORM_ADMIN_KEY`（管理用の共有パスワード。`X-Admin-Key` ヘッダで送る）が必要。
  PoCの仮の仕組みで、本番では運営メンバー自身のGoogleログインで管理する形に置き換える想定

## エンドポイント

| メソッド | パス | 用途 |
|---|---|---|
| POST | `/v1/auth/verify` | 各プロダクトのサーバーが呼ぶ。Firebase ID Tokenを検証し、名簿に載っているかを返す |
| GET | `/v1/admin/whitelist` | 名簿の一覧。要`X-Admin-Key` |
| POST | `/v1/admin/whitelist` | 名簿に登録（`{"email", "added_by"}`）。要`X-Admin-Key` |
| DELETE | `/v1/admin/whitelist/{email}` | 名簿から削除。要`X-Admin-Key` |

`POST /v1/auth/verify` の応答の `status`:

| status | HTTP | 意味 |
|---|---|---|
| `allowed` | 200 | 名簿に載っている。ログインしてよい |
| `not_whitelisted` | 403 | 名簿に載っていない |
| `email_unverified` | 403 | メールアドレスの所有確認が済んでいない（確認メールのリンクを踏んでいないメール/パスワードのアカウント） |
| （`error`のみ） | 401 | ID Tokenが不正 |

`email_unverified` を拒否するのは、名簿をメールアドレスで照合しているためです。この確認がないと、他人の登録済みメールアドレスで
Firebaseアカウントを作るだけで通過できてしまいます。

## 動作確認

`go run ./cmd/server` で起動したあと http://localhost:8080/ を開く（`web/`をこのサーバーが配信する）。
`web/firebase-config.js` は `web/firebase-config.example.js` をコピーしてFirebaseのWeb SDK設定を入れる。

1. 「1.」で管理キーと登録者名を入れ、自分のGoogleアカウントのメールアドレスを名簿に登録する
2. 「2.」でGoogleログインし、「認証基盤で確認」が `allowed`（200）になることを確認する
3. 「3. GM2」「4. FinanSu」で「Googleで〜にログイン」を押す。アカウントがなければ新規登録フォームが出る

## プロダクトへの組み込み例

- [examples/gm2-mock](examples/gm2-mock) — group-manager-2（Rails + devise_token_auth）の認証部分を再現したモックへの組み込み（:3100）
- [examples/finansu-mock](examples/finansu-mock) — FinanSu（Go + Echo、独自の `mail_auth` / `session`）の認証部分を再現したモックへの組み込み（:3200）

どちらも、認証基盤でID Tokenと名簿を確認したあと、各プロダクトのアカウントに紐付けて（なければ新規登録して）、
**そのプロダクトの既存のログイントークンを発行する**形にしている。既存のAPIと権限判定には手を入れない。
Googleから新規登録したアカウントは、各プロダクトで一番低いロールになる。権限は各プロダクトの管理画面で上げる。

## 未実装（PoCのスコープ外）

- 名簿の管理を、共有パスワードではなく運営メンバーのGoogleログインで行う
- `/v1/auth/verify` の呼び出し元の認証（`clients`テーブルでのclient_id/secret確認）
- `clients` / `user_client_links` テーブル（手順書3節の設計はまだコード化していない）
- SQLite以外のDB（本番想定ならPostgres等への差し替えが必要）
