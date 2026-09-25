# auth-poc-test

NUTMEG関連プロダクトの共通認証基盤の個人PoC。設計の背景と決定事項は
[docs/auth-poc-test-handoff.md](docs/auth-poc-test-handoff.md) を参照。

- 認証: Firebase Authentication（無印。Identity Platformへは絶対にアップグレードしない）
- 認可: 各プロダクト側の責務のまま。このAPIは「このユーザーは誰か」だけを答える
- ホワイトリスト: Firebase標準機能では実現できないため独自実装（SQLiteでpending/approved/rejectedを管理）

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

## エンドポイント

| メソッド | パス | 用途 |
|---|---|---|
| POST | `/v1/auth/verify` | クライアントが取得したFirebase ID Tokenを検証し、whitelistの状態を返す |
| GET | `/v1/admin/whitelist` | whitelist一覧（`?status=pending`等でフィルタ可）。要`X-Admin-Key`ヘッダ |
| POST | `/v1/admin/whitelist` | 事前登録（承認前のメールアドレスをpendingで追加）。要`X-Admin-Key`ヘッダ |
| POST | `/v1/admin/whitelist/approve` | 指定メールアドレスをapprovedにする。要`X-Admin-Key`ヘッダ |
| POST | `/v1/admin/whitelist/reject` | 指定メールアドレスをrejectedにする。要`X-Admin-Key`ヘッダ |

`POST /v1/auth/verify` は、初めて見るメールアドレスであれば自動的に `pending` として
whitelistに登録した上で403を返す（＝ログイン申請の一次受付を兼ねる）。運営が
`/v1/admin/whitelist/approve` で承認するまではログインを許可しない。

`email_verified` が `false` のトークン（確認メールのリンクを踏んでいないメール/パスワードのアカウント）は、
whitelistに登録せず `status: "email_unverified"` の403を返す。whitelistはメールアドレスで照合しているため、
この確認がないと、他人の承認済みメールアドレスでFirebaseアカウントを作るだけで通過できてしまう。

## 動作確認

`go run ./cmd/server` で起動したあと http://localhost:8080/ を開く（`web/`をこのサーバーが配信する）。
`web/firebase-config.js` は `web/firebase-config.example.js` をコピーしてFirebaseのWeb SDK設定を入れる。

## プロダクトへの組み込み例

- [examples/gm2-mock](examples/gm2-mock) — group-manager-2（Rails + devise_token_auth）の認証部分を再現したモックへの組み込み

## 未実装（PoCのスコープ外）

- 各プロダクトへ渡す独自セッション/JWTの発行（現状は各プロダクトが自分のセッションを発行する。gm2-mock参照）
- `/v1/auth/verify` の呼び出し元の認証（`clients`テーブルでのclient_id/secret確認）
- `clients` / `user_client_links` テーブル（手順書3節の設計はまだコード化していない）
- SQLite以外のDB（本番想定ならPostgres等への差し替えが必要）
