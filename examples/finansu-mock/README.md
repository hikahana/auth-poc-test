# finansu-mock

FinanSu の**認証まわりだけ**を再現した Go API です。認証基盤（リポジトリ直下のGoサーバー）を
本物のFinanSuに組み込む前に、ここで組み込み方を検証します。

- FinanSuと同じ Echo v4.11.4
- `users` / `roles` / `mail_auth` / `session` テーブルは `mysql/prdDb/*.sql` の定義を写したもの（DBだけSQLite）
- ユーザー作成・メール認証・`current_user` は、FinanSuの `openapi.yaml` と usecase から、ルートとパラメータの形（クエリパラメータ、`Access-Token` ヘッダ）を写したもの
- OpenAPIのコード生成とwireによるDIは省略し、`handler → usecase → repository` の層構成だけ合わせた

## FinanSuの既存認証（GM2との違い）

- メールとパスワード（bcrypt）は `users` ではなく `mail_auth` テーブルにある
- ログインすると10文字のランダムな `accessToken` を発行して `session` に保存する。セッションはユーザーごとに1つで、再ログインすると古いトークンは無効になる
- APIの認証は `Access-Token` ヘッダ。ロールごとの権限判定はフロント側で `current_user` の `roleID` を見て行っている

## 仕組み

```
ブラウザ ──(Firebase SDK)──> Firebase Auth ──> ID Token
   │
   └─ POST /mail_auth/firebase_signin {"id_token": ...}
         FinanSu ──(サーバー間)──> 認証基盤 POST /v1/auth/verify
                                     ├ ID Tokenを検証
                                     └ whitelist が approved か
         FinanSu: users.auth_platform_user_id で既存ユーザーを特定
                  (初回は検証済みメールで mail_auth.email と照合して紐付け)
         FinanSu: 既存のパスワードログインと同じ処理で session を作り accessToken を返す
```

返す `accessToken` はパスワードログインと同じものです。そのため `current_user` もフロントの権限判定も変更なしで動きます。

| 状況 | 応答 |
|---|---|
| ID Tokenが不正 | 401 |
| whitelistで未承認（pending / rejected / email_unverified） | 403 |
| 承認済みだが、そのメールアドレスのFinanSuユーザーがいない、または論理削除済み（`is_deleted`） | 403 |
| そのFinanSuユーザーが既に別のFirebaseアカウントと紐付いている | 409 |
| 認証基盤に接続できない | 502 |

ID Tokenは、ほかの `mail_auth` 系ルートのようなクエリパラメータではなく、JSONボディで受け取ります。
クエリに載せるとアクセスログ（Echoのloggerミドルウェア）に資格情報が残るためです。

## 起動

認証基盤（リポジトリ直下、`:8080`）を先に起動しておきます。

```bash
go run .
```

モックは **http://localhost:3200** で起動します（本物のFinanSu APIの1323番とは被りません）。
初回起動時に `user@example.com`（roleID 1）と `admin@example.com`（roleID 2）が作られます。パスワードはどちらも `password` です。

動作確認は http://localhost:8080/ の「5. FinanSuモック連携」から行います。

1. 「1.」でGoogleログインする
2. 「5.」の①で、同じメールアドレスのFinanSuユーザーを作る（ロールも選べる）
3. 「3.」でそのメールアドレスをwhitelistで承認する
4. 「5.」の②「FirebaseでFinanSuにログイン」→ ③「current_user」で、`authPlatformUserID` と、①で選んだ `roleID` が入っていることを確認する

テストは次のコマンドで実行できます。

```bash
go test ./...
```

## 本物のFinanSuへ移植するときの差分

| 移植先 | 内容 |
|---|---|
| `mysql/migrations/000007_*.{up,down}.sql` | [mysql-migrations/](mysql-migrations) をそのまま置く（`users.auth_platform_user_id` を追加） |
| `openapi/openapi.yaml` | `POST /mail_auth/firebase_signin`（JSONボディ `id_token`）を追加し、`make gen` |
| `api/externals/repository/` | `user_repository` に `FindByAuthPlatformUserID` と `LinkAuthPlatformUserID`、`mail_auth_repository` に `FindMailAuthByUserID` を追加 |
| `api/internals/usecase/` | `firebase_auth_usecase.go` と `authplatform` クライアントを追加し、wireのプロバイダに登録 |
| `api/externals/handler/` | `PostMailAuthFirebaseSignin` を追加 |
| 環境変数 | `AUTH_PLATFORM_URL` |
| フロント（`view/next-project`） | Firebase SDKでID Tokenを取得して `/mail_auth/firebase_signin` に送り、返ってきた `accessToken` を既存ログインと同じ場所に保存する |

移植するコードは、このモックと同じくプレースホルダ（`?`）でSQLを組み立ててください。本物の
`session_repository.go` と `mail_auth_repository.go` は、メールアドレスやアクセストークンを文字列連結で
SQLに埋め込んでいるため、そこには乗らないようにします。
