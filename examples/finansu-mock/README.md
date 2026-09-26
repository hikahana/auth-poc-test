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
                                     └ 名簿（ホワイトリスト）に載っているか
         FinanSu: users.auth_platform_user_id で既存ユーザーを特定
                  (初回は検証済みメールで mail_auth.email と照合して紐付け)
                  ├ 見つかった → 既存のパスワードログインと同じ処理で session を作り accessToken を返す
                  └ 見つからない → 404 {"registrationRequired": true, "email": ...}
                                    ↓ フロントはメール固定の新規登録フォームを出す
   └─ POST /mail_auth/firebase_signup {"id_token", "name", "bureau_id"}
         FinanSu: 同じく認証基盤で確認 → メールはID Tokenから取り出して users と mail_auth を作成
                  （1トランザクション、roleID 1: user）→ そのままログイン（accessTokenを返す）
```

返す `accessToken` はパスワードログインと同じものです。そのため `current_user` もフロントの権限判定も変更なしで動きます。

新規登録について:

- 入力は本物の新規登録画面（`SignUpView.tsx`）からパスワードを除いた、名前と局だけ。メールアドレスはフォームから受け取らず、サーバー側でID Tokenから取り出す
- ロールは本物の新規登録と同じ `1: user` 固定。権限はFinanSu側で上げる
- `session.auth_id` が `mail_auth` を参照するため、`mail_auth` の行も作る。パスワードは推測できないランダム値のハッシュを入れ、Googleでしか入れないようにする

| 状況 | 応答 |
|---|---|
| ID Tokenが不正 | 401 |
| 名簿に載っていない / メール未確認（`not_whitelisted` / `email_unverified`） | 403 |
| 名簿に載っているがFinanSuにアカウントがない（ログイン時） | 404 `registrationRequired: true` と `email` |
| アカウントが論理削除済み（`is_deleted`） | 403 |
| 新規登録時、既にアカウントがある | 409 |
| そのFinanSuユーザーが既に別のFirebaseアカウントと紐付いている | 409 |
| 新規登録で名前か局が空 | 400 |
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

動作確認は http://localhost:8080/ から行います。

1. 「1.」で自分のGoogleアカウントのメールアドレスを名簿に登録する
2. 「2.」でGoogleログインする
3. 「4. FinanSu」の「GoogleでFinanSuにログイン」を押す。FinanSuにアカウントがなければ、メール固定の新規登録フォームが出るので、名前と局を入れて登録する
4. 「current_user」で `authPlatformUserID` が入り、`roleID` が 1（user）になっていることを確認する

既にFinanSuアカウントを持っている人が初めてGoogleで入る場合（メールで自動紐付け）は、「4.」の
「（テスト用）既存FinanSuユーザーを作る」で先にパスワード登録しておくと試せます。

テストは次のコマンドで実行できます。

```bash
go test ./...
```

## 本物のFinanSuへ移植するときの差分

| 移植先 | 内容 |
|---|---|
| `mysql/migrations/000007_*.{up,down}.sql` | [mysql-migrations/](mysql-migrations) をそのまま置く（`users.auth_platform_user_id` を追加） |
| `openapi/openapi.yaml` | `POST /mail_auth/firebase_signin`（`id_token`）と `POST /mail_auth/firebase_signup`（`id_token`, `name`, `bureau_id`）をJSONボディで追加し、`make gen` |
| `api/externals/repository/` | `user_repository` に `FindByAuthPlatformUserID`・`LinkAuthPlatformUserID`・`RegisterFirebaseUser`（トランザクション）、`mail_auth_repository` に `FindMailAuthByUserID` を追加 |
| `api/internals/usecase/` | `firebase_auth_usecase.go` と `authplatform` クライアントを追加し、wireのプロバイダに登録 |
| `api/externals/handler/` | `PostMailAuthFirebaseSignin` と `PostMailAuthFirebaseSignup` を追加 |
| 環境変数 | `AUTH_PLATFORM_URL` |
| フロント（`view/next-project`） | 下記 |

フロントの「Googleでログイン」ボタンは、Firebase SDKでID Tokenを取得して `/mail_auth/firebase_signin` に送り、次のように分岐します。

- 200：返ってきた `accessToken` を既存ログインと同じ場所に保存する
- 404（`registrationRequired`）：`SignUpView` からパスワード欄を除いた、メール固定の新規登録画面を出し、`/mail_auth/firebase_signup` に送る

移植するコードは、このモックと同じくプレースホルダ（`?`）でSQLを組み立ててください。本物の
`session_repository.go` と `mail_auth_repository.go` は、メールアドレスやアクセストークンを文字列連結で
SQLに埋め込んでいるため、そこには乗らないようにします。
