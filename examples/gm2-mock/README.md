# gm2-mock

group-manager-2（GM2）の**認証まわりだけ**を再現したRails APIです。認証基盤（リポジトリ直下のGoサーバー）を
本物のGM2に組み込む前に、ここで組み込み方を検証します。

- Ruby 3.0.7 / Rails 6.1.3.1 / devise 4.7.3 / devise_token_auth 1.1.5 は、GM2の`Gemfile.lock`から作ったので本物と同じバージョン
- `User`/`Role`モデル、devise・devise_token_auth・CORSの設定、新規登録コントローラは本物から写して最小化したもの
- DBだけはMySQLではなくSQLite（認証の流れはDBに依存しないため）

## 仕組み

```
ブラウザ ──(Firebase SDK)──> Firebase Auth ──> ID Token
   │
   └─ POST /api/auth/firebase_sign_in {id_token}
         GM2 ──(サーバー間)──> 認証基盤 POST /v1/auth/verify
                                  ├ ID Tokenを検証
                                  └ whitelist が approved か
         GM2: users.auth_platform_user_id で既存ユーザーを特定
              (初回は検証済みメールで既存ユーザーに紐付け)
         GM2: user.create_new_auth_token で従来と同じ access-token / client / uid を返す
```

GM2が返すトークンはパスワードログイン（`POST /api/auth/sign_in`）と同じものです。そのため既存のAPI、
`authenticate_api_user!`、ロール判定（`require_staff_or_above!`など）はまったく変更せずに動きます。
**認可は引き続きGM2のロール**で行われ、認証基盤は「誰か」だけを答えます。

| 状況 | GM2の応答 |
|---|---|
| ID Tokenが不正 | 401 |
| whitelistで未承認（pending / rejected / email_unverified） | 403 |
| 承認済みだがGM2にそのメールのユーザーがいない | 403（GM2側で勝手にユーザーを作らない） |
| そのGM2ユーザーが既に別のFirebaseアカウントと紐付いている | 409 |
| 認証基盤に接続できない | 502 |

## 起動

認証基盤（リポジトリ直下）を先に起動しておきます（`:8080`）。

```bash
docker compose up -d --build
```

モックは **http://localhost:3100** で起動します（3000番はローカルで動かす本物のGM2用に空けています）。
seedで `manager@example.com` / `staff@example.com` / `user@example.com`（パスワードはすべて `password`）が作られます。

動作確認は http://localhost:8080/ の「4. GM2モック連携」から行います。

1. 「1.」でGoogleログインする
2. 「4.」の①で、同じメールアドレスのGM2ユーザーをパスワード登録する（＝「既存GM2ユーザー」の状態を作る）
3. 「3.」でそのメールアドレスをwhitelistで承認する
4. 「4.」の②「FirebaseでGM2にログイン」→ ③「現在のユーザー」で`auth_platform_user_id`が入っていることを確認する
5. 「staff専用API」はuserロールなので403になる。ロールを上げると200になる

```bash
docker compose exec api bin/rails runner 'User.find_by(email: "you@example.com").update!(role_id: Role::STAFF_ID)'
```

テストは次のコマンドで実行できます。

```bash
docker compose run --rm api bin/rails test
```

## 本物のGM2へ移植するときの差分

GM2に持っていくのは以下だけです。既存ファイルの変更は`routes.rb`の1行だけです。

| ファイル | 内容 |
|---|---|
| `db/migrate/*_add_auth_platform_user_id_to_users.rb` | `users.auth_platform_user_id`（nullable, unique）を追加 |
| `app/services/auth_platform_client.rb` | 認証基盤の`/v1/auth/verify`を呼ぶクライアント |
| `app/controllers/api/auth/firebase_sessions_controller.rb` | Firebaseログインのエンドポイント |
| `config/routes.rb` | `namespace :api { namespace :auth { post 'firebase_sign_in' } }` を追加 |
| 環境変数 | `AUTH_PLATFORM_URL` |
| `test/integration/firebase_sign_in_test.rb` | そのまま移植可能 |

`api/auth/`配下はGM2の`ApiAccessControlRegistry`で未認証の対象外（excluded）になっているので、
`config/api_access_control.yml`への追記は不要です。フロント（Next.js の `user/` と Nuxt の `admin_view/`）には、
Firebase SDKでID Tokenを取り、`/api/auth/firebase_sign_in`に送って、返ってきたヘッダを既存ログインと同じ場所に
保存する処理を足します。
