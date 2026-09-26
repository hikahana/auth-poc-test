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
                                  └ 名簿（ホワイトリスト）に載っているか
         GM2: users.auth_platform_user_id で既存ユーザーを特定
              (初回は検証済みメールで既存ユーザーに紐付け)
              ├ 見つかった → user.create_new_auth_token で従来と同じ access-token / client / uid を返す
              └ 見つからない → 404 { registration_required: true, email }
                                ↓ フロントはメール固定の新規登録フォームを出す
   └─ POST /api/auth/firebase_sign_up {id_token, name}
         GM2: 同じく認証基盤で確認 → メールはID Tokenから取り出して users を作成（role: user）
              → そのままログイン（同じヘッダを返す）
```

GM2が返すトークンはパスワードログイン（`POST /api/auth/sign_in`）と同じものです。そのため既存のAPI、
`authenticate_api_user!`、ロール判定（`require_staff_or_above!`など）はまったく変更せずに動きます。
**認可は引き続きGM2のロール**で行われ、認証基盤は「誰か」だけを答えます。

新規登録について:

- メールアドレスはフォームから受け取らず、サーバー側でID Tokenから取り出す（フォームを細工して他人のメールで登録できないように）
- ロールは一番低い `user`（`Role::USER_ID`）固定。staff / manager への昇格はGM2の管理画面で行う
- パスワード欄はない。Googleでしか入らないため、devise用には推測できないランダムなパスワードを入れておく

| 状況 | GM2の応答 |
|---|---|
| ID Tokenが不正 | 401 |
| 名簿に載っていない / メール未確認（`not_whitelisted` / `email_unverified`） | 403 |
| 名簿に載っているがGM2にアカウントがない（ログイン時） | 404 `registration_required: true` と `email` |
| 新規登録時、既にアカウントがある | 409 |
| そのGM2ユーザーが既に別のFirebaseアカウントと紐付いている | 409 |
| 新規登録で名前が空 | 422 |
| 認証基盤に接続できない | 502 |

## 起動

認証基盤（リポジトリ直下）を先に起動しておきます（`:8080`）。

```bash
docker compose up -d --build
```

モックは **http://localhost:3100** で起動します（3000番はローカルで動かす本物のGM2用に空けています）。
seedで `manager@example.com` / `staff@example.com` / `user@example.com`（パスワードはすべて `password`）が作られます。

動作確認は http://localhost:8080/ から行います。

1. 「1.」で自分のGoogleアカウントのメールアドレスを名簿に登録する
2. 「2.」でGoogleログインする
3. 「3. GM2」の「GoogleでGM2にログイン」を押す。GM2にアカウントがなければ、メール固定の新規登録フォームが出るので、名前を入れて登録する
4. 「現在のユーザー」で `auth_platform_user_id` が入り、`role_id` が 3（user）になっていることを確認する
5. 「staff専用API」はuserロールなので403になる。ロールを上げると200になる

既にGM2アカウントを持っている人が初めてGoogleで入る場合（メールで自動紐付け）は、「3.」の
「（テスト用）既存GM2ユーザーを作る」で先にパスワード登録しておくと試せます。

```bash
docker compose exec api bin/rails runner 'User.find_by(email: "you@example.com").update!(role_id: Role::STAFF_ID)'
```

テストは次のコマンドで実行できます。

```bash
docker compose run --rm api bin/rails test
```

## 本物のGM2へ移植するときの差分

GM2に持っていくのは以下だけです。既存ファイルの変更は`routes.rb`の2行だけです。

| ファイル | 内容 |
|---|---|
| `db/migrate/*_add_auth_platform_user_id_to_users.rb` | `users.auth_platform_user_id`（nullable, unique）を追加 |
| `app/services/auth_platform_client.rb` | 認証基盤の`/v1/auth/verify`を呼ぶクライアント |
| `app/controllers/api/auth/firebase_sessions_controller.rb` | Googleログインと新規登録のエンドポイント |
| `config/routes.rb` | `namespace :api { namespace :auth { post 'firebase_sign_in'; post 'firebase_sign_up' } }` を追加 |
| 環境変数 | `AUTH_PLATFORM_URL` |
| `test/integration/firebase_sign_in_test.rb` | そのまま移植可能 |

`api/auth/`配下はGM2の`ApiAccessControlRegistry`で未認証の対象外（excluded）になっているので、
`config/api_access_control.yml`への追記は不要です。

本物のGM2の新規登録は `user_details`（学籍番号・学科・学年・電話番号）も受け取ります。移植時は
`firebase_sign_up` でも同じ項目を受け取り、既存の `RegistrationsController` と同じ必須チェックをかけてください。

Googleログインの対象はNUTMEGメンバー（実行委員）だけなので、フロントの「Googleでログイン」ボタンは
実行委員向けの `admin_view/` に置きます。参加団体向けの `user/` は従来のパスワードログインのままです。
ボタンは Firebase SDKでID Tokenを取り、`/api/auth/firebase_sign_in` に送り、次のように分岐します。

- 200：返ってきたヘッダを既存ログインと同じ場所に保存する
- 404（`registration_required`）：メール固定の新規登録画面を出し、`/api/auth/firebase_sign_up` に送る
