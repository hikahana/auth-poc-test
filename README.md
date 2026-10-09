# auth-poc-test

NUTMEG関連プロダクトの共通認証基盤の個人PoC。設計の背景と決定事項は
[docs/auth-poc-test-handoff.md](docs/auth-poc-test-handoff.md) を参照。

- 対象: NUTMEGメンバー（実行委員）のみ。GM2の参加団体は従来のパスワードログインのまま
- 認証: Firebase Authentication（無印。Identity Platformへは絶対にアップグレードしない）。
  ただしGoogleログインはFirebaseを通さずに行い、名簿で通した人だけをFirebaseに入れる（弾いた人はFirebaseに残らない）
- 認可: 各プロダクト側の責務のまま。このAPIは「このユーザーは誰か」だけを答える
- 名簿（ホワイトリスト）: `….nutfes@gmail.com` のアドレスだけを通し、初回ログインで自動登録する。締め出すときは無効化する

## 全体の流れ

```
メンバー: 各プロダクトで「Googleでログイン」（Google Identity Servicesのボタン。Firebaseはまだ使わない）
  ↓ GoogleのID Token
認証基盤 POST /v1/auth/google: GoogleのID Tokenを検証
  ├ .nutfes@gmail.com 以外 → 拒否（名簿にもFirebaseにも残さない）
  ├ 初めてのアドレス → 名簿に「メンバー」として自動登録して通す
  ├ 無効化されている → 拒否（Firebaseには入れない）
  └ 有効 → Firebaseのユーザーを（なければ）作り、カスタムトークンを返す
      ↓ signInWithCustomToken
ブラウザ: Firebaseにログイン → FirebaseのID Tokenを各プロダクトへ
  ↓
認証基盤 POST /v1/auth/verify: 同じ名簿チェックをもう一度行い、通す（どのプロダクトにログインしたかを記録）
  ↓
各プロダクト: そのメールアドレスのアカウントがあるか
  ├ ある → ログイン完了（初回はメールで既存アカウントに自動で紐付け）
  └ ない → 新規登録画面へ。メールはGoogleのもので固定、残りの項目を入力して登録 → ログイン完了
```

## セットアップ

1. Firebaseコンソールで新規プロジェクトを作成し、Sign-in method の **Google・メール/パスワードはどちらも無効のままにする**
   （有効になっていたら無効化する）。FirebaseのAPIキーはブラウザに公開されるので、有効だと誰でも直接Firebaseに
   ユーザーを作れてしまい、名簿で先に弾く意味がなくなる。カスタムトークンでのログインは、この設定に関係なく使える
2. プロジェクト設定 > サービスアカウント からサービスアカウントキー(JSON)を発行し、
   リポジトリ直下に `service-account.json` として配置する（`.gitignore`済み。カスタムトークンの署名にも使う）
3. Google Cloudコンソール（Firebaseと同じプロジェクト）> APIとサービス > 認証情報 で、
   「Web client (auto created by Google Service)」のクライアントIDを控える。
   その「承認済みのJavaScript生成元」に、ログインボタンを置くページのオリジン（`http://localhost:8080` と `http://localhost`。
   localhostはポート付きと無しの両方が要る）を追加する。載っていないオリジンではボタンが動かない
4. `.env.example` を `.env` にコピーし、`GOOGLE_OAUTH_CLIENT_ID` に3.のクライアントIDを入れる（未設定だと起動しない）
5. 最初の管理者を登録する（最初の1回だけ。以降の管理者は管理画面から追加する。`.nutfes@gmail.com` のアドレスに限る）

   ```bash
   go run ./cmd/seed-admin 22.taro.nutfes@gmail.com
   ```

6. 起動する

   ```bash
   go run ./cmd/server
   ```

7. 認証基盤を呼ぶプロダクトを登録し、出力されたIDと秘密鍵を各プロダクトの環境変数に設定する
   （管理画面の「3. プロダクト」からも登録できる。秘密鍵は発行時に一度だけ表示される）

   2つ目の引数は、無効化した人のセッションを消すよう通知する先（プロダクトの受け口）。後から管理画面でも変更できる。

   ```bash
   go run ./cmd/register-client GM2 http://localhost:3100/api/auth/platform_revocations > examples/gm2-mock/.env
   go run ./cmd/register-client FinanSu http://localhost:3200/auth_platform/revocations > examples/finansu-mock/.env
   ```

## 名簿（ホワイトリスト）

- 通すのは `….nutfes@gmail.com`（`@gmail.com` の前が `.nutfes` で終わる）アドレスだけ。大文字・小文字は区別しない。
  それ以外のアドレスは、ログインも管理画面からの登録も拒否する
- `.nutfes` のアドレスで初めてログインした人は、名簿に `member`（メンバー）として自動登録される（`added_by` は `auto`）
- **注意**: `〇〇.nutfes@gmail.com` は誰でもGmailで作れるため、このルールだけではNUTMEGと無関係の人も入れてしまう。
  管理画面で自動登録された人を確認し、心当たりのない人は無効化する運用が前提（各プロダクトは一番低い権限から始まる）
- 締め出すときは削除ではなく**無効化**する。無効化した人は、再ログインしても再登録されず拒否される。「再有効化」で戻せる。
  （削除だと、次のログインでまた自動登録されてしまうため）
- 名簿の各メールアドレスは役割を持つ。`member`（メンバー）か `admin`（管理者）
- 名簿を操作できるのは有効な管理者だけ。管理者は自分のGoogleアカウントでログインして操作する
  （Firebase ID Tokenを `Authorization: Bearer` で送り、検証済みメールが名簿に有効な `admin` で載っているかを見る）。
  パスワードや共有キーはない。登録者（`added_by`）・無効化した人（`disabled_by`）には操作した管理者のメールが自動で入る
- 最後の1人の有効な管理者は、無効化も降格もできない（誰も管理できなくなるのを防ぐ）
- 最初の管理者は `go run ./cmd/seed-admin <email>` で登録する。メールアドレスをリポジトリに残さないよう、シードファイルではなく引数で渡す
- この役割は「認証基盤を誰が操作できるか」だけを決める。GM2やFinanSuの中の権限とは無関係

### 一括無効化

卒業生の整理などのために、条件に合う有効なメンバーをまとめて無効化できる（各プロダクトのセッションも消す）。管理者は対象にならない。

- 入学年度: アドレス先頭の2桁（`22.h.hanada.nutfes@gmail.com` なら22）の範囲。先頭が2桁の数字でないアドレスは、年度の条件では選ばれない
- 名簿への登録日: 日付の範囲（日本時間、両端を含む）。自動登録の人は初めてログインした日
- 両方指定すると両方を満たす人が対象。`dry_run: true` で対象者だけを確認できる（管理画面では「対象を確認」→「実行」の2段階）

## プロダクト（クライアント）とログイン記録

- `/v1/auth/verify` を呼べるのは、登録済みで有効なプロダクトだけ。プロダクトはIDと秘密鍵をHTTP Basic認証で送る
- 秘密鍵は認証基盤にハッシュだけを保存する。忘れたら再発行する（再発行すると古い秘密鍵はすぐ使えなくなる）
- プロダクトを停止すると、そのプロダクトからの `verify` はすべて401になる
- `verify` で `allowed` を返すたびに、「どのログイン（FirebaseのユーザーID）が、どのプロダクトに、最初と最後にいつログインしたか」を記録する。
  記録できなかった場合はログインを通さない（後で無効化できないログインを作らないため）
- 認証基盤はセッションを持たない。この記録は、無効化した人のセッションを各プロダクトに消させるために使う

## 無効化したときの即時ログアウト

名簿で無効化すると（一括も同じ）、認証基盤は次の順に処理し、結果をプロダクトごとに返す（管理画面にも表示される）。

1. 名簿で無効化する（以降の新しいログインはすべて拒否される）
2. ログイン記録から、その人がログインしたことのあるプロダクトを調べる
3. Firebaseでその人のリフレッシュトークンを無効化する（ブラウザが新しいID Tokenを取れなくなる）
4. 各プロダクトの通知先URLへ「この人のセッションを消して」と署名付きで通知する

- 1つのプロダクトへの通知が失敗しても、ほかのプロダクトへの通知と無効化は行われる。失敗は結果に `failed` と出るので、
  「強制ログアウト」（`POST /v1/admin/logins/revoke`）で再送する。自動の再送はない
- 通知先URLが未設定のプロダクトは `skipped` になる（そのプロダクトのセッションは有効期限まで残る）
- 「強制ログアウト」は、名簿では有効のままセッションだけを消すのにも使える
- 注意: 各プロダクトが通知で消すのはセッションだけ。無効化した人がそのプロダクトのパスワードも持っている場合は、パスワードで
  再びログインできてしまう。完全に締め出すには、プロダクト側でアカウントを停止する

### 通知の仕様（各プロダクトが実装する受け口）

```
POST <通知先URL>
Content-Type: application/json
X-Auth-Platform-Signature: t=<UNIX秒>,v1=<HMAC-SHA256の16進>

{"event":"user.revoked","sub":"<FirebaseのユーザーID>","email":"<メールアドレス>"}
```

- 署名の鍵は `SHA-256(AUTH_PLATFORM_CLIENT_SECRET)` の16進文字列（小文字）。署名する文字列は `"<t>.<生のリクエストボディ>"`。
  プロダクトは自分の秘密鍵から同じ鍵を作れるので、追加の設定は要らない（認証基盤は秘密鍵そのものを保存していない）
- `t` が自分の時計から5分以上ずれている通知は拒否する（盗聴した通知の再送を防ぐため）
- 署名が正しければ、`users.auth_platform_user_id = sub` のユーザーのセッションをすべて消し、2xxを返す。
  該当ユーザーがいなくても2xxを返す（再送しても安全なように）
- 実装例: [GM2モック](examples/gm2-mock/app/controllers/api/auth/platform_revocations_controller.rb)、
  [FinanSuモック](examples/finansu-mock/authplatform/revocation.go)、署名の参照実装は [internal/revocation](internal/revocation/revocation.go)

## エンドポイント

| メソッド | パス | 用途 |
|---|---|---|
| POST | `/v1/auth/google` | ブラウザが呼ぶ（認証不要）。GoogleのID Token（`{"credential"}`）を検証し、名簿で通した人にだけFirebaseのカスタムトークン（`custom_token`）を返す。初めての `.nutfes` アドレスは自動登録する。`status` は `verify` と同じ |
| POST | `/v1/auth/verify` | 各プロダクトのサーバーが呼ぶ（要Basic認証）。Firebase ID Tokenを検証し、通してよいかを返す。初めての `.nutfes` アドレスは自動登録する |
| GET | `/v1/admin/whitelist` | 名簿の一覧（無効化された人を含む）。管理者のみ |
| POST | `/v1/admin/whitelist` | 名簿に先に登録しておく（`{"email", "role"}`。`role` 省略時は `member`）。主に管理者の追加用。管理者のみ |
| PATCH | `/v1/admin/whitelist/{email}` | 役割の変更（`{"role"}`）。管理者のみ |
| POST | `/v1/admin/whitelist/{email}/disable` | 無効化し、各プロダクトのセッションを無効化する。結果（`revocations`）を返す。管理者のみ |
| POST | `/v1/admin/whitelist/{email}/enable` | 再有効化。管理者のみ |
| POST | `/v1/admin/whitelist/bulk-disable` | 一括無効化（`{"entry_year_from", "entry_year_to", "registered_from", "registered_to", "dry_run"}`）。管理者のみ |
| GET | `/v1/admin/clients` | プロダクトの一覧（秘密鍵は含まない）。管理者のみ |
| POST | `/v1/admin/clients` | プロダクトの登録（`{"name", "revoke_url"}`）。応答にだけ `client_secret` が入る。管理者のみ |
| PATCH | `/v1/admin/clients/{id}` | 停止・再開、通知先URLの変更（`{"is_active"}` / `{"revoke_url"}`）。管理者のみ |
| POST | `/v1/admin/clients/{id}/secret` | 秘密鍵の再発行。管理者のみ |
| GET | `/v1/admin/logins` | ログイン記録（`?email=` で絞り込み可）。管理者のみ |
| POST | `/v1/admin/logins/revoke` | 強制ログアウト（`{"email"}`）。名簿は変えずにセッションだけ無効化し、結果を返す。管理者のみ |

管理者のみのAPIは、ログインしていなければ401、有効な管理者でなければ403を返す。最後の有効な管理者を無効化・降格しようとすると409。
`.nutfes@gmail.com` 以外のアドレスを登録しようとすると400。
`verify` はプロダクトの認証情報が無い・間違っている・停止中のとき、`WWW-Authenticate` ヘッダ付きの401を返す
（ID Tokenが不正な401と区別できるように）。

`POST /v1/auth/verify` の応答の `status`:

| status | HTTP | 意味 |
|---|---|---|
| `allowed` | 200 | ログインしてよい（初めての `.nutfes` アドレスはこの時点で自動登録済み） |
| `not_nutfes_email` | 403 | `.nutfes@gmail.com` 以外のアドレス |
| `disabled` | 403 | 管理者によって無効化されている |
| `email_unverified` | 403 | メールアドレスの所有確認が済んでいない |
| （`error`のみ） | 401 | ID Tokenが不正 |

`email_unverified` を拒否するのは、名簿をメールアドレスで照合しているためです。この確認がないと、他人の `.nutfes` アドレスで
アカウントを作るだけで、その人になりすませてしまいます。

`verify` でも名簿チェックをもう一度行うのは、`/v1/auth/google` を通らずに作られたFirebaseのログイン
（Sign-in methodの設定を戻してしまった場合など）を通さないためです。
`/v1/auth/google` は、Firebaseに同じメールの未確認ユーザー（以前のメール/パスワード登録など）がいたら、
それを削除して作り直します。所有確認をしていない誰かが設定したパスワードを、Googleで確認済みとして扱わないためです。

## 動作確認

`go run ./cmd/server` で起動したあと http://localhost:8080/ を開く（`web/`をこのサーバーが配信する）。
`web/firebase-config.js` は `web/firebase-config.example.js` をコピーしてFirebaseのWeb SDK設定と
`googleClientId`（`.env` の `GOOGLE_OAUTH_CLIENT_ID` と同じ値）を入れる。

1. 「1.」で、`seed-admin` で登録したアカウントでGoogleログインする（「2.」に名簿、「3.」にプロダクトが表示される）
2. 「4. GM2」「5. FinanSu」で「Googleで〜にログイン」を押す。アカウントがなければ新規登録フォームが出る
3. 別の `.nutfes` アカウントでログインすると、「2.」の名簿に「自動登録」として追加される。`.nutfes` 以外は拒否され、
   Firebaseコンソールの Authentication > ユーザー にも追加されない
4. 「2.」の「ログインしたプロダクト」に、ログインしたプロダクトが記録されていることを確認する
5. 「2.」でその人を無効化（または強制ログアウト）すると、結果欄にプロダクトごとの結果が出て、
   「4.」「5.」の「現在のユーザー」「current_user」が401になる。無効化した人は再ログインしても拒否される
6. 「2.」の「一括無効化」で入学年度や登録日を指定し、「対象を確認」→「実行」

## プロダクトへの組み込み例

- [examples/gm2-mock](examples/gm2-mock) — group-manager-2（Rails + devise_token_auth）の認証部分を再現したモックへの組み込み（:3100）
- [examples/finansu-mock](examples/finansu-mock) — FinanSu（Go + Echo、独自の `mail_auth` / `session`）の認証部分を再現したモックへの組み込み（:3200）

どちらも、認証基盤でID Tokenと名簿を確認したあと、各プロダクトのアカウントに紐付けて（なければ新規登録して）、
**そのプロダクトの既存のログイントークンを発行する**形にしている。既存のAPIと権限判定には手を入れない。
Googleから新規登録したアカウントは、各プロダクトで一番低いロールになる。権限は各プロダクトの管理画面で上げる。

## Firebase Authの制限（2026-09時点、[公式](https://firebase.google.com/docs/auth/limits)）

- 登録ユーザー数は無制限。Identity Platformにアップグレードすると、Sparkプランで1日3,000アクティブユーザーまでになるので、アップグレードしない
- 新規アカウント作成は同じIPアドレスから1時間100件まで。Firebaseのユーザーは認証基盤のサーバーがAdmin SDKで作るようになったので、
  この制限がそのまま当てはまるかは未確認（当てはまる場合、全員分がサーバーのIPに集まるので、新入生説明会などの一斉初回ログインで引っかかりやすくなる）
- 確認メールは1日1,000通、管理API（トークン無効化など）は毎秒1,000リクエストまで

## 未実装（PoCのスコープ外）

- SQLite以外のDB（本番想定ならPostgres等への差し替えが必要）
- 通知失敗時の自動再送
