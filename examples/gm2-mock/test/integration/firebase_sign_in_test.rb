require 'test_helper'

class FirebaseSignInTest < ActionDispatch::IntegrationTest
  def verified(status: 'allowed', sub: 'firebase-uid-1', email: 'member@example.com', email_verified: true)
    AuthPlatformClient::Result.new(status: status, sub: sub, email: email, email_verified: email_verified)
  end

  def firebase_post(path, result, params = {})
    AuthPlatformClient.stub(:verify, result) do
      post path, params: { id_token: 'token' }.merge(params), as: :json
    end
  end

  def firebase_sign_in(result)
    firebase_post('/api/auth/firebase_sign_in', result)
  end

  def firebase_sign_up(result, name: 'Member')
    firebase_post('/api/auth/firebase_sign_up', result, name: name)
  end

  test 'links an existing account by verified email and issues devise_token_auth headers' do
    user = create_user(email: 'member@example.com')

    firebase_sign_in(verified)

    assert_response :ok
    assert_equal 'firebase-uid-1', user.reload.auth_platform_user_id

    get '/api/v1/users/current', headers: auth_headers_from(response)
    assert_response :ok
    assert_equal user.id, response.parsed_body.dig('data', 'id')
  end

  test 'finds a linked user by sub even after their email changed' do
    user = create_user(email: 'old@example.com', auth_platform_user_id: 'firebase-uid-1')

    firebase_sign_in(verified(email: 'new@example.com'))

    assert_response :ok
    assert_equal user.id, response.parsed_body.dig('data', 'id')
  end

  test 'asks a whitelisted member without a GM2 account to register, with the email to fix' do
    firebase_sign_in(verified(email: 'newcomer@example.com'))

    assert_response :not_found
    assert_equal true, response.parsed_body['registration_required']
    assert_equal 'newcomer@example.com', response.parsed_body['email']
    assert_empty auth_headers_from(response)
  end

  test 'sign-up creates a lowest-role account from the token email and signs in' do
    firebase_sign_up(verified(email: 'newcomer@example.com'), name: 'Newcomer')

    assert_response :created
    user = User.find_by!(email: 'newcomer@example.com')
    assert_equal 'Newcomer', user.name
    assert_equal Role::USER_ID, user.role_id
    assert_equal 'firebase-uid-1', user.auth_platform_user_id

    get '/api/v1/users/current', headers: auth_headers_from(response)
    assert_response :ok
  end

  test 'sign-up ignores any email sent in the form' do
    AuthPlatformClient.stub(:verify, verified(email: 'newcomer@example.com')) do
      post '/api/auth/firebase_sign_up', params: { id_token: 'token', name: 'X', email: 'victim@example.com' }, as: :json
    end

    assert_response :created
    assert User.exists?(email: 'newcomer@example.com')
    assert_not User.exists?(email: 'victim@example.com')
  end

  test 'sign-up refuses when the account already exists or the login is not whitelisted' do
    create_user(email: 'member@example.com')
    firebase_sign_up(verified)
    assert_response :conflict

    firebase_sign_up(verified(status: 'not_whitelisted', sub: 'uid-2', email: 'someone@example.com'))
    assert_response :forbidden
    assert_not User.exists?(email: 'someone@example.com')

    firebase_sign_up(verified(sub: 'uid-3', email: 'noname@example.com'), name: '')
    assert_response :unprocessable_entity
  end

  test 'rejects a login that is not on the whitelist' do
    create_user(email: 'member@example.com')

    firebase_sign_in(verified(status: 'not_whitelisted'))

    assert_response :forbidden
    assert_empty auth_headers_from(response)
  end

  test 'does not link by an unverified email' do
    user = create_user(email: 'member@example.com')

    firebase_sign_in(verified(email_verified: false))

    assert_response :forbidden
    assert_nil user.reload.auth_platform_user_id
  end

  test 'refuses to relink an account already linked to a different login' do
    user = create_user(email: 'member@example.com', auth_platform_user_id: 'someone-else')

    firebase_sign_in(verified)

    assert_response :conflict
    assert_equal 'someone-else', user.reload.auth_platform_user_id
  end

  test 'maps an invalid id token to 401 and an unreachable platform to 502' do
    firebase_sign_in(AuthPlatformClient::Result.new(status: 'invalid'))
    assert_response :unauthorized

    firebase_sign_in(AuthPlatformClient::Result.new(status: 'error'))
    assert_response :bad_gateway
  end

  test 'GM2 roles still govern authorization after a Firebase login' do
    create_user(email: 'member@example.com', role_id: Role::USER_ID)
    firebase_sign_in(verified)
    user_headers = auth_headers_from(response)

    get '/api/v1/staff/ping', headers: user_headers
    assert_response :forbidden

    create_user(email: 'staff@example.com', role_id: Role::STAFF_ID)
    firebase_sign_in(verified(sub: 'firebase-uid-2', email: 'staff@example.com'))

    get '/api/v1/staff/ping', headers: auth_headers_from(response)
    assert_response :ok
  end

  test 'existing password login keeps working' do
    create_user(email: 'member@example.com')

    post '/api/auth/sign_in', params: { email: 'member@example.com', password: 'password' }, as: :json
    assert_response :ok

    get '/api/v1/users/current', headers: auth_headers_from(response)
    assert_response :ok
  end
end
