require 'test_helper'

class FirebaseSignInTest < ActionDispatch::IntegrationTest
  def verified(status: 'approved', sub: 'firebase-uid-1', email: 'member@example.com', email_verified: true)
    AuthPlatformClient::Result.new(status: status, sub: sub, email: email, email_verified: email_verified)
  end

  def firebase_sign_in(result)
    AuthPlatformClient.stub(:verify, result) do
      post '/api/auth/firebase_sign_in', params: { id_token: 'token' }, as: :json
    end
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

  test 'rejects a user the whitelist has not approved' do
    create_user(email: 'member@example.com')

    firebase_sign_in(verified(status: 'pending'))

    assert_response :forbidden
    assert_empty auth_headers_from(response)
  end

  test 'rejects an approved login that has no GM2 account' do
    firebase_sign_in(verified(email: 'stranger@example.com'))

    assert_response :forbidden
    assert_equal 0, User.where(auth_platform_user_id: 'firebase-uid-1').count
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
