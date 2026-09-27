require 'test_helper'

class PlatformRevocationsTest < ActionDispatch::IntegrationTest
  SECRET = 'cs_test_secret'

  setup do
    @previous_secret = ENV['AUTH_PLATFORM_CLIENT_SECRET']
    ENV['AUTH_PLATFORM_CLIENT_SECRET'] = SECRET
  end

  teardown do
    ENV['AUTH_PLATFORM_CLIENT_SECRET'] = @previous_secret
  end

  def signature(body, timestamp: Time.now.to_i, secret: SECRET)
    key = Digest::SHA256.hexdigest(secret)
    "t=#{timestamp},v1=#{OpenSSL::HMAC.hexdigest('SHA256', key, "#{timestamp}.#{body}")}"
  end

  def notify(body, header: signature(body))
    post '/api/auth/platform_revocations', params: body,
                                           headers: { 'Content-Type' => 'application/json',
                                                      'X-Auth-Platform-Signature' => header }
  end

  def signed_in_headers(user)
    post '/api/auth/sign_in', params: { email: user.email, password: 'password' }, as: :json
    assert_response :ok
    auth_headers_from(response)
  end

  def revoke_body(sub)
    { event: 'user.revoked', sub: sub, email: 'member@example.com' }.to_json
  end

  test 'a signed notification drops every session of the linked user' do
    user = create_user(email: 'member@example.com', auth_platform_user_id: 'uid-1')
    headers = signed_in_headers(user)
    other = create_user(email: 'other@example.com', auth_platform_user_id: 'uid-2')
    other_headers = signed_in_headers(other)

    notify(revoke_body('uid-1'))
    assert_response :no_content

    get '/api/v1/users/current', headers: headers
    assert_response :unauthorized

    get '/api/v1/users/current', headers: other_headers
    assert_response :ok
  end

  test 'an unknown sub is acknowledged so the platform can retry safely' do
    notify(revoke_body('uid-unknown'))
    assert_response :no_content
  end

  test 'forged, stale or unsigned notifications are rejected and change nothing' do
    user = create_user(email: 'member@example.com', auth_platform_user_id: 'uid-1')
    headers = signed_in_headers(user)
    body = revoke_body('uid-1')

    [
      signature(body, secret: 'cs_wrong'),
      signature(body, timestamp: 10.minutes.ago.to_i),
      signature(revoke_body('uid-2')),
      '',
      'garbage'
    ].each do |header|
      notify(body, header: header)
      assert_response :unauthorized
    end

    get '/api/v1/users/current', headers: headers
    assert_response :ok
  end
end
