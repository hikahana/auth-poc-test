# frozen_string_literal: true

require 'net/http'

# Server-to-server client for the auth platform's POST /v1/auth/verify.
# Firebase Admin SDK has no Ruby version, so GM2 delegates ID token
# verification (and the email whitelist check) to the platform.
module AuthPlatformClient
  Result = Struct.new(:status, :sub, :email, :email_verified, keyword_init: true) do
    def allowed?
      status == 'allowed'
    end

    def invalid?
      status == 'invalid'
    end

    def error?
      status == 'error'
    end
  end

  module_function

  def verify(id_token)
    uri = URI.join(base_url, '/v1/auth/verify')
    request = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
    request.basic_auth(ENV.fetch('AUTH_PLATFORM_CLIENT_ID', ''), ENV.fetch('AUTH_PLATFORM_CLIENT_SECRET', ''))
    request.body = { id_token: id_token }.to_json

    response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                                                   open_timeout: 3, read_timeout: 5) do |http|
      http.request(request)
    end

    case response
    when Net::HTTPOK, Net::HTTPForbidden then result_from(JSON.parse(response.body))
    # The platform challenges with WWW-Authenticate only when GM2's own client
    # credentials are wrong — a server misconfiguration, not the user's fault.
    when Net::HTTPUnauthorized
      return Result.new(status: 'invalid') unless response['WWW-Authenticate']

      Rails.logger.error('[AuthPlatformClient] client credentials rejected; check AUTH_PLATFORM_CLIENT_ID/SECRET')
      Result.new(status: 'error')
    else
      Rails.logger.warn("[AuthPlatformClient] unexpected response #{response.code}")
      Result.new(status: 'error')
    end
  rescue StandardError => e
    Rails.logger.warn("[AuthPlatformClient] #{e.class}: #{e.message}")
    Result.new(status: 'error')
  end

  def result_from(body)
    Result.new(status: body['status'].to_s, sub: body['sub'], email: body['email'],
               email_verified: body['email_verified'] == true)
  end

  def base_url
    ENV.fetch('AUTH_PLATFORM_URL', 'http://localhost:8080')
  end
end
