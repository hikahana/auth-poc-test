# frozen_string_literal: true

# Receives "drop this user's sessions" notifications from the auth platform,
# sent when an email is removed from its whitelist (or on a force logout).
#
# The request is signed: X-Auth-Platform-Signature: t=<unix>,v1=<hex>, where
# v1 = HMAC-SHA256(key: SHA256_hex(AUTH_PLATFORM_CLIENT_SECRET), "<t>.<raw body>").
# Lives under api/auth/, which GM2's ApiAccessControlRegistry treats as an
# excluded (unauthenticated) prefix — the signature is the authentication.
module Api
  module Auth
    class PlatformRevocationsController < ApplicationController
      TOLERANCE = 5.minutes

      # POST /api/auth/platform_revocations
      def create
        return head :unauthorized unless valid_signature?

        payload = JSON.parse(request.raw_post)
        return head :bad_request unless payload['event'] == 'user.revoked' && payload['sub'].present?

        user = User.find_by(auth_platform_user_id: payload['sub'])
        # Every devise_token_auth token, including ones from a password login:
        # the person has been removed from NUTMEG, not just from Google login.
        user&.update!(tokens: {})

        # 204 even for an unknown sub, so the platform can safely retry.
        head :no_content
      rescue JSON::ParserError
        head :bad_request
      end

      private

      def valid_signature?
        secret = ENV['AUTH_PLATFORM_CLIENT_SECRET'].to_s
        return false if secret.empty?

        parts = request.headers['X-Auth-Platform-Signature'].to_s.split(',').each_with_object({}) do |kv, h|
          key, value = kv.strip.split('=', 2)
          h[key] = value
        end
        timestamp = Integer(parts['t'], exception: false)
        return false if timestamp.nil? || parts['v1'].blank?
        return false if (Time.now.to_i - timestamp).abs > TOLERANCE

        key = Digest::SHA256.hexdigest(secret)
        expected = OpenSSL::HMAC.hexdigest('SHA256', key, "#{timestamp}.#{request.raw_post}")
        ActiveSupport::SecurityUtils.secure_compare(expected, parts['v1'])
      end
    end
  end
end
