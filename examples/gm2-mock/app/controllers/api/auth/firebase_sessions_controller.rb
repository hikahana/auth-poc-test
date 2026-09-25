# frozen_string_literal: true

# Sign-in via the shared auth platform (Firebase), alongside the existing
# devise_token_auth password login. It issues the same access-token/client/uid
# headers as POST /api/auth/sign_in, so every existing endpoint and role check
# keeps working unchanged — the auth platform only says who the user is.
#
# Lives under api/auth/, which GM2's ApiAccessControlRegistry already treats as
# an excluded (unauthenticated) prefix.
module Api
  module Auth
    class FirebaseSessionsController < ApplicationController
      def create
        id_token = params[:id_token].to_s
        return render_error(:bad_request, 'id_token is required') if id_token.blank?

        result = AuthPlatformClient.verify(id_token)
        return render_error(:unauthorized, 'invalid id token') if result.invalid?
        return render_error(:bad_gateway, 'auth platform unavailable') if result.error?
        return render_error(:forbidden, "login not approved (#{result.status})") unless result.approved?

        user = find_or_link_user(result)
        return if performed?

        response.headers.merge!(user.create_new_auth_token)
        render json: { data: user.token_validation_response }
      end

      private

      def find_or_link_user(result)
        user = User.find_by(auth_platform_user_id: result.sub)
        return user if user

        # First login through the platform: link to the existing GM2 account
        # with the same email. Linking by email is only safe for addresses the
        # identity provider has verified; otherwise anyone could claim an
        # account by registering its email in Firebase.
        unless result.email_verified
          render_error(:forbidden, 'email is not verified')
          return
        end

        user = User.find_by(email: result.email.to_s.downcase)
        unless user
          render_error(:forbidden, 'no GM2 account for this email')
          return
        end

        if user.auth_platform_user_id.present?
          render_error(:conflict, 'this GM2 account is already linked to another login')
          return
        end

        user.update!(auth_platform_user_id: result.sub)
        user
      end

      def render_error(status, message)
        render json: { success: false, errors: [message] }, status: status
      end
    end
  end
end
