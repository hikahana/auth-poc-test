# frozen_string_literal: true

# Sign-in / sign-up via the shared auth platform (Firebase), alongside the
# existing devise_token_auth password login. Both issue the same
# access-token/client/uid headers as POST /api/auth/sign_in, so every existing
# endpoint and role check keeps working unchanged — the auth platform only
# says who the user is.
#
# Lives under api/auth/, which GM2's ApiAccessControlRegistry already treats as
# an excluded (unauthenticated) prefix.
module Api
  module Auth
    class FirebaseSessionsController < ApplicationController
      # POST /api/auth/firebase_sign_in
      # A whitelisted member without a GM2 account gets 404 with
      # registration_required, so the frontend can open the sign-up form with
      # the email fixed.
      def create
        result = verify_allowed_login
        return if performed?

        user = find_or_link_user(result)
        return if performed?

        sign_in_as(user)
      end

      # POST /api/auth/firebase_sign_up { id_token, name }
      # The email is taken from the verified ID token, never from the form, so
      # the fixed email field on the sign-up screen cannot be tampered with.
      def sign_up
        result = verify_allowed_login
        return if performed?
        return render_error(:unprocessable_entity, 'name is required') if params[:name].blank?

        if User.exists?(auth_platform_user_id: result.sub) || User.exists?(email: result.email.to_s.downcase)
          return render_error(:conflict, 'a GM2 account already exists for this login; sign in instead')
        end

        user = User.new(
          email: result.email,
          name: params[:name],
          role_id: Role::USER_ID,
          auth_platform_user_id: result.sub,
          # Google-only accounts never use a password; a random one keeps
          # devise's validations satisfied without being guessable.
          password: SecureRandom.base64(32)
        )
        return render_error(:unprocessable_entity, user.errors.full_messages.join(', ')) unless user.save

        sign_in_as(user, status: :created)
      end

      private

      def verify_allowed_login
        id_token = params[:id_token].to_s
        return render_error(:bad_request, 'id_token is required') if id_token.blank?

        result = AuthPlatformClient.verify(id_token)
        return render_error(:unauthorized, 'invalid id token') if result.invalid?
        return render_error(:bad_gateway, 'auth platform unavailable') if result.error?
        return render_error(:forbidden, "login not allowed (#{result.status})") unless result.allowed?

        result
      end

      def find_or_link_user(result)
        user = User.find_by(auth_platform_user_id: result.sub)
        return user if user

        # First login through the platform: link to the existing GM2 account
        # with the same email. Linking by email is only safe for addresses the
        # identity provider has verified; otherwise anyone could claim an
        # account by registering its email in Firebase.
        return render_error(:forbidden, 'email is not verified') unless result.email_verified

        user = User.find_by(email: result.email.to_s.downcase)
        unless user
          render json: { success: false, registration_required: true, email: result.email,
                         errors: ['no GM2 account for this email'] }, status: :not_found
          return
        end

        if user.auth_platform_user_id.present?
          render_error(:conflict, 'this GM2 account is already linked to another login')
          return
        end

        user.update!(auth_platform_user_id: result.sub)
        user
      end

      def sign_in_as(user, status: :ok)
        response.headers.merge!(user.create_new_auth_token)
        render json: { data: user.token_validation_response }, status: status
      end

      def render_error(status, message)
        render json: { success: false, errors: [message] }, status: status
      end
    end
  end
end
