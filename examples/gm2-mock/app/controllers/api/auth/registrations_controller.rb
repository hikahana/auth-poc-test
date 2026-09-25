# frozen_string_literal: true

# Trimmed from group-manager-2 api/app/controllers/api/auth/registrations_controller.rb
# (user_details handling removed). New sign-ups always get the plain user role.
module Api
  module Auth
    class RegistrationsController < DeviseTokenAuth::RegistrationsController
      private

      def sign_up_params
        allowed_attrs = %i[name email password password_confirmation confirm_success_url]
        permitted = if params[:registration]
                      params.require(:registration).permit(allowed_attrs)
                    else
                      params.permit(allowed_attrs)
                    end

        permitted.merge(role_id: Role::USER_ID)
      end
    end
  end
end
