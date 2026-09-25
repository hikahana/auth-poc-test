# frozen_string_literal: true

class Api::V1::CurrentUserApiController < AuthenticatedController
  def show
    render json: fmt(ok, current_api_user.as_json(only: %i[id name email role_id auth_platform_user_id]))
  end
end
