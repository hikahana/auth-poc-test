# frozen_string_literal: true

# Auth-relevant part of group-manager-2 api/app/controllers/application_controller.rb.
# The real app routes every action through ApiAccessControlRegistry; here the
# user/staff split is expressed with plain before_actions instead.
class ApplicationController < ActionController::API
  include DeviseTokenAuth::Concerns::SetUserByToken

  def ok
    { code: 200, message: 'Success' }
  end

  def fmt(status, data = [], option = '')
    status.store('option', option) if option != ''
    { status: status, data: data }
  end

  private

  def require_staff_or_above!
    return if current_api_user&.role_id.in?(Role::STAFF_OR_ABOVE_IDS)

    render json: fmt({ code: 403, message: 'Forbidden' }),
           status: :forbidden
  end
end
