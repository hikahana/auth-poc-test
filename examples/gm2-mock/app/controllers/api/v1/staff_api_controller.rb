# frozen_string_literal: true

# Stand-in for GM2's staff-only endpoints: authorization stays in GM2, so a
# user who signed in through Firebase is still bound by their GM2 role.
class Api::V1::StaffApiController < AuthenticatedController
  before_action :require_staff_or_above!

  def ping
    render json: fmt(ok, { role_id: current_api_user.role_id })
  end
end
