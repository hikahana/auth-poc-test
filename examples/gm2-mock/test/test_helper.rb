ENV['RAILS_ENV'] ||= 'test'
require_relative '../config/environment'
require 'rails/test_help'
require 'minitest/mock'

class ActionDispatch::IntegrationTest
  setup do
    [[1, 'manager'], [2, 'staff'], [3, 'user']].each do |id, name|
      Role.find_or_create_by!(id: id) { |role| role.name = name }
    end
  end

  def create_user(email:, role_id: Role::USER_ID, auth_platform_user_id: nil)
    User.create!(email: email, name: email, password: 'password',
                 role_id: role_id, auth_platform_user_id: auth_platform_user_id)
  end

  def auth_headers_from(response)
    response.headers.slice('access-token', 'client', 'uid')
  end
end
