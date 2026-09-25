# frozen_string_literal: true

# Auth-relevant part of group-manager-2 api/app/models/user.rb.
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  include DeviseTokenAuth::Concerns::User

  belongs_to :role
end
