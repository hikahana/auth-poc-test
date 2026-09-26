Rails.application.routes.draw do
  namespace :api do
    mount_devise_token_auth_for 'User', at: 'auth', controllers: {
      registrations: 'api/auth/registrations'
    }
    namespace :auth do
      post 'firebase_sign_in', to: 'firebase_sessions#create'
      post 'firebase_sign_up', to: 'firebase_sessions#sign_up'
    end

    namespace :v1 do
      get 'users/current', to: 'current_user_api#show'
      get 'staff/ping', to: 'staff_api#ping'
    end
  end
end
