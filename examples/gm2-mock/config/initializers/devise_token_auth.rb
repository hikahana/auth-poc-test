# Copied from group-manager-2 api/config/initializers/devise_token_auth.rb (active lines only).
DeviseTokenAuth.setup do |config|
  config.change_headers_on_each_request = false
  config.token_lifespan = 2.weeks
  config.headers_names = { 'access-token': 'access-token',
                           client: 'client',
                           expiry: 'expiry',
                           uid: 'uid',
                           'token-type': 'token-type' }
end
