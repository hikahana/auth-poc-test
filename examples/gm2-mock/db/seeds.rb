# Role ids match group-manager-2 db/fixtures/develop/01_role.rb.
[[1, 'manager'], [2, 'staff'], [3, 'user']].each do |id, name|
  Role.find_or_create_by!(id: id) { |role| role.name = name }
end

{
  'manager@example.com' => Role::MANAGER_ID,
  'staff@example.com' => Role::STAFF_ID,
  'user@example.com' => Role::USER_ID
}.each do |email, role_id|
  User.find_or_create_by!(email: email) do |user|
    user.name = email.split('@').first
    user.password = 'password'
    user.role_id = role_id
  end
end
