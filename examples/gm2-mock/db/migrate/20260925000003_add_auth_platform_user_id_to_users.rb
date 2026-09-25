# The only schema change GM2 itself needs: the auth platform's stable user id
# (the Firebase UID / `sub` claim). Nullable so existing users keep working
# until their first Firebase login links them.
class AddAuthPlatformUserIdToUsers < ActiveRecord::Migration[6.1]
  def change
    add_column :users, :auth_platform_user_id, :string
    add_index :users, :auth_platform_user_id, unique: true
  end
end
