import sys
sys.path.insert(0, '.')
from dashboard.auth import init_auth_db, get_auth_conn, hash_password

init_auth_db()
new_password = "Phoenix$123"
salt, pw_hash = hash_password(new_password)
conn = get_auth_conn()
conn.execute(
    "UPDATE users SET password_hash=?, salt=?, must_change_password=0 WHERE username=?",
    (pw_hash, salt, "admin")
)
conn.commit()
conn.close()
print(f"Password successfully reset to: {new_password}")