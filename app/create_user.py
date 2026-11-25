"""Add a login, or reset its password. Run on the web server:

    sudo webapp-create-user <username>
"""
import getpass
import sys

from werkzeug.security import generate_password_hash

from app import db  # importing app also creates the users table if needed


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: webapp-create-user <username>")
    username = sys.argv[1].strip()

    password = getpass.getpass("Password: ")
    if len(password) < 8:
        sys.exit("Password must be at least 8 characters.")
    if getpass.getpass("Password again: ") != password:
        sys.exit("Passwords do not match.")

    with db() as conn:
        conn.execute(
            """INSERT INTO users (username, password_hash) VALUES (%s, %s)
               ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash""",
            (username, generate_password_hash(password)),
        )
    print(f"User '{username}' saved.")


if __name__ == "__main__":
    main()
