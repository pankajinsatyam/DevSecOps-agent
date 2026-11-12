import hashlib
import sqlite3


def get_user(name):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
