"""Small user lookup helper — intentional CWE-89 pattern for Antares e2e smoke."""

import sqlite3


def lookup_user(username: str, db_path: str = "app.db") -> list[tuple]:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
