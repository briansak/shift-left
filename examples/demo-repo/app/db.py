import sqlite3


def lookup_user(username: str) -> dict | None:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Intentionally vulnerable pattern for Antares demo — do not deploy.
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return {"username": row[0]} if row else None
