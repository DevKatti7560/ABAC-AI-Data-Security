import sqlite3
from pathlib import Path


DATABASE_PATH = Path("database/abac.db")


def get_connection():
    """Create and return a SQLite database connection."""

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    return sqlite3.connect(DATABASE_PATH)


def initialize_database():
    """Create the audit log table if it does not exist."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT,
            department TEXT,
            resource TEXT NOT NULL,
            classification TEXT,
            action TEXT NOT NULL,
            purpose TEXT,
            decision TEXT NOT NULL,
            policy_id TEXT,
            policy_name TEXT,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    connection.commit()
    connection.close()


def insert_access_log(
    request,
    decision,
    policy_id,
    policy_name,
    reason
):
    """Store an authorization decision in the audit log."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO access_logs (
            request_id,
            user_id,
            role,
            department,
            resource,
            classification,
            action,
            purpose,
            decision,
            policy_id,
            policy_name,
            reason
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request.get("request_id"),
            request.get("user_id"),
            request.get("role"),
            request.get("department"),
            request.get("resource"),
            request.get("classification"),
            request.get("action"),
            request.get("purpose"),
            decision,
            policy_id,
            policy_name,
            reason
        )
    )

    connection.commit()
    connection.close()


def get_access_logs():
    """Retrieve all access logs."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            request_id,
            user_id,
            role,
            department,
            resource,
            classification,
            action,
            purpose,
            decision,
            policy_id,
            policy_name,
            reason,
            timestamp
        FROM access_logs
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    connection.close()

    return rows


if __name__ == "__main__":

    initialize_database()

    print("SQLite database initialized successfully.")
    print(f"Database: {DATABASE_PATH}")