
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

# Store the database in the project root.
BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "shopify_tokens.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    """Create the Shopify token table if it doesn't exist."""

    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS shopify_tokens (
                shop TEXT PRIMARY KEY,
                customer_id TEXT NOT NULL,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                refresh_token_expires_at TEXT,
                updated_at TEXT NOT NULL
            )
        """)


def save_token(shop: str, token_data: dict):
    """Insert or update a Shopify store's credentials."""

    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        connection.execute("""
            INSERT INTO shopify_tokens (
                shop,
                customer_id,
                access_token,
                refresh_token,
                expires_at,
                refresh_token_expires_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(shop) DO UPDATE SET
                customer_id = excluded.customer_id,
                access_token = excluded.access_token,
                refresh_token = excluded.refresh_token,
                expires_at = excluded.expires_at,
                refresh_token_expires_at = excluded.refresh_token_expires_at,
                updated_at = excluded.updated_at
        """, (
            shop,
            token_data["customer_id"],
            token_data["access_token"],
            token_data["refresh_token"],
            token_data["expires_at"],
            token_data.get("refresh_token_expires_at"),
            now
        ))


def get_token(shop: str):
    """Retrieve credentials for a Shopify store."""

    with get_connection() as connection:
        row = connection.execute("""
            SELECT *
            FROM shopify_tokens
            WHERE shop = ?
        """, (shop,)).fetchone()

    return dict(row) if row else None


def delete_token(shop: str):
    """Delete a store's credentials when disconnected."""

    with get_connection() as connection:
        connection.execute("""
            DELETE FROM shopify_tokens
            WHERE shop = ?
        """, (shop,))
