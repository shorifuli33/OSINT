"""
Nahidx001 - Local SQLite Database for Search History
Stores search history with timestamps and result counts.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "nahidx001.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS search_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            search_type TEXT NOT NULL,
            query TEXT NOT NULL,
            total_results INTEGER DEFAULT 0,
            employee_count INTEGER DEFAULT 0,
            user_count INTEGER DEFAULT 0,
            results_json TEXT,
            raw_response TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_search(search_type: str, query: str, total_results: int,
                employee_count: int, user_count: int,
                results: list, raw_response: dict):
    """Save a search to history."""
    conn = _get_conn()
    conn.execute(
        """INSERT INTO search_history
           (timestamp, search_type, query, total_results, employee_count, user_count, results_json, raw_response)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now().isoformat(),
            search_type,
            query,
            total_results,
            employee_count,
            user_count,
            json.dumps(results, ensure_ascii=False),
            json.dumps(raw_response, ensure_ascii=False),
        ),
    )
    conn.commit()
    conn.close()


def get_history(limit: int = 100) -> list:
    """Retrieve search history ordered by most recent."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM search_history ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_search_by_id(search_id: int) -> Optional[dict]:
    """Retrieve a specific search by its ID."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM search_history WHERE id = ?", (search_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_aggregate_stats() -> dict:
    """Get aggregate statistics across all searches."""
    conn = _get_conn()
    row = conn.execute("""
        SELECT
            COUNT(*) as total_searches,
            COALESCE(SUM(total_results), 0) as total_breaches,
            COALESCE(SUM(employee_count), 0) as total_employees,
            COALESCE(SUM(user_count), 0) as total_users
        FROM search_history
    """).fetchone()
    conn.close()
    return dict(row) if row else {
        "total_searches": 0,
        "total_breaches": 0,
        "total_employees": 0,
        "total_users": 0,
    }


def delete_history_item(search_id: int):
    """Delete a single history entry."""
    conn = _get_conn()
    conn.execute("DELETE FROM search_history WHERE id = ?", (search_id,))
    conn.commit()
    conn.close()


def clear_all_history():
    """Delete all search history."""
    conn = _get_conn()
    conn.execute("DELETE FROM search_history")
    conn.commit()
    conn.close()


# Initialize the database on import
init_db()
