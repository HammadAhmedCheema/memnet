import sqlite3
import os

DB_PATH = "mft_session.db"

def get_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    """Initialize a fresh session database."""
    # Ensure any old session file is cleared on start
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except:
            pass
            
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plugin_name TEXT,
            results_json TEXT,
            params_json TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def insert_scan_result(plugin_name, results_json, params_json="{}"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_results (plugin_name, results_json, params_json) VALUES (?, ?, ?)",
        (plugin_name, results_json, params_json)
    )
    conn.commit()
    conn.close()

def get_all_scan_results():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT plugin_name, results_json FROM scan_results")
    rows = cursor.fetchall()
    conn.close()
    return rows

def cleanup_session_db():
    """Flush and remove the session database file."""
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
            print(f"// SESSION_FLUSH: {DB_PATH} removed.")
        except Exception as e:
            print(f"// ERROR_FLUSH: {str(e)}")
