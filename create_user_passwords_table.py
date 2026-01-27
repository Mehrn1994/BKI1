"""
Create user_passwords table for authentication
Run this script once to add password authentication to your database
"""
import sqlite3
from pathlib import Path

# Database path
DATA_DIR = Path(__file__).parent / 'data'
DB_PATH = DATA_DIR / 'network_ipam.db'

def create_passwords_table():
    """Create user_passwords table"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        
        print("✅ user_passwords table created successfully!")
        print(f"📂 Database: {DB_PATH}")
        
    except Exception as e:
        print(f"❌ Error creating table: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    create_passwords_table()
