"""
Create reserved_ips table for LAN IP reservation system.

Run this script once (from the same folder as server_database.py)
to create the table in data/network_ipam.db if it does not exist.
"""

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "network_ipam.db"


def create_reserved_ips_table():
    print("=" * 80)
    print(f"Creating 'reserved_ips' table in: {DB_PATH}")
    print("=" * 80)

    if not DATA_DIR.exists():
        print(f"Creating data directory: {DATA_DIR}")
        DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reserved_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lan_ip TEXT NOT NULL UNIQUE,
                province TEXT NOT NULL,
                point_name_persian TEXT NOT NULL,
                request_number TEXT NOT NULL,
                mehrgestar_code TEXT,
                point_type TEXT NOT NULL,
                reserved_by TEXT NOT NULL,
                reserved_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                expiry_date DATETIME NOT NULL,
                status TEXT DEFAULT 'RESERVED',
                used_in_config TEXT,
                used_date DATETIME
            )
        """)

        conn.commit()
        conn.close()

        print("✅ Table 'reserved_ips' created (or already exists).")
        print("Columns:")
        print(" - id (INTEGER, PK)")
        print(" - lan_ip (TEXT, UNIQUE)")
        print(" - province (TEXT)")
        print(" - point_name_persian (TEXT)")
        print(" - request_number (TEXT)")
        print(" - mehrgestar_code (TEXT)")
        print(" - point_type (TEXT)")
        print(" - reserved_by (TEXT)")
        print(" - reserved_date (DATETIME, default now)")
        print(" - expiry_date (DATETIME, must be set by application)")
        print(" - status (TEXT: RESERVED / USED / EXPIRED)")
        print(" - used_in_config (TEXT: INTRANET / APN-INT / APN-MALI)")
        print(" - used_date (DATETIME)")
        print("=" * 80)
        print("Done.")
    except Exception as e:
        print("❌ Error creating reserved_ips table:", e)
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    create_reserved_ips_table()
