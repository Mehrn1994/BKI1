"""
Update Intranet Database from Latest Excel File
Sync ipplan.xlsx -> network_ipam.db (intranet_tunnels table)
"""
import pandas as pd
import sqlite3
from pathlib import Path
from datetime import datetime

# Paths
DATA_DIR = Path('data')
DB_PATH = DATA_DIR / 'network_ipam.db'
EXCEL_FILE = DATA_DIR / 'ipplan.xlsx'

print("=" * 80)
print("UPDATING INTRANET DATABASE FROM EXCEL")
print("=" * 80)

# Check files exist
if not EXCEL_FILE.exists():
    print(f"❌ ERROR: Excel file not found: {EXCEL_FILE}")
    exit(1)

if not DB_PATH.exists():
    print(f"❌ ERROR: Database not found: {DB_PATH}")
    print("   Run migrate_to_database.py first to create the database.")
    exit(1)

# Read Excel
print(f"\n📂 Reading Excel file: {EXCEL_FILE}")
df = pd.read_excel(EXCEL_FILE, sheet_name='Sheet1')
print(f"   ✓ Loaded {len(df)} rows")
print(f"   ✓ Columns: {list(df.columns)}")

# Column mapping (Excel -> Database)
column_map = {
    'Tunnel Name': 'Tunnel Name',
    'IP Address': 'IP Address',
    'IP LAN': 'IP LAN',
    'IP Intranet': 'IP Intranet',
    'Description': 'Description',
    'Province': 'Province',
    'Status': 'Status',
    'Reserved By': 'Reserved By',
    'Reserved At': 'Reserved At'
}

# Connect to database
print(f"\n🔌 Connecting to database: {DB_PATH}")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Check if table exists
cursor.execute("""
    SELECT name FROM sqlite_master 
    WHERE type='table' AND name='intranet_tunnels'
""")
if not cursor.fetchone():
    print("❌ ERROR: intranet_tunnels table does not exist!")
    print("   Creating table now...")
    cursor.execute("""
        CREATE TABLE intranet_tunnels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            "Tunnel Name" TEXT,
            "IP Address" TEXT UNIQUE NOT NULL,
            "IP LAN" TEXT,
            "IP Intranet" TEXT,
            Description TEXT,
            Province TEXT,
            Status TEXT DEFAULT 'Free',
            "Reserved By" TEXT,
            "Reserved At" TEXT
        )
    """)
    print("   ✓ Table created")

# Clear existing data
print("\n🗑️  Clearing existing intranet_tunnels data...")
cursor.execute("DELETE FROM intranet_tunnels")
deleted_count = cursor.rowcount
print(f"   ✓ Deleted {deleted_count} old records")

# Insert data from Excel
print("\n📥 Inserting data from Excel...")
inserted = 0
skipped = 0

for idx, row in df.iterrows():
    try:
        # Clean IP Address (remove /31 if present)
        ip_address = str(row.get('IP Address', '')).strip()

        # Handle NaN values
        tunnel_name = row.get('Tunnel Name') if pd.notna(row.get('Tunnel Name')) else None
        ip_lan = row.get('IP LAN') if pd.notna(row.get('IP LAN')) else None
        ip_intranet = row.get('IP Intranet') if pd.notna(row.get('IP Intranet')) else None
        description = row.get('Description') if pd.notna(row.get('Description')) else None
        province = row.get('Province') if pd.notna(row.get('Province')) else None
        status = row.get('Status', 'Free') if pd.notna(row.get('Status')) else 'Free'
        reserved_by = row.get('Reserved By') if pd.notna(row.get('Reserved By')) else None
        reserved_at = row.get('Reserved At') if pd.notna(row.get('Reserved At')) else None

        # Convert reserved_at to string if it's a datetime
        if reserved_at and hasattr(reserved_at, 'strftime'):
            reserved_at = reserved_at.strftime('%Y-%m-%d %H:%M:%S')
        elif reserved_at:
            reserved_at = str(reserved_at)

        cursor.execute("""
            INSERT INTO intranet_tunnels (
                "Tunnel Name", "IP Address", "IP LAN", "IP Intranet",
                Description, Province, Status, "Reserved By", "Reserved At"
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tunnel_name, ip_address, ip_lan, ip_intranet,
            description, province, status, reserved_by, reserved_at
        ))
        inserted += 1

    except sqlite3.IntegrityError as e:
        print(f"   ⚠ Row {idx}: Duplicate IP {ip_address}")
        skipped += 1
    except Exception as e:
        print(f"   ❌ Row {idx}: Error - {e}")
        skipped += 1

conn.commit()

# Verify insertion
cursor.execute("SELECT COUNT(*) FROM intranet_tunnels")
total_count = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM intranet_tunnels WHERE Status = 'Free'")
free_count = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM intranet_tunnels WHERE Status = 'Reserved'")
reserved_count = cursor.fetchone()[0]

print(f"\n✅ Successfully inserted: {inserted} records")
if skipped > 0:
    print(f"⚠️  Skipped: {skipped} records")

print(f"\n📊 Database Statistics:")
print(f"   Total tunnels: {total_count}")
print(f"   Free tunnels: {free_count}")
print(f"   Reserved tunnels: {reserved_count}")

# Show sample data - FIXED to handle None values
print(f"\n📋 Sample FREE tunnels from database:")
cursor.execute("""
    SELECT "IP Address", "Tunnel Name", Province, Status 
    FROM intranet_tunnels 
    WHERE Status = 'Free' 
    LIMIT 5
""")
for row in cursor.fetchall():
    ip_addr = row[0] or "N/A"
    tunnel_name = row[1] or "N/A"
    province = row[2] or "N/A"
    status = row[3] or "N/A"
    print(f"   {ip_addr:20} {tunnel_name:15} {province:10} {status}")

print(f"\n📋 Sample RESERVED tunnels from database:")
cursor.execute("""
    SELECT "IP Address", "Tunnel Name", Description, "Reserved By"
    FROM intranet_tunnels 
    WHERE Status = 'Reserved' 
    LIMIT 5
""")
for row in cursor.fetchall():
    ip_addr = row[0] or "N/A"
    tunnel_name = row[1] or "N/A"
    description = row[2] or "N/A"
    reserved_by = row[3] or "N/A"
    print(f"   {ip_addr:20} {tunnel_name:15} {description:25} By: {reserved_by}")

conn.close()

print("\n" + "=" * 80)
print("✅ DATABASE UPDATE COMPLETED SUCCESSFULLY!")
print("=" * 80)