"""
Import ONLY FREE Tunnel IPs from Excel to SQLite Database
Filters out already-used tunnels based on branch descriptions
"""

import pandas as pd
import sqlite3
import re
from pathlib import Path

# Configuration
EXCEL_FILE = 'data/ISR-APN-RO-IP-PLAN-2.xlsx'
DB_PATH = 'data/network_ipam.db'

# Keywords that indicate a tunnel is USED (not free)
USED_INDICATORS = [
    'gilanet', 'kiosk', 'atm', 'branch', 'mall', 'hospital', 
    'clinic', 'university', 'bazar', 'market', 'restaurant',
    'hotel', 'pharmacy', 'cooperative', 'hq', 'tehb', 'teh-',
    'bsh-', 'alz-', 'frs-', 'khz-', 'khr-', 'krm-', 'esf-',
    'yrd-', 'maz-', 'qzv-', 'gil-', 'hmz-', 'lor-', 'snb-'
]

print("="*80)
print("IMPORTING FREE TUNNEL IPs TO DATABASE")
print("="*80)

# Check if file exists
if not Path(EXCEL_FILE).exists():
    print(f"❌ ERROR: File not found: {EXCEL_FILE}")
    exit(1)

# Read Excel file
print(f"\n📂 Reading Excel file: {EXCEL_FILE}")
df = pd.read_excel(EXCEL_FILE, sheet_name='Tunnel Interfaces')
print(f"✓ Loaded {len(df)} rows")

# Clean and filter data
print(f"\n🧹 Filtering FREE tunnels only...")

# Remove subnet header rows
df = df[~df['Interface Name'].str.contains('SUBNET', na=False, case=False)]

# Remove rows with missing critical data
df = df.dropna(subset=['Interface Name', 'IP Address (/31)'])

# Filter: Keep only FREE tunnels (no description or generic description)
def is_free_tunnel(description):
    """Check if tunnel is free based on description"""
    if pd.isna(description) or str(description).strip() == '':
        return True
    
    desc_lower = str(description).lower()
    
    # If description contains any USED indicator, it's NOT free
    for indicator in USED_INDICATORS:
        if indicator in desc_lower:
            return False
    
    return True

df['is_free'] = df['Description'].apply(is_free_tunnel)
df_free = df[df['is_free'] == True].copy()

print(f"  ℹ️  Total tunnels in Excel: {len(df)}")
print(f"  ℹ️  Used tunnels (filtered out): {len(df) - len(df_free)}")
print(f"  ✅ FREE tunnels: {len(df_free)}")

if len(df_free) == 0:
    print("\n⚠️  WARNING: No free tunnels found in Excel!")
    print("   All tunnels appear to be in use.")
    print("   Consider generating new tunnel IP ranges instead.")
    exit(0)

# Clean IP addresses
df_free['IP Address (/31)'] = df_free['IP Address (/31)'].str.strip()

# Extract tunnel number from interface name
def extract_tunnel_number(interface_name):
    """Extract tunnel number from interface name like 'Tunnel18192' -> '18192'"""
    if pd.isna(interface_name):
        return None
    match = re.search(r'(\d+)', str(interface_name))
    return match.group(1) if match else None

df_free['Tunnel Number'] = df_free['Interface Name'].apply(extract_tunnel_number)

# Remove /31 or /32 from IP addresses for storage
df_free['Tunnel IP HUB'] = df_free['IP Address (/31)'].str.replace(r'/\d+', '', regex=True)

# Calculate Tunnel IP Branch (the pair IP)
def calculate_branch_ip(hub_ip):
    """Calculate the paired IP for /31 subnet"""
    if pd.isna(hub_ip):
        return None
    try:
        parts = hub_ip.split('.')
        last_octet = int(parts[3])
        # For /31 pairs, if even -> odd (even+1), if odd -> even (odd-1)
        if last_octet % 2 == 0:
            paired_octet = last_octet + 1
        else:
            paired_octet = last_octet - 1
        return f"{parts[0]}.{parts[1]}.{parts[2]}.{paired_octet}"
    except:
        return None

df_free['Tunnel IP Branch'] = df_free['Tunnel IP HUB'].apply(calculate_branch_ip)

# Connect to database
print(f"\n💾 Connecting to database: {DB_PATH}")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Drop existing table if exists
print(f"\n🗑️  Dropping existing tunnel_ips table (if exists)...")
cursor.execute("DROP TABLE IF EXISTS tunnel_ips")

# Create table
print(f"\n🏗️  Creating tunnel_ips table...")
cursor.execute("""
    CREATE TABLE tunnel_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tunnel_number TEXT UNIQUE,
        interface_name TEXT,
        branch_description TEXT,
        tunnel_ip_hub TEXT,
        tunnel_ip_branch TEXT,
        apn_ip TEXT,
        status TEXT DEFAULT 'Free',
        reserved_by TEXT,
        reserved_at TEXT,
        branch_name TEXT
    )
""")

# Insert data
print(f"\n📥 Inserting {len(df_free)} FREE tunnel records...")
inserted = 0
skipped = 0

for idx, row in df_free.iterrows():
    try:
        # Skip if tunnel_ip_hub or tunnel_ip_branch is missing
        if pd.isna(row['Tunnel IP HUB']) or pd.isna(row['Tunnel IP Branch']):
            skipped += 1
            continue
            
        cursor.execute("""
            INSERT INTO tunnel_ips (
                tunnel_number,
                interface_name,
                branch_description,
                tunnel_ip_hub,
                tunnel_ip_branch,
                apn_ip,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, 'Free')
        """, (
            row['Tunnel Number'],
            row['Interface Name'],
            None,  # No description for free tunnels
            row['Tunnel IP HUB'],
            row['Tunnel IP Branch'],
            row.get('Destination IP', None)
        ))
        inserted += 1
    except Exception as e:
        print(f"  ⚠️  Error inserting row {idx}: {e}")
        skipped += 1

conn.commit()

# Verify insertion
cursor.execute("SELECT COUNT(*) FROM tunnel_ips WHERE status = 'Free'")
count = cursor.fetchone()[0]

print(f"\n✅ Successfully inserted {inserted} FREE tunnel records")
print(f"⚠️  Skipped: {skipped}")
print(f"✅ Database now contains {count} FREE tunnel entries")

# Show sample data
print(f"\n🔍 Sample FREE tunnels from database:")
cursor.execute("SELECT * FROM tunnel_ips WHERE status = 'Free' LIMIT 5")
for row in cursor.fetchall():
    print(f"  Tunnel {row[1]}: {row[4]} <-> {row[5]}")

# Show statistics
cursor.execute("SELECT status, COUNT(*) FROM tunnel_ips GROUP BY status")
print(f"\n📊 Status statistics:")
for row in cursor.fetchall():
    print(f"  {row[0]}: {row[1]}")

conn.close()
print(f"\n{'='*80}")
print("✅ IMPORT COMPLETED SUCCESSFULLY!")
print(f"   FREE tunnels available for reservation: {count}")
print("="*80)
