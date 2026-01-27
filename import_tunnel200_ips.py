"""
Import Tunnel200 /31 IP pairs into database
Based on APN-INT-HUB.xlsx
"""

import sqlite3
import pandas as pd
from pathlib import Path

# Paths
DATA_DIR = Path('data')
DB_PATH = DATA_DIR / 'network_ipam.db'
EXCEL_FILE = DATA_DIR / 'APN-INT-HUB.xlsx'

print("="*80)
print("IMPORTING TUNNEL200 /31 IP PAIRS TO DATABASE")
print("="*80)

# Read Excel file
print(f"\nReading Excel file: {EXCEL_FILE}")
df = pd.read_excel(EXCEL_FILE)
print(f"Loaded {len(df)} rows")

# Extract used IPs
used_octets = set()
print("\nExtracting used IP addresses...")

for idx, row in df.iterrows():
    tunnel = row['Interface Name']
    ip_val = row['IP Address (/31)']
    
    if pd.notna(tunnel) and str(tunnel).startswith('Tunnel') and pd.notna(ip_val):
        ip_str = str(ip_val).strip().replace('/31', '').strip()
        if ip_str.startswith('10.200.1.'):
            parts = ip_str.split('.')
            if len(parts) == 4:
                try:
                    last_octet = int(parts[3])
                    # For /31, both even and odd are used in the pair
                    if last_octet % 2 == 0:  # Even number (HUB side)
                        used_octets.add(last_octet)
                        used_octets.add(last_octet + 1)
                    else:  # Odd number (Branch side)
                        used_octets.add(last_octet - 1)
                        used_octets.add(last_octet)
                except:
                    pass

print(f"  Used octets: {len(used_octets)}")
print(f"  Used /31 pairs: {len(used_octets) // 2}")

# Connect to database
print(f"\nConnecting to database: {DB_PATH}")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Drop and recreate table
print("Dropping existing tunnel200_ips table if exists...")
cursor.execute("DROP TABLE IF EXISTS tunnel200_ips")

print("Creating tunnel200_ips table...")
cursor.execute("""
    CREATE TABLE tunnel200_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hub_ip TEXT NOT NULL UNIQUE,
        branch_ip TEXT NOT NULL UNIQUE,
        pair_notation TEXT NOT NULL,
        status TEXT DEFAULT 'Free',
        tunnel_number TEXT,
        branch_name TEXT,
        description TEXT,
        username TEXT,
        reservation_date TEXT
    )
""")

# Generate all /31 pairs and insert FREE ones
print("\nGenerating and inserting FREE /31 pairs...")
inserted = 0
skipped = 0

for i in range(0, 255, 2):  # Even numbers for HUB side
    hub_octet = i
    branch_octet = i + 1
    
    # Check if this pair is free
    if hub_octet not in used_octets and branch_octet not in used_octets:
        hub_ip = f'10.200.1.{hub_octet}'
        branch_ip = f'10.200.1.{branch_octet}'
        pair_notation = f'10.200.1.{hub_octet}/31'
        
        try:
            cursor.execute("""
                INSERT INTO tunnel200_ips (hub_ip, branch_ip, pair_notation, status)
                VALUES (?, ?, ?, 'Free')
            """, (hub_ip, branch_ip, pair_notation))
            inserted += 1
        except sqlite3.IntegrityError:
            skipped += 1

conn.commit()

# Verify
cursor.execute("SELECT COUNT(*) FROM tunnel200_ips WHERE status = 'Free'")
free_count = cursor.fetchone()[0]

print(f"\n  ✓ Successfully inserted {inserted} FREE /31 pairs")
if skipped > 0:
    print(f"  ⚠ Skipped {skipped} duplicates")
print(f"\n  Database now contains {free_count} FREE Tunnel200 IP pairs")

# Show sample
print("\nSample FREE Tunnel200 IP pairs from database:")
cursor.execute("""
    SELECT hub_ip, branch_ip, pair_notation 
    FROM tunnel200_ips 
    WHERE status = 'Free' 
    ORDER BY hub_ip
    LIMIT 10
""")

for row in cursor.fetchall():
    print(f"  HUB: {row[0]:15} | Branch: {row[1]:15} | Pair: {row[2]}")

# Status statistics
cursor.execute("SELECT status, COUNT(*) FROM tunnel200_ips GROUP BY status")
print("\nStatus statistics:")
for row in cursor.fetchall():
    print(f"  {row[0]}: {row[1]}")

conn.close()

print("\n" + "="*80)
print("IMPORT COMPLETED SUCCESSFULLY!")
print(f"FREE Tunnel200 /31 pairs available for auto-assignment: {free_count}")
print("="*80)
