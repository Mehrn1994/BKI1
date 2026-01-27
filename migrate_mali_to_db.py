"""
Add APN مالی data to database
Run this once to import the مالی sheet
"""

import pandas as pd
import sqlite3
from pathlib import Path

DB_PATH = Path('data/network_ipam.db')

print("=" * 60)
print("Adding APN مالی to Database")
print("=" * 60)

conn = sqlite3.connect(DB_PATH)

# Import مالی sheet
print("\n📁 Importing راه اندازی شده-مالی sheet...")
try:
    df = pd.read_excel('data/Guilanet-Information.xlsx', sheet_name='راه اندازی شده-مالی')
    
    # Clean column names (remove invisible spaces)
    df.columns = df.columns.str.strip()
    
    print(f"   Cleaned columns: {list(df.columns)}")
    
    # Add tracking columns if not exist
    if 'Username' not in df.columns:
        df['Username'] = None
    if 'Reservation Date' not in df.columns:
        df['Reservation Date'] = None
    if 'Tunnel IP Branch' not in df.columns:
        df['Tunnel IP Branch'] = None
    if 'Tunnel IP HUB' not in df.columns:
        df['Tunnel IP HUB'] = None
    if 'Tunnel Number' not in df.columns:
        df['Tunnel Number'] = None
    
    # Save to database
    df.to_sql('apn_mali', conn, if_exists='replace', index=False)
    print(f"   ✓ Saved {len(df)} rows to 'apn_mali' table")
    
    # Count free IPs in 10.250.45.0/21 range
    cursor = conn.cursor()
    
    # Column names after cleaning
    ip_col = 'گیلانتIP'
    branch_col = 'نام محل استقرار'
    
    # Show sample IPs
    print(f"\n   Sample IPs from column '{ip_col}':")
    cursor.execute(f'SELECT "{ip_col}" FROM apn_mali LIMIT 10')
    for row in cursor.fetchall():
        print(f"      - {row[0]}")
    
    # Count total IPs in range
    cursor.execute(f"""
        SELECT COUNT(*) 
        FROM apn_mali 
        WHERE "{ip_col}" LIKE '10.250.4%'
    """)
    total_in_range = cursor.fetchone()[0]
    
    # Count free IPs
    cursor.execute(f"""
        SELECT COUNT(*) 
        FROM apn_mali 
        WHERE "{ip_col}" LIKE '10.250.4%'
          AND ("{branch_col}" IS NULL OR "{branch_col}" = '' OR "{branch_col}" = 'nan')
    """)
    free_count = cursor.fetchone()[0]
    
    print(f"\n   📊 Statistics:")
    print(f"      - Total rows: {len(df)}")
    print(f"      - IPs in 10.250.45.0/21 range: {total_in_range}")
    print(f"      - Free IPs: {free_count}")
    print(f"      - Reserved IPs: {total_in_range - free_count}")
    
except Exception as e:
    print(f"   ✗ Error: {e}")
    import traceback
    traceback.print_exc()

conn.close()

print("\n" + "=" * 60)
print("✅ مالی Data Added to Database!")
print("=" * 60)
