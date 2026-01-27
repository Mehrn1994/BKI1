"""
Fixed version - handles different column structures
"""

import pandas as pd
import sqlite3
from pathlib import Path

print("=" * 60)
print("STEP 1: Converting Excel to SQLite Database")
print("=" * 60)

db_path = Path('data/network_ipam.db')
conn = sqlite3.connect(db_path)
print(f"✓ Created database: {db_path}")

# === Convert ipplan.xlsx ===
print("\n📁 Converting ipplan.xlsx...")
try:
    df = pd.read_excel('data/ipplan.xlsx', sheet_name='Sheet1')
    df.to_sql('intranet_tunnels', conn, if_exists='replace', index=False)
    print(f"   ✓ Saved {len(df)} rows to 'intranet_tunnels' table")
except Exception as e:
    print(f"   ✗ Error: {e}")

# === Convert IP-ATM-1.xlsx (FIXED) ===
print("\n📁 Converting IP-ATM-1.xlsx (all provinces)...")
try:
    xls = pd.ExcelFile('data/IP-ATM-1.xlsx')
    total_rows = 0
    
    # First, create the table structure manually
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS lan_ips (
            province TEXT,
            branch_name TEXT,
            octet1 INTEGER,
            octet2 INTEGER,
            octet3 INTEGER,
            username TEXT,
            reservation_date TEXT,
            row_number INTEGER
        )
    """)
    
    for sheet_name in xls.sheet_names:
        print(f"   Processing {sheet_name}...")
        df = pd.read_excel(xls, sheet_name=sheet_name, header=None)
        
        # Process each row
        for idx, row in df.iterrows():
            try:
                branch_name = row.iloc[2] if len(row) > 2 else None
                octet1 = int(row.iloc[3]) if len(row) > 3 and pd.notna(row.iloc[3]) else None
                octet2 = int(row.iloc[4]) if len(row) > 4 and pd.notna(row.iloc[4]) else None
                octet3 = int(row.iloc[5]) if len(row) > 5 and pd.notna(row.iloc[5]) else None
                username = row.iloc[6] if len(row) > 6 else None
                res_date = row.iloc[7] if len(row) > 7 else None
                
                # Only save rows with valid IP structure (10.X.Y.0)
                if octet1 == 10 and octet2 and octet3:
                    cursor.execute("""
                        INSERT INTO lan_ips 
                        (province, branch_name, octet1, octet2, octet3, username, reservation_date, row_number)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        sheet_name,
                        str(branch_name) if pd.notna(branch_name) else None,
                        octet1,
                        octet2,
                        octet3,
                        str(username) if pd.notna(username) else None,
                        str(res_date) if pd.notna(res_date) else None,
                        idx
                    ))
                    total_rows += 1
                    
            except (ValueError, TypeError, IndexError):
                continue
        
        print(f"      ✓ Processed {sheet_name}")
    
    conn.commit()
    print(f"   ✓ Total: {total_rows} LAN IPs saved")
    
except Exception as e:
    print(f"   ✗ Error: {e}")
    import traceback
    traceback.print_exc()

# === Convert Guilanet-Information.xlsx ===
print("\n📁 Converting Guilanet-Information.xlsx...")
try:
    df = pd.read_excel('data/Guilanet-Information.xlsx', sheet_name='غیرمالی')
    df.to_sql('apn_ips', conn, if_exists='replace', index=False)
    print(f"   ✓ Saved {len(df)} rows to 'apn_ips' table")
except Exception as e:
    print(f"   ✗ Error: {e}")

conn.close()

print("\n" + "=" * 60)
print("✅ MIGRATION COMPLETE!")
print("=" * 60)
print(f"Database created: {db_path}")
print("\nYour Excel files are still there (not deleted)")
print("Now you can test with: python test_database.py")
