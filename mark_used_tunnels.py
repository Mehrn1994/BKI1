"""
Mark Used Tunnel IPs as Reserved
FIXED: Detects ANY non-empty description as USED
"""

import pandas as pd
import sqlite3
from pathlib import Path

EXCEL_FILE = 'data/ISR-APN-RO-IP-PLAN-2.xlsx'
DB_PATH = 'data/network_ipam.db'

print("="*80)
print("MARKING USED TUNNEL IPs AS RESERVED")
print("="*80)

if not Path(EXCEL_FILE).exists():
    print(f"❌ ERROR: File not found: {EXCEL_FILE}")
    exit(1)

print(f"\n📂 Reading Excel file: {EXCEL_FILE}")
df = pd.read_excel(EXCEL_FILE, sheet_name='Tunnel Interfaces')
print(f"✓ Loaded {len(df)} rows")

# Remove subnet header rows
df = df[~df['Interface Name'].str.contains('SUBNET|TITLE|Interface Name', na=False, case=False)]
df = df.dropna(subset=['Interface Name', 'IP Address (/31)'])

# Filter: ANY row with description = USED
def is_used_tunnel(description):
    """ANY non-empty description = USED tunnel"""
    if pd.isna(description):
        return False
    
    desc_str = str(description).strip()
    
    # Empty or just whitespace = Free
    if desc_str == '' or desc_str.lower() in ['nan', 'none', '']:
        return False
    
    # Anything else = USED
    return True

df['is_used'] = df['Description'].apply(is_used_tunnel)
df_used = df[df['is_used'] == True].copy()

print(f"\n📊 Statistics:")
print(f"  Total tunnels in Excel: {len(df)}")
print(f"  Used tunnels (to mark as Reserved): {len(df_used)}")
print(f"  Free tunnels (remain Free): {len(df) - len(df_used)}")

# Clean IP addresses - REMOVE /31 or /32 suffix
def clean_ip(ip_str):
    if pd.isna(ip_str):
        return None
    
    ip = str(ip_str).strip()
    
    # Remove /31 or /32
    if '/31' in ip:
        ip = ip.replace('/31', '')
    if '/32' in ip:
        ip = ip.replace('/32', '')
    
    return ip.strip()

df_used['clean_ip_hub'] = df_used['IP Address (/31)'].apply(clean_ip)

print(f"\n🔍 Sample Excel IPs (HUB side - first 10):")
for idx, row in df_used.head(10).iterrows():
    desc = row['Description'][:50] if len(str(row['Description'])) > 50 else row['Description']
    print(f"  {row['clean_ip_hub']} -> {desc}")

# Connect to database
print(f"\n💾 Connecting to database: {DB_PATH}")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Mark used tunnels as Reserved
print(f"\n🔄 Marking used tunnels as 'Reserved'...")
marked = 0
not_found = 0
not_found_list = []

for idx, row in df_used.iterrows():
    tunnel_ip_hub = row['clean_ip_hub']
    description = row['Description']
    
    if not tunnel_ip_hub:
        continue
    
    try:
        cursor.execute("""
            UPDATE tunnel_ips 
            SET status = 'Reserved',
                branch_description = ?,
                reserved_at = datetime('now')
            WHERE tunnel_ip_hub = ?
            AND status = 'Free'
        """, (description, tunnel_ip_hub))
        
        if cursor.rowcount > 0:
            marked += 1
        else:
            not_found += 1
            if not_found <= 10:
                not_found_list.append(f"{tunnel_ip_hub} ({description[:30]})")
            
    except Exception as e:
        print(f"  ⚠️  Error updating {tunnel_ip_hub}: {e}")

conn.commit()

# Get statistics
cursor.execute("SELECT COUNT(*) FROM tunnel_ips WHERE status = 'Free'")
total_free = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM tunnel_ips WHERE status = 'Reserved'")
total_reserved = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM tunnel_ips")
total_all = cursor.fetchone()[0]

print(f"\n✅ Successfully marked {marked} tunnels as Reserved")
print(f"⚠️  Not found in database: {not_found}")

if not_found_list:
    print(f"\n🔍 Sample NOT FOUND IPs:")
    for nf in not_found_list:
        print(f"  {nf}")

print(f"\n📊 Database Statistics:")
print(f"  Total tunnels: {total_all}")
print(f"  FREE tunnels: {total_free}")
print(f"  RESERVED tunnels: {total_reserved}")

# Show sample FREE tunnels
print(f"\n🔍 Sample FREE tunnel pairs (ready to use):")
cursor.execute("SELECT tunnel_number, tunnel_ip_hub, tunnel_ip_branch FROM tunnel_ips WHERE status = 'Free' LIMIT 10")
for row in cursor.fetchall():
    print(f"  Tunnel {row[0]}: HUB={row[1]} ↔ Branch={row[2]}")

conn.close()

print(f"\n{'='*80}")
print("✅ COMPLETED!")
print(f"   {total_free} truly FREE tunnels available")
print(f"   {total_reserved} already-used tunnels marked as Reserved")
print("="*80)
