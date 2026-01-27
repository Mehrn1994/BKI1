"""
Reset Tunnel Database and Re-import from Excel
"""

import pandas as pd
import sqlite3
from pathlib import Path

EXCEL_FILE = 'data/ISR-APN-RO-IP-PLAN-2.xlsx'
DB_PATH = 'data/network_ipam.db'

print("="*80)
print("RESETTING TUNNEL DATABASE")
print("="*80)

# Connect to database
print(f"\n💾 Connecting to database: {DB_PATH}")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Check table structure
cursor.execute("PRAGMA table_info(tunnel_ips)")
columns = [row[1] for row in cursor.fetchall()]
print(f"📋 Table columns: {', '.join(columns)}")

# Step 1: Clear all tunnel_ips
print(f"\n🗑️  Clearing tunnel_ips table...")
cursor.execute("DELETE FROM tunnel_ips")
conn.commit()
print(f"✅ Cleared all tunnel IPs")

# Step 2: Read Excel and extract ALL subnets
print(f"\n📂 Reading Excel file: {EXCEL_FILE}")
df = pd.read_excel(EXCEL_FILE, sheet_name='Tunnel Interfaces')

# Find subnet rows
subnet_rows = df[df['Interface Name'].astype(str).str.contains('SUBNET:', na=False)]
print(f"\n🔍 Found {len(subnet_rows)} subnets:")

subnets = []
for idx, row in subnet_rows.iterrows():
    subnet_str = str(row['Interface Name'])
    if 'SUBNET:' in subnet_str:
        subnet = subnet_str.split('SUBNET:')[1].strip()
        subnets.append(subnet)
        print(f"  - {subnet}")

# Step 3: Generate tunnel IPs for each subnet
print(f"\n🔄 Generating tunnel IPs...")

total_inserted = 0

for subnet in subnets:
    # Parse subnet (e.g., "10.156.100.0/24")
    base_ip = subnet.split('/')[0]
    octets = base_ip.split('.')
    
    # Generate /31 pairs: .2/.3, .4/.5, .6/.7, etc.
    for i in range(2, 255, 2):  # Start at .2, step by 2
        hub_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{i}"
        branch_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{i+1}"
        
        # Generate tunnel number (concatenate octets + last octet)
        tunnel_number = f"{octets[0]}{octets[1]}{octets[2]}{str(i).zfill(3)}"
        
        # Insert into database (without subnet column)
        cursor.execute("""
            INSERT INTO tunnel_ips 
            (tunnel_number, tunnel_ip_hub, tunnel_ip_branch, status)
            VALUES (?, ?, ?, 'Free')
        """, (tunnel_number, hub_ip, branch_ip))
        
        total_inserted += 1

conn.commit()

print(f"✅ Inserted {total_inserted} FREE tunnel pairs")

# Step 4: Now mark used tunnels
print(f"\n🔄 Marking USED tunnels as Reserved...")

# Remove header rows
df_clean = df[~df['Interface Name'].str.contains('SUBNET|TITLE|Interface Name', na=False, case=False)]
df_clean = df_clean.dropna(subset=['Interface Name', 'IP Address (/31)'])

# Filter USED tunnels (any with description)
def is_used(desc):
    if pd.isna(desc):
        return False
    desc_str = str(desc).strip()
    return desc_str not in ['', 'nan', 'none']

df_clean['is_used'] = df_clean['Description'].apply(is_used)
df_used = df_clean[df_clean['is_used'] == True].copy()

print(f"  Found {len(df_used)} USED tunnels in Excel")

# Clean IPs
def clean_ip(ip_str):
    if pd.isna(ip_str):
        return None
    ip = str(ip_str).strip()
    ip = ip.replace('/31', '').replace('/32', '').replace('/30', '')
    return ip.strip()

df_used['clean_ip'] = df_used['IP Address (/31)'].apply(clean_ip)

marked = 0
not_found = 0
not_found_list = []

for idx, row in df_used.iterrows():
    tunnel_ip = row['clean_ip']
    description = row['Description']
    
    if not tunnel_ip:
        continue
    
    cursor.execute("""
        UPDATE tunnel_ips 
        SET status = 'Reserved',
            branch_description = ?,
            reserved_at = datetime('now')
        WHERE tunnel_ip_hub = ?
    """, (description, tunnel_ip))
    
    if cursor.rowcount > 0:
        marked += 1
    else:
        not_found += 1
        if not_found <= 10:
            not_found_list.append(f"{tunnel_ip} ({description[:30]})")

conn.commit()

# Final statistics
cursor.execute("SELECT COUNT(*) FROM tunnel_ips WHERE status = 'Free'")
total_free = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM tunnel_ips WHERE status = 'Reserved'")
total_reserved = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM tunnel_ips")
total_all = cursor.fetchone()[0]

print(f"\n✅ Marked {marked} tunnels as Reserved")
print(f"⚠️  Not found: {not_found}")

if not_found_list:
    print(f"\n🔍 Sample NOT FOUND IPs:")
    for nf in not_found_list:
        print(f"  {nf}")

print(f"\n📊 Final Database Statistics:")
print(f"  Total tunnels: {total_all}")
print(f"  FREE tunnels: {total_free}")
print(f"  RESERVED tunnels: {total_reserved}")

# Show sample FREE
print(f"\n🔍 Sample FREE tunnel pairs:")
cursor.execute("SELECT tunnel_number, tunnel_ip_hub, tunnel_ip_branch FROM tunnel_ips WHERE status = 'Free' LIMIT 10")
for row in cursor.fetchall():
    print(f"  Tunnel {row[0]}: HUB={row[1]} ↔ Branch={row[2]}")

conn.close()

print(f"\n{'='*80}")
print("✅ RESET COMPLETED!")
print(f"   Database ready with {total_free} FREE tunnels")
print("="*80)
