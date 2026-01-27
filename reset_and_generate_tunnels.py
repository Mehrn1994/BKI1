"""
RESET & Generate FREE Tunnel IP Pairs from ACTUAL Excel Subnets
Uses the exact IP ranges from ISR-APN-RO-IP-PLAN-2.xlsx
"""

import sqlite3
from pathlib import Path

DB_PATH = 'data/network_ipam.db'

# EXACT subnets from your Excel file
TUNNEL_SUBNETS = [
    '10.156.100.0/24',  # 4 free pairs
    '10.158.100.0/24',  # 79 free pairs
    '10.159.100.0/24',  # 4 free pairs
    '10.161.100.0/24',  # 7 free pairs
    '10.163.100.0/24',  # 3 free pairs
    '10.164.100.0/24',  # 112 free pairs (MOST FREE!)
]

def generate_tunnel_pairs(subnet):
    """Generate /31 tunnel pairs from a /24 subnet"""
    pairs = []
    
    parts = subnet.split('/')
    base_ip = parts[0]
    octets = base_ip.split('.')
    
    base = f"{octets[0]}.{octets[1]}.{octets[2]}"
    
    # Generate pairs: 2-3, 4-5, 6-7, ..., 252-253
    for i in range(2, 254, 2):
        hub_ip = f"{base}.{i}"
        branch_ip = f"{base}.{i+1}"
        
        pairs.append({
            'hub': hub_ip,
            'branch': branch_ip,
            'subnet': subnet
        })
    
    return pairs

print("="*80)
print("RESET & GENERATE FREE TUNNEL IP PAIRS")
print("Using ACTUAL Excel subnets only")
print("="*80)

# Connect to database
print(f"\n💾 Connecting to database: {DB_PATH}")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# DROP and recreate table
print(f"\n🗑️  Dropping old tunnel_ips table...")
cursor.execute("DROP TABLE IF EXISTS tunnel_ips")

print(f"🏗️  Creating fresh tunnel_ips table...")
cursor.execute("""
    CREATE TABLE tunnel_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tunnel_number TEXT UNIQUE,
        interface_name TEXT,
        branch_description TEXT,
        tunnel_ip_hub TEXT UNIQUE,
        tunnel_ip_branch TEXT UNIQUE,
        apn_ip TEXT,
        status TEXT DEFAULT 'Free',
        reserved_by TEXT,
        reserved_at TEXT,
        branch_name TEXT
    )
""")

# Generate all pairs
print(f"\n🔄 Generating tunnel pairs...")
all_pairs = []
for subnet in TUNNEL_SUBNETS:
    pairs = generate_tunnel_pairs(subnet)
    all_pairs.extend(pairs)
    print(f"  ✓ Generated {len(pairs)} pairs from {subnet}")

print(f"\n📊 Total tunnel pairs generated: {len(all_pairs)}")

# Insert new tunnel pairs
print(f"\n📥 Inserting tunnel pairs...")
inserted = 0

for idx, pair in enumerate(all_pairs, start=1):
    hub = pair['hub']
    branch = pair['branch']
    
    try:
        # Generate UNIQUE tunnel number using HUB IP (no dots)
        # Example: 10.156.100.2 -> Tunnel10156100002
        octets = hub.split('.')
        tunnel_num = f"{octets[0]}{octets[1]}{octets[2]}{int(octets[3]):03d}"
        
        cursor.execute("""
            INSERT INTO tunnel_ips (
                tunnel_number,
                interface_name,
                tunnel_ip_hub,
                tunnel_ip_branch,
                status
            ) VALUES (?, ?, ?, ?, 'Free')
        """, (
            tunnel_num,
            f"Tunnel{tunnel_num}",
            hub,
            branch
        ))
        
        inserted += 1
            
    except Exception as e:
        print(f"  ⚠️  Error inserting pair {idx} ({hub}): {e}")

conn.commit()

# Verify
cursor.execute("SELECT COUNT(*) FROM tunnel_ips WHERE status = 'Free'")
total_free = cursor.fetchone()[0]

print(f"\n✅ Successfully inserted {inserted} tunnel pairs")
print(f"📊 Total FREE tunnel pairs in database: {total_free}")

# Show sample from each subnet
print(f"\n🔍 Sample FREE tunnel pairs (from each subnet):")
for subnet in TUNNEL_SUBNETS:
    base = subnet.split('/')[0].rsplit('.', 1)[0]
    cursor.execute(f"""
        SELECT tunnel_number, tunnel_ip_hub, tunnel_ip_branch 
        FROM tunnel_ips 
        WHERE tunnel_ip_hub LIKE '{base}.%' 
        AND status = 'Free' 
        LIMIT 2
    """)
    rows = cursor.fetchall()
    print(f"\n  From {subnet}:")
    for row in rows:
        print(f"    Tunnel {row[0]}: HUB={row[1]} ↔ Branch={row[2]}")

conn.close()

print(f"\n{'='*80}")
print("✅ GENERATION COMPLETED!")
print(f"   {total_free} tunnels from ACTUAL Excel ranges")
print("="*80)
