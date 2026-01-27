"""
Auto-Generate Free /31 Tunnel IP Pairs
Creates tunnel pairs from unused IP subnets
"""

import sqlite3
from pathlib import Path

DB_PATH = 'data/network_ipam.db'

# Define IP ranges for tunnel generation
TUNNEL_SUBNETS = [
    '10.164.100.0/24',  # Extend existing subnet
    '10.165.100.0/24',  # New subnet
    '10.166.100.0/24',  # New subnet
    '10.167.100.0/24',  # New subnet
]

def generate_tunnel_pairs(subnet):
    """
    Generate /31 tunnel pairs from a /24 subnet
    A /24 subnet (e.g., 10.164.100.0/24) can provide 126 /31 pairs
    """
    pairs = []
    
    # Extract base IP
    parts = subnet.split('/')
    base_ip = parts[0]
    octets = base_ip.split('.')
    
    base = f"{octets[0]}.{octets[1]}.{octets[2]}"
    
    # Generate pairs: 0-1, 2-3, 4-5, ..., 252-253
    # Skip .0 and .255 (network/broadcast)
    for i in range(2, 254, 2):  # Start from 2, step by 2
        hub_ip = f"{base}.{i}"
        branch_ip = f"{base}.{i+1}"
        
        pairs.append({
            'hub': hub_ip,
            'branch': branch_ip,
            'subnet': subnet
        })
    
    return pairs

print("="*80)
print("AUTO-GENERATING FREE TUNNEL IP PAIRS")
print("="*80)

# Generate all pairs
all_pairs = []
for subnet in TUNNEL_SUBNETS:
    pairs = generate_tunnel_pairs(subnet)
    all_pairs.extend(pairs)
    print(f"\n✓ Generated {len(pairs)} pairs from {subnet}")

print(f"\n📊 Total tunnel pairs generated: {len(all_pairs)}")

# Connect to database
print(f"\n💾 Connecting to database: {DB_PATH}")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Check if table exists, if not create it
cursor.execute("""
    CREATE TABLE IF NOT EXISTS tunnel_ips (
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

# Get existing tunnel IPs to avoid duplicates
cursor.execute("SELECT tunnel_ip_hub, tunnel_ip_branch FROM tunnel_ips")
existing = set((row[0], row[1]) for row in cursor.fetchall())
print(f"  ℹ️  Existing tunnels in database: {len(existing)}")

# Insert new tunnel pairs
print(f"\n📥 Inserting new tunnel pairs...")
inserted = 0
skipped = 0

for idx, pair in enumerate(all_pairs, start=1):
    hub = pair['hub']
    branch = pair['branch']
    
    # Skip if already exists
    if (hub, branch) in existing:
        skipped += 1
        continue
    
    try:
        # Generate a unique tunnel number based on IP
        # Format: subnet_id + octet4
        # Example: 10.164.100.34 -> tunnel number: 164034
        octets = hub.split('.')
        # Convert to int for formatting
        tunnel_num = f"{int(octets[2])}{int(octets[3]):03d}"  # ← FIXED: Convert to int
        
        cursor.execute("""
            INSERT OR IGNORE INTO tunnel_ips (
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
        
        if cursor.rowcount > 0:
            inserted += 1
        else:
            skipped += 1
            
    except Exception as e:
        print(f"  ⚠️  Error inserting pair {idx} ({hub}): {e}")
        skipped += 1

conn.commit()

# Verify
cursor.execute("SELECT COUNT(*) FROM tunnel_ips WHERE status = 'Free'")
total_free = cursor.fetchone()[0]

print(f"\n✅ Successfully inserted {inserted} new tunnel pairs")
print(f"⚠️  Skipped (duplicates): {skipped}")
print(f"\n📊 Total FREE tunnel pairs in database: {total_free}")

# Show sample
print(f"\n🔍 Sample FREE tunnel pairs:")
cursor.execute("SELECT tunnel_number, tunnel_ip_hub, tunnel_ip_branch FROM tunnel_ips WHERE status = 'Free' LIMIT 10")
for row in cursor.fetchall():
    print(f"  Tunnel {row[0]}: HUB={row[1]} ↔ Branch={row[2]}")

conn.close()

print(f"\n{'='*80}")
print("✅ GENERATION COMPLETED SUCCESSFULLY!")
print(f"   Total FREE tunnels available: {total_free}")
print("="*80)
