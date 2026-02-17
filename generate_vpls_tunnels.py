"""
Generate VPLS/MPLS Tunnel IP /31 Pairs PER PROVINCE and populate database.
Each province has its own independent pool of 100.100.100.x tunnel IPs.
IP Range per province: 100.100.100.0 - 100.100.100.255 (128 /31 pairs)

Each /31 pair:
  - hub_ip: even IP (e.g. 100.100.100.0)
  - branch_ip: odd IP (e.g. 100.100.100.1)
  - ip_address: pair notation (e.g. 100.100.100.0/31)
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'network_ipam.db')

# All provinces that need VPLS/MPLS tunnel pools
PROVINCES = [
    'Tehran', 'Alborz', 'East Azerbaijan', 'West Azerbaijan',
    'Kurdistan', 'Isfahan', 'Razavi Khorasan', 'Fars', 'Kerman',
    'Khuzestan', 'Lorestan', 'Gilan', 'Golestan', 'Mazandaran',
    'Sistan and Baluchestan', 'Yazd', 'Zanjan', 'Semnan', 'Markazi',
    'Hamadan', 'Qazvin', 'Qom', 'Ardabil', 'Ilam', 'Bushehr',
    'Chaharmahal and Bakhtiari', 'Hormozgan', 'Kermanshah',
    'Kohgiluyeh and Boyer-Ahmad', 'North Khorasan', 'South Khorasan',
]

# IP Range: 100.100.100.0 - 100.100.100.255 = 128 /31 pairs per province
BASE = '100.100.100'


def generate_pairs():
    """Generate /31 IP pairs for one province"""
    pairs = []
    for fourth in range(0, 256, 2):  # 0,2,4,...254 = 128 pairs
        hub_ip = f"{BASE}.{fourth}"
        branch_ip = f"{BASE}.{fourth + 1}"
        ip_address = f"{hub_ip}/31"
        pairs.append((ip_address, hub_ip, branch_ip))
    return pairs


def populate_database():
    """Insert per-province /31 pairs into vpls_tunnels table"""
    print(f"\nConnecting to database: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create table if not exists
    cursor.execute("""CREATE TABLE IF NOT EXISTS vpls_tunnels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        hub_ip TEXT,
        branch_ip TEXT,
        tunnel_name TEXT,
        description TEXT,
        province TEXT,
        branch_name TEXT,
        wan_ip TEXT,
        tunnel_dest TEXT,
        status TEXT DEFAULT 'Free',
        username TEXT,
        reservation_date TEXT)""")

    # Clear existing data
    cursor.execute("SELECT COUNT(*) FROM vpls_tunnels")
    existing = cursor.fetchone()[0]
    if existing > 0:
        print(f"  Clearing {existing} existing records...")
        cursor.execute("DELETE FROM vpls_tunnels")

    pairs = generate_pairs()
    total_inserted = 0

    for province in PROVINCES:
        for ip_address, hub_ip, branch_ip in pairs:
            cursor.execute("""
                INSERT INTO vpls_tunnels (ip_address, hub_ip, branch_ip, province, status)
                VALUES (?, ?, ?, ?, 'Free')
            """, (ip_address, hub_ip, branch_ip, province))
            total_inserted += 1

    conn.commit()

    # Create index for fast province+status lookups
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vpls_tunnels_status ON vpls_tunnels(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vpls_tunnels_province ON vpls_tunnels(province, status)")

    # Verify
    cursor.execute("SELECT province, COUNT(*) FROM vpls_tunnels GROUP BY province ORDER BY province")
    print(f"\nInserted {total_inserted} records ({len(PROVINCES)} provinces x {len(pairs)} pairs):")
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]} pairs")

    conn.close()
    return total_inserted


if __name__ == '__main__':
    print("=" * 70)
    print("GENERATING PER-PROVINCE VPLS/MPLS TUNNEL IP /31 PAIRS")
    print("=" * 70)
    print(f"\nIP Range per province: {BASE}.0 - {BASE}.255 (128 /31 pairs)")
    print(f"Provinces: {len(PROVINCES)}")

    count = populate_database()

    print(f"\n{'=' * 70}")
    print(f"DONE! {count} VPLS/MPLS tunnel IP pairs ready for use")
    print("=" * 70)
