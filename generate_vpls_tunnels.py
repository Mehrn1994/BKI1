"""
Generate VPLS/MPLS Tunnel IP /31 Pairs and populate database + Excel
IP Range: 100.100.100.0 - 100.100.103.255 (1024 IPs = 512 /31 pairs)

Each /31 pair:
  - hub_ip: even IP (e.g. 100.100.100.0)
  - branch_ip: odd IP (e.g. 100.100.100.1)
  - ip_address: pair notation (e.g. 100.100.100.0/31)
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'network_ipam.db')
EXCEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'VPLS_MPLS_Tunnel_IPs.xlsx')

# IP Range for VPLS/MPLS tunnels: 100.100.100.0/22
# This gives us 100.100.100.0 - 100.100.103.255 = 512 /31 pairs
BASE_OCTETS = [100, 100]
THIRD_OCTETS = [100, 101, 102, 103]  # 4 x 256 = 1024 IPs = 512 pairs

def generate_pairs():
    """Generate /31 IP pairs"""
    pairs = []
    for third in THIRD_OCTETS:
        for fourth in range(0, 256, 2):  # Step by 2 for /31 pairs
            hub_ip = f"{BASE_OCTETS[0]}.{BASE_OCTETS[1]}.{third}.{fourth}"
            branch_ip = f"{BASE_OCTETS[0]}.{BASE_OCTETS[1]}.{third}.{fourth + 1}"
            ip_address = f"{hub_ip}/31"
            pairs.append((ip_address, hub_ip, branch_ip))
    return pairs

def populate_database(pairs):
    """Insert /31 pairs into vpls_tunnels table"""
    print(f"\n💾 Connecting to database: {DB_PATH}")
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

    # Check existing count
    cursor.execute("SELECT COUNT(*) FROM vpls_tunnels")
    existing = cursor.fetchone()[0]

    if existing > 0:
        print(f"⚠️  Table already has {existing} records.")
        print("   Clearing and regenerating...")
        cursor.execute("DELETE FROM vpls_tunnels")

    # Insert pairs
    inserted = 0
    for ip_address, hub_ip, branch_ip in pairs:
        cursor.execute("""
            INSERT INTO vpls_tunnels (ip_address, hub_ip, branch_ip, status)
            VALUES (?, ?, ?, 'Free')
        """, (ip_address, hub_ip, branch_ip))
        inserted += 1

    conn.commit()

    # Verify
    cursor.execute("SELECT COUNT(*) FROM vpls_tunnels WHERE status = 'Free'")
    free_count = cursor.fetchone()[0]

    print(f"✅ Inserted {inserted} /31 pairs")
    print(f"✅ Free tunnel IPs: {free_count}")

    # Sample data
    print(f"\n🔍 Sample tunnel IPs:")
    cursor.execute("SELECT * FROM vpls_tunnels LIMIT 5")
    for row in cursor.fetchall():
        print(f"  ID={row[0]}: {row[1]} (Hub: {row[2]}, Branch: {row[3]}) - {row[10]}")

    conn.close()
    return inserted

def generate_excel(pairs):
    """Generate Excel file with tunnel IP data"""
    try:
        import pandas as pd
        data = []
        for ip_address, hub_ip, branch_ip in pairs:
            data.append({
                'IP Address': ip_address,
                'HUB IP': hub_ip,
                'Branch IP': branch_ip,
                'Tunnel Name': '',
                'Description': '',
                'Province': '',
                'Branch Name': '',
                'WAN IP': '',
                'Tunnel Dest': '',
                'Status': 'Free',
                'User': '',
                'Date': ''
            })

        df = pd.DataFrame(data)
        df.to_excel(EXCEL_PATH, index=False, sheet_name='VPLS_MPLS_Tunnels')
        print(f"\n📊 Excel file generated: {EXCEL_PATH}")
        print(f"   Total rows: {len(df)}")
    except ImportError:
        print("⚠️  pandas not installed, skipping Excel generation")
    except Exception as e:
        print(f"❌ Excel generation error: {e}")


if __name__ == '__main__':
    print("=" * 70)
    print("GENERATING VPLS/MPLS TUNNEL IP /31 PAIRS")
    print("=" * 70)
    print(f"\nIP Range: 100.100.100.0 - 100.100.103.255")

    pairs = generate_pairs()
    print(f"Generated {len(pairs)} /31 pairs")

    count = populate_database(pairs)
    generate_excel(pairs)

    print(f"\n{'=' * 70}")
    print(f"✅ DONE! {count} VPLS/MPLS tunnel IP pairs ready for use")
    print("=" * 70)
