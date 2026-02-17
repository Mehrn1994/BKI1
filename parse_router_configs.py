"""
Parse all Router config files and extract tunnel information.
Build Excel database with used/free tunnel IPs for VPLS/MPLS.

For each management router, extracts:
- Tunnel name, description, IP address, tunnel source, tunnel destination
- Identifies which 100.100.100.x/31 IPs are used
- Creates per-province sheets in Excel
- Updates vpls_tunnels DB table marking used IPs
"""

import re
import os
import sqlite3
from datetime import datetime

ROUTER_DIR = os.path.join(os.path.dirname(__file__), 'Router')
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'network_ipam.db')
EXCEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'VPLS_MPLS_Tunnel_IPs.xlsx')

# Province abbreviation mapping from filenames
PROVINCE_MAP = {
    'ALZ': 'Alborz', 'ARD': 'Ardabil', 'AZGH': 'West Azerbaijan',
    'AZSH': 'East Azerbaijan', 'BSH': 'Bushehr', 'CHB': 'Chaharmahal',
    'ESF': 'Isfahan', 'FRS': 'Fars', 'GIL': 'Gilan', 'GLS': 'Golestan',
    'HMD': 'Hamadan', 'HMZ': 'Hormozgan', 'ILM': 'Ilam',
    'KHR': 'Razavi Khorasan', 'KHRJ': 'South Khorasan',
    'KHZ': 'Khuzestan', 'KNB': 'Kohgiluyeh', 'KRD': 'Kurdistan',
    'KRM': 'Kerman', 'KRMJ': 'Kermanshah', 'KRSH': 'Kermanshah',
    'LOR': 'Lorestan', 'MAZ': 'Mazandaran', 'MRZ': 'Markazi',
    'QOM': 'Qom', 'QZV': 'Qazvin', 'SMN': 'Semnan',
    'SNB': 'Sistan', 'YZD': 'Yazd', 'ZNJ': 'Zanjan',
    'M1': 'Tehran-M1', 'M2': 'Tehran-M2', 'OSTehran': 'Tehran-OS',
    'Tehran': 'Tehran', 'KhShomali': 'North Khorasan',
}


def extract_province(filename):
    """Extract province abbreviation from filename."""
    # e.g. '3825-ALZ-7' -> 'ALZ', 'ASR1002X-ESF-Feb-15...' -> 'ESF'
    parts = filename.replace('.', '-').split('-')
    for p in parts:
        if p in PROVINCE_MAP:
            return p, PROVINCE_MAP[p]
    # Try multi-part like 'OSTehran', 'KhShomali'
    for key in PROVINCE_MAP:
        if key in filename:
            return key, PROVINCE_MAP[key]
    return filename, filename


def parse_router_config(filepath):
    """Parse a single router config file and extract tunnel interfaces."""
    tunnels = []
    with open(filepath, 'r', errors='ignore') as f:
        lines = f.readlines()

    current_tunnel = None

    for line in lines:
        line = line.rstrip()

        if line.startswith('interface Tunnel'):
            # Save previous tunnel
            if current_tunnel and current_tunnel.get('ip_address'):
                tunnels.append(current_tunnel)

            tunnel_name = line.replace('interface ', '').strip()
            current_tunnel = {
                'tunnel_name': tunnel_name,
                'description': '',
                'ip_address': '',
                'ip_mask': '',
                'tunnel_source': '',
                'tunnel_destination': '',
            }

        elif current_tunnel is not None:
            stripped = line.strip()

            if stripped.startswith('description '):
                current_tunnel['description'] = stripped.replace('description ', '').strip().strip('"')

            elif stripped.startswith('ip address '):
                parts = stripped.split()
                if len(parts) >= 3:
                    current_tunnel['ip_address'] = parts[2]
                    current_tunnel['ip_mask'] = parts[3] if len(parts) > 3 else ''

            elif stripped.startswith('tunnel source '):
                current_tunnel['tunnel_source'] = stripped.replace('tunnel source ', '').strip()

            elif stripped.startswith('tunnel destination '):
                current_tunnel['tunnel_destination'] = stripped.replace('tunnel destination ', '').strip()

            elif line.startswith('interface ') or line.startswith('!'):
                if current_tunnel.get('ip_address'):
                    tunnels.append(current_tunnel)
                if line.startswith('interface ') and not line.startswith('interface Tunnel'):
                    current_tunnel = None
                elif line.startswith('!'):
                    current_tunnel = None

    # Don't forget the last tunnel
    if current_tunnel and current_tunnel.get('ip_address'):
        tunnels.append(current_tunnel)

    return tunnels


def main():
    print("=" * 80)
    print("PARSING ROUTER CONFIGS - EXTRACTING TUNNEL IPs")
    print("=" * 80)

    all_tunnels = []  # (province_abbr, province_name, router_file, tunnel_data)
    vpls_used_ips = {}  # ip -> tunnel_info (only 100.100.100.x range)

    config_files = sorted(os.listdir(ROUTER_DIR))
    print(f"\nFound {len(config_files)} router config files")

    for filename in config_files:
        filepath = os.path.join(ROUTER_DIR, filename)
        if os.path.isdir(filepath):
            # Check for files inside directories
            for sub in os.listdir(filepath):
                subpath = os.path.join(filepath, sub)
                if os.path.isfile(subpath):
                    filepath = subpath
                    break
            else:
                continue

        prov_abbr, prov_name = extract_province(filename)
        tunnels = parse_router_config(filepath)

        print(f"\n  {filename} ({prov_name}): {len(tunnels)} tunnels")

        for t in tunnels:
            all_tunnels.append({
                'province_abbr': prov_abbr,
                'province_name': prov_name,
                'router_file': filename,
                **t
            })

            # Track 100.100.100.x IPs (VPLS/MPLS range)
            ip = t['ip_address']
            if ip.startswith('100.100.10'):
                # Find the /31 pair base (even IP)
                parts = ip.split('.')
                last = int(parts[3])
                base = last - (last % 2)
                pair_base = f"{parts[0]}.{parts[1]}.{parts[2]}.{base}"
                pair_ip = f"{pair_base}/31"

                vpls_used_ips[pair_ip] = {
                    'tunnel_name': t['tunnel_name'],
                    'description': t['description'],
                    'ip_address': ip,
                    'tunnel_source': t['tunnel_source'],
                    'tunnel_destination': t['tunnel_destination'],
                    'province': prov_name,
                    'province_abbr': prov_abbr,
                    'router': filename,
                }
                print(f"    VPLS/MPLS: {t['tunnel_name']} -> {ip} ({t['description']})")

    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"Total tunnels found: {len(all_tunnels)}")
    print(f"VPLS/MPLS (100.100.x.x) used IPs: {len(vpls_used_ips)}")

    # ==================== UPDATE DATABASE ====================
    print(f"\n{'=' * 60}")
    print("UPDATING DATABASE")
    print(f"{'=' * 60}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Ensure table exists
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

    # Mark used IPs in the database
    updated = 0
    for pair_ip, info in vpls_used_ips.items():
        cursor.execute("""
            UPDATE vpls_tunnels
            SET status = 'Used',
                tunnel_name = ?,
                description = ?,
                province = ?,
                wan_ip = ?,
                tunnel_dest = ?,
                username = 'imported',
                reservation_date = ?
            WHERE ip_address = ? AND LOWER(status) = 'free'
        """, (
            info['tunnel_name'],
            info['description'],
            info['province'],
            info['tunnel_source'],
            info['tunnel_destination'],
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            pair_ip
        ))
        if cursor.rowcount > 0:
            updated += 1

    conn.commit()

    # Show stats
    cursor.execute("SELECT status, COUNT(*) FROM vpls_tunnels GROUP BY status")
    print(f"\nDatabase status after import:")
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]}")

    conn.close()
    print(f"Updated {updated} tunnel IP pairs to 'Used'")

    # ==================== GENERATE EXCEL ====================
    print(f"\n{'=' * 60}")
    print("GENERATING EXCEL FILE")
    print(f"{'=' * 60}")

    try:
        import pandas as pd

        # Sheet 1: All tunnels summary
        df_all = pd.DataFrame(all_tunnels)
        df_all = df_all[['province_abbr', 'province_name', 'router_file',
                         'tunnel_name', 'description', 'ip_address', 'ip_mask',
                         'tunnel_source', 'tunnel_destination']]

        # Sheet 2: VPLS/MPLS used IPs
        vpls_rows = []
        for pair_ip, info in sorted(vpls_used_ips.items()):
            vpls_rows.append({
                'IP Pair (/31)': pair_ip,
                'Tunnel Name': info['tunnel_name'],
                'Description': info['description'],
                'Tunnel IP': info['ip_address'],
                'Tunnel Source': info['tunnel_source'],
                'Tunnel Destination': info['tunnel_destination'],
                'Province': info['province'],
                'Province Code': info['province_abbr'],
                'Router': info['router'],
                'Status': 'Used',
                'User': 'imported',
                'Date': datetime.now().strftime('%Y-%m-%d')
            })
        df_vpls_used = pd.DataFrame(vpls_rows)

        # Sheet 3: Free VPLS IPs
        conn2 = sqlite3.connect(DB_PATH)
        df_free = pd.read_sql_query(
            "SELECT ip_address, hub_ip, branch_ip, status FROM vpls_tunnels WHERE LOWER(status) = 'free' ORDER BY id",
            conn2
        )
        conn2.close()

        # Per-province sheets
        province_data = {}
        for t in all_tunnels:
            prov = t['province_abbr']
            if prov not in province_data:
                province_data[prov] = []
            province_data[prov].append(t)

        with pd.ExcelWriter(EXCEL_PATH, engine='openpyxl') as writer:
            df_all.to_excel(writer, sheet_name='All_Tunnels', index=False)
            if len(vpls_rows) > 0:
                df_vpls_used.to_excel(writer, sheet_name='VPLS_Used', index=False)
            df_free.to_excel(writer, sheet_name='VPLS_Free', index=False)

            # Per-province sheets
            for prov_abbr in sorted(province_data.keys()):
                sheet_name = prov_abbr[:31]  # Excel sheet name max 31 chars
                df_prov = pd.DataFrame(province_data[prov_abbr])
                df_prov.to_excel(writer, sheet_name=sheet_name, index=False)

        print(f"Excel file generated: {EXCEL_PATH}")
        print(f"  Sheets: All_Tunnels, VPLS_Used, VPLS_Free + {len(province_data)} province sheets")

    except Exception as e:
        print(f"Excel generation error: {e}")
        import traceback
        traceback.print_exc()

    print(f"\n{'=' * 80}")
    print("DONE!")
    print(f"{'=' * 80}")


if __name__ == '__main__':
    main()
