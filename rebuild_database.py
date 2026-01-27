"""
Database Rebuild Script - CORRECTED
Uses Branch-Lan-IP.xlsx as main branch source
Maps province from Intranet.xlsx by octet2
"""

import sqlite3
import pandas as pd
import os
import shutil
from datetime import datetime

# Paths
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'network_ipam.db')
BACKUP_DIR = os.path.join(os.path.dirname(__file__), 'data', 'backups')
EXCEL_DIR = os.path.join(os.path.dirname(__file__), 'excel_files')

def backup_existing():
    if os.path.exists(DB_PATH):
        os.makedirs(BACKUP_DIR, exist_ok=True)
        backup_name = f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        shutil.copy2(DB_PATH, os.path.join(BACKUP_DIR, backup_name))
        print(f"Backup: {backup_name}")

def create_tables(conn):
    cursor = conn.cursor()
    
    tables = ['lan_ips', 'intranet_tunnels', 'apn_ips', 'apn_mali', 'tunnel_mali', 'tunnel200_ips', 'user_passwords', 'reserved_ips']
    for table in tables:
        cursor.execute(f"DROP TABLE IF EXISTS {table}")
    
    cursor.execute("""
        CREATE TABLE lan_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            row_number INTEGER,
            branch_name TEXT,
            province TEXT,
            octet2 INTEGER,
            octet3 INTEGER,
            wan_ip TEXT,
            status TEXT DEFAULT 'Active',
            username TEXT,
            reservation_date TEXT,
            notes TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE intranet_tunnels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tunnel_name TEXT,
            ip_address TEXT,
            ip_lan TEXT,
            ip_intranet TEXT,
            description TEXT,
            province TEXT,
            status TEXT,
            reserved_by TEXT,
            reserved_at TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE apn_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            row_number INTEGER,
            province TEXT,
            branch_name TEXT,
            type TEXT,
            lan_ip TEXT,
            ip_wan_apn TEXT,
            username TEXT,
            reservation_date TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE apn_mali (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            row_number INTEGER,
            province TEXT,
            branch_name TEXT,
            type TEXT,
            lan_ip TEXT,
            ip_wan TEXT,
            username TEXT,
            reservation_date TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE tunnel_mali (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interface_name TEXT,
            description TEXT,
            ip_address TEXT,
            hub_ip TEXT,
            branch_ip TEXT,
            destination_ip TEXT,
            status TEXT DEFAULT 'Free',
            username TEXT,
            branch_name TEXT,
            reservation_date TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE tunnel200_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interface_name TEXT,
            description TEXT,
            ip_address TEXT,
            hub_ip TEXT,
            branch_ip TEXT,
            pair_notation TEXT,
            tunnel_number TEXT,
            status TEXT DEFAULT 'Free',
            username TEXT,
            branch_name TEXT,
            reservation_date TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE user_passwords (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TEXT,
            last_login TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE reserved_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            province TEXT,
            octet2 INTEGER,
            octet3 INTEGER,
            branch_name TEXT,
            username TEXT,
            reservation_date TEXT,
            expiry_date TEXT,
            request_number TEXT,
            point_type TEXT,
            mehregostar_code TEXT
        )
    """)
    
    conn.commit()
    print("Tables created")

def build_province_map(excel_dir):
    """Build province mapping from multiple sources"""
    province_map = {}
    
    # Manual mapping for known octet2 values (Tehran branches)
    manual_map = {
        1: 'تهران',
        2: 'تهران',  # Tehran branches
        4: 'تهران',
    }
    province_map.update(manual_map)
    
    # First from Intranet
    intranet_file = os.path.join(excel_dir, 'Intranet.xlsx')
    if os.path.exists(intranet_file):
        df = pd.read_excel(intranet_file)
        for _, row in df.iterrows():
            ip_lan = str(row.get('IP LAN', ''))
            province = row.get('Province', '')
            if ip_lan and province and pd.notna(province):
                parts = ip_lan.split('.')
                if len(parts) >= 2:
                    try:
                        octet2 = int(parts[1])
                        if octet2 not in province_map:
                            province_map[octet2] = str(province)
                    except:
                        pass
    
    # Then from APN files (Persian names)
    apn_file = os.path.join(excel_dir, 'IP_APN_WAN.xlsx')
    if os.path.exists(apn_file):
        # APN INT
        try:
            df1 = pd.read_excel(apn_file, sheet_name='IP APN 10.250.66.x')
            for _, row in df1.iterrows():
                octet2 = row.iloc[5] if pd.notna(row.iloc[5]) else None
                province = row.get('Province', '')
                if octet2 and province and pd.notna(province):
                    octet2 = int(octet2)
                    if octet2 not in province_map or not province_map[octet2]:
                        province_map[octet2] = str(province).strip()
        except:
            pass
        
        # APN Mali
        try:
            df2 = pd.read_excel(apn_file, sheet_name='IP APN WAN 10.250.x.x')
            for _, row in df2.iterrows():
                octet2 = row.get('Lan IP', None)
                province = row.get('Province', '')
                if octet2 and province and pd.notna(province) and pd.notna(octet2):
                    octet2 = int(octet2)
                    if octet2 not in province_map or not province_map[octet2]:
                        province_map[octet2] = str(province).strip()
        except:
            pass
    
    # Convert English to Persian
    province_persian = {
        'Tehran': 'تهران', 'AZSH': 'آذربایجان شرقی', 'AZGH': 'آذربایجان غربی',
        'KRD': 'کردستان', 'ZNJ': 'زنجان', 'QZV': 'قزوین', 'Qazvin': 'قزوین',
        'KHRJ': 'خراسان جنوبی', 'KHSH': 'خراسان شمالی', 'KHZ': 'خوزستان',
        'Khuzestan': 'خوزستان', 'Fars': 'فارس', 'Kerman': 'کرمان',
        'Razavi Khorasan': 'خراسان رضوی', 'Lorestan': 'لرستان', 'Hamadan': 'همدان',
        'Hormozgan': 'هرمزگان', 'Bushehr': 'بوشهر', 'Yazd': 'یزد',
        'Isfahan': 'اصفهان', 'Gilan': 'گیلان', 'Mazandaran': 'مازندران',
        'Golestan': 'گلستان', 'Semnan': 'سمنان', 'Markazi': 'مرکزی',
        'Qom': 'قم', 'Alborz': 'البرز', 'Ardabil': 'اردبیل', 'Ilam': 'ایلام',
        'تهران بزرگ': 'تهران',  # Normalize Tehran names
    }
    
    for octet2, province in list(province_map.items()):
        if province in province_persian:
            province_map[octet2] = province_persian[province]
    
    print(f"Province map: {len(province_map)} mappings")
    return province_map

def import_branch_lan_ips(conn, excel_dir, province_map):
    """Import ALL sheets from Branch-Lan-IP.xlsx - each sheet is a province"""
    filepath = os.path.join(excel_dir, 'Branch-Lan-IP.xlsx')
    print(f"\nImporting from Branch-Lan-IP.xlsx (all sheets)...")
    
    # Province code to Persian name mapping
    province_codes = {
        'TEHB': 'تهران بزرگ', 'TEH': 'تهران', 'KRJ': 'البرز', 'AZSH': 'آذربایجان شرقی',
        'KRMSH': 'کرمانشاه', 'KHZ': 'خوزستان', 'FRS': 'فارس', 'KRM-JKRM': 'کرمان',
        'KHR': 'خراسان رضوی', 'ESF': 'اصفهان', 'SNB': 'سیستان و بلوچستان',
        'KRD': 'کردستان', 'SMN': 'سمنان', 'LOR': 'لرستان', 'HMD': 'همدان',
        'CHB': 'چهارمحال و بختیاری', 'HMZ': 'هرمزگان', 'BSH': 'بوشهر',
        'ZNJ': 'زنجان', 'YZD': 'یزد', 'GIL': 'گیلان', 'GLS': 'گلستان',
        'ARD': 'اردبیل', 'MRZ': 'مرکزی', 'ILM': 'ایلام', 'KHB': 'کهگیلویه و بویراحمد',
        'QZV': 'قزوین', 'QOM': 'قم', 'KHRJ': 'خراسان جنوبی', 'KHSH': 'خراسان شمالی',
        'MAZ': 'مازندران', 'AZGH': 'آذربایجان غربی'
    }
    
    xl = pd.ExcelFile(filepath)
    cursor = conn.cursor()
    
    total_active = 0
    total_free = 0
    
    for sheet_name in xl.sheet_names:
        df = pd.read_excel(xl, sheet_name=sheet_name)
        province = province_codes.get(sheet_name, sheet_name)
        
        # Find column indices dynamically
        cols = list(df.columns)
        
        # Find 'Branch name' column
        branch_col = None
        for i, col in enumerate(cols):
            if 'Branch' in str(col) or 'branch' in str(col):
                branch_col = i
                break
        
        if branch_col is None:
            print(f"  {sheet_name}: Could not find Branch column, skipping")
            continue
        
        # LAN IP octets are typically at branch_col+1, branch_col+2, branch_col+3
        lan_col1 = branch_col + 1  # First octet (10)
        lan_col2 = branch_col + 2  # Second octet
        lan_col3 = branch_col + 3  # Third octet
        
        # WAN IP is usually at lan_col1+4 onwards
        wan_col1 = lan_col1 + 4  # First octet (10)
        wan_col2 = lan_col1 + 5  # Second octet
        wan_col3 = lan_col1 + 6  # Third octet
        wan_col4 = lan_col1 + 7  # Fourth octet
        
        active_count = 0
        free_count = 0
        
        for _, row in df.iterrows():
            try:
                branch_name = str(row.iloc[branch_col]).strip() if pd.notna(row.iloc[branch_col]) else ''
                
                # Get LAN IP octets
                octet2 = int(row.iloc[lan_col2]) if lan_col2 < len(row) and pd.notna(row.iloc[lan_col2]) else None
                octet3 = int(row.iloc[lan_col3]) if lan_col3 < len(row) and pd.notna(row.iloc[lan_col3]) else None
                
                # Skip rows without IP data
                if octet2 is None or octet3 is None:
                    continue
                
                # WAN IP
                wan_ip = ''
                if wan_col4 < len(row):
                    try:
                        w1 = row.iloc[wan_col1] if pd.notna(row.iloc[wan_col1]) else None
                        w2 = row.iloc[wan_col2] if pd.notna(row.iloc[wan_col2]) else None
                        w3 = row.iloc[wan_col3] if pd.notna(row.iloc[wan_col3]) else None
                        w4 = row.iloc[wan_col4] if pd.notna(row.iloc[wan_col4]) else None
                        if w1 and w2 and w3 and w4:
                            wan_ip = f"{int(w1)}.{int(w2)}.{int(w3)}.{int(w4)}"
                    except:
                        pass
                
                # Status: Active if has branch name, Free if empty
                status = 'Active' if branch_name else 'Free'
                
                cursor.execute("""
                    INSERT INTO lan_ips (row_number, branch_name, province, octet2, octet3, wan_ip, status, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (None, branch_name, province, octet2, octet3, wan_ip, status, ''))
                
                if branch_name:
                    active_count += 1
                else:
                    free_count += 1
            except Exception as e:
                pass
        
        print(f"  {sheet_name} ({province}): {active_count} active + {free_count} free")
        total_active += active_count
        total_free += free_count
    
    conn.commit()
    print(f"  TOTAL: {total_active} active branches + {total_free} free IPs = {total_active + total_free}")

def import_intranet_tunnels(conn, excel_dir):
    filepath = os.path.join(excel_dir, 'Intranet.xlsx')
    print(f"\nImporting Intranet Tunnels...")
    
    df = pd.read_excel(filepath)
    cursor = conn.cursor()
    
    count = 0
    for _, row in df.iterrows():
        try:
            cursor.execute("""
                INSERT INTO intranet_tunnels (tunnel_name, ip_address, ip_lan, ip_intranet, description, province, status, reserved_by, reserved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(row.get('Tunnel Name', '')).strip() if pd.notna(row.get('Tunnel Name')) else '',
                str(row.get('IP Address', '')).strip() if pd.notna(row.get('IP Address')) else '',
                str(row.get('IP LAN', '')).strip() if pd.notna(row.get('IP LAN')) else '',
                str(row.get('IP Intranet', '')).strip() if pd.notna(row.get('IP Intranet')) else '',
                str(row.get('Description', '')).strip() if pd.notna(row.get('Description')) else '',
                str(row.get('Province', '')).strip() if pd.notna(row.get('Province')) else '',
                str(row.get('Status', '')).strip() if pd.notna(row.get('Status')) else '',
                str(row.get('Reserved By', '')).strip() if pd.notna(row.get('Reserved By')) else '',
                str(row.get('Reserved At', '')).strip() if pd.notna(row.get('Reserved At')) else ''
            ))
            count += 1
        except:
            pass
    
    conn.commit()
    print(f"  Imported {count} tunnels")

def import_apn_int(conn, excel_dir):
    filepath = os.path.join(excel_dir, 'IP_APN_WAN.xlsx')
    print(f"\nImporting APN INT...")
    
    df = pd.read_excel(filepath, sheet_name='IP APN 10.250.66.x')
    cursor = conn.cursor()
    
    count = 0
    for _, row in df.iterrows():
        try:
            lan_ip = ''
            if pd.notna(row.get('Lan IP')):
                octet2 = row.iloc[5] if pd.notna(row.iloc[5]) else ''
                octet3 = row.iloc[6] if pd.notna(row.iloc[6]) else ''
                if octet2 and octet3:
                    lan_ip = f"10.{int(octet2)}.{int(octet3)}.0/24"
            
            ip_wan = str(row.get('IP WAN APN', '')).strip() if pd.notna(row.get('IP WAN APN')) else ''
            
            if ip_wan and ip_wan.startswith('10.250.66'):
                cursor.execute("""
                    INSERT INTO apn_ips (row_number, province, branch_name, type, lan_ip, ip_wan_apn, username, reservation_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row.get('No'),
                    str(row.get('Province', '')).strip() if pd.notna(row.get('Province')) else '',
                    str(row.get('Branche Name', '')).strip() if pd.notna(row.get('Branche Name')) else '',
                    str(row.get('Type', '')).strip() if pd.notna(row.get('Type')) else '',
                    lan_ip, ip_wan,
                    str(row.get('Username', '')).strip() if pd.notna(row.get('Username')) else '',
                    str(row.get('Reservation Date', '')).strip() if pd.notna(row.get('Reservation Date')) else ''
                ))
                count += 1
        except:
            pass
    
    conn.commit()
    print(f"  Imported {count} APN INT IPs")

def import_apn_mali(conn, excel_dir):
    filepath = os.path.join(excel_dir, 'IP_APN_WAN.xlsx')
    print(f"\nImporting APN Mali...")
    
    df = pd.read_excel(filepath, sheet_name='IP APN WAN 10.250.x.x')
    cursor = conn.cursor()
    
    count = 0
    for _, row in df.iterrows():
        try:
            lan_ip = ''
            if pd.notna(row.get('Lan IP')):
                octet2 = row.get('Lan IP')
                octet3 = row.iloc[6] if pd.notna(row.iloc[6]) else ''
                if octet2 and octet3:
                    lan_ip = f"10.{int(octet2)}.{int(octet3)}.0/24"
            
            ip_wan = str(row.get('IP WAN', '')).strip() if pd.notna(row.get('IP WAN')) else ''
            
            if ip_wan and ip_wan.startswith('10.250'):
                cursor.execute("""
                    INSERT INTO apn_mali (row_number, province, branch_name, type, lan_ip, ip_wan, username, reservation_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row.get('No'),
                    str(row.get('Province', '')).strip() if pd.notna(row.get('Province')) else '',
                    str(row.get('Branch Name', '')).strip() if pd.notna(row.get('Branch Name')) else '',
                    str(row.get('Type', '')).strip() if pd.notna(row.get('Type')) else '',
                    lan_ip, ip_wan,
                    str(row.get('Username', '')).strip() if pd.notna(row.get('Username')) else '',
                    str(row.get('Reservation Date', '')).strip() if pd.notna(row.get('Reservation Date')) else ''
                ))
                count += 1
        except:
            pass
    
    conn.commit()
    print(f"  Imported {count} APN Mali IPs")

def import_tunnel_mali(conn, excel_dir):
    filepath = os.path.join(excel_dir, 'Tunnel_IP_Pair_APN_Mali.xlsx')
    print(f"\nImporting Tunnel Mali...")
    
    df = pd.read_excel(filepath)
    cursor = conn.cursor()
    
    count = 0
    free_count = 0
    reserved_count = 0
    
    for _, row in df.iterrows():
        try:
            interface = str(row.get('Interface Name', '')).strip() if pd.notna(row.get('Interface Name')) else ''
            ip_addr = str(row.get('IP Address (/31)', '')).strip() if pd.notna(row.get('IP Address (/31)')) else ''
            
            # Skip SUBNET rows and rows without IP
            if 'SUBNET' in interface or not ip_addr:
                continue
            
            # Handle "Free" as interface name - this means it's an available slot
            if interface == 'Free':
                status = 'Free'
                interface = ''  # Clear interface name for free slots
                free_count += 1
            else:
                # Get Status from file - NaN or empty = Free
                file_status = row.get('Status', '')
                if pd.isna(file_status) or str(file_status).strip() == '':
                    status = 'Free'
                    free_count += 1
                else:
                    status = str(file_status).strip()
                    reserved_count += 1
            
            # Calculate /31 pair - HUB and Branch IPs
            # For /31: even IP = HUB, odd IP = Branch
            base_ip = ip_addr.replace('/31', '').strip()
            parts = base_ip.split('.')
            hub_ip = ''
            branch_ip = ''
            
            if len(parts) == 4:
                last_octet = int(parts[3])
                # In /31, the even IP is HUB, odd IP is Branch
                if last_octet % 2 == 0:
                    # Even - this is HUB
                    hub_ip = base_ip
                    branch_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{last_octet + 1}"
                else:
                    # Odd - this is Branch, HUB is previous
                    branch_ip = base_ip
                    hub_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{last_octet - 1}"
            
            # Destination IP from file
            dest_ip = str(row.get('Destination IP', '')).strip() if pd.notna(row.get('Destination IP')) else ''
            
            cursor.execute("""
                INSERT INTO tunnel_mali (interface_name, description, ip_address, hub_ip, branch_ip, destination_ip, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                interface,
                str(row.get('Description', '')).strip() if pd.notna(row.get('Description')) else '',
                ip_addr,
                hub_ip,
                branch_ip,
                dest_ip,
                status
            ))
            count += 1
        except Exception as e:
            pass
    
    conn.commit()
    print(f"  Imported {count} Tunnel Mali pairs ({free_count} Free, {reserved_count} Reserved)")

def import_tunnel200(conn, excel_dir):
    filepath = os.path.join(excel_dir, 'Tunnel200_IPs-APN-INT.xlsx')
    print(f"\nImporting Tunnel200...")
    
    df = pd.read_excel(filepath)
    cursor = conn.cursor()
    
    count = 0
    for _, row in df.iterrows():
        try:
            interface = str(row.get('Interface Name', '')).strip() if pd.notna(row.get('Interface Name')) else ''
            ip_addr = str(row.get('IP Address (/31)', '')).strip() if pd.notna(row.get('IP Address (/31)')) else ''
            
            if 'SUBNET' in interface or not ip_addr:
                continue
            
            base_ip = ip_addr.replace('/31', '')
            parts = base_ip.split('.')
            if len(parts) == 4:
                last_octet = int(parts[3])
                if last_octet % 2 == 0:
                    hub_ip = base_ip
                    branch_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{last_octet + 1}"
                else:
                    branch_ip = base_ip
                    hub_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{last_octet - 1}"
                
                tunnel_num = ''.join(filter(str.isdigit, interface))
                
                cursor.execute("""
                    INSERT INTO tunnel200_ips (interface_name, description, ip_address, hub_ip, branch_ip, pair_notation, tunnel_number, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'Free')
                """, (
                    interface,
                    str(row.get('Description', '')).strip() if pd.notna(row.get('Description')) else '',
                    ip_addr, hub_ip, branch_ip, f"{hub_ip}/31", tunnel_num
                ))
                count += 1
        except:
            pass
    
    conn.commit()
    print(f"  Imported {count} Tunnel200 pairs")

def verify_data(conn):
    print("\n" + "="*60)
    print("Data Verification")
    print("="*60)
    
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM lan_ips")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM lan_ips WHERE province IS NOT NULL AND province != ''")
    with_prov = cursor.fetchone()[0]
    print(f"  lan_ips: {total} total, {with_prov} with province")
    
    cursor.execute("SELECT branch_name, province, octet2, octet3 FROM lan_ips WHERE province != '' LIMIT 3")
    for row in cursor.fetchall():
        print(f"    {row[0]}: {row[1]}, 10.{row[2]}.{row[3]}.0/24")
    
    tables = ['intranet_tunnels', 'apn_ips', 'apn_mali', 'tunnel_mali', 'tunnel200_ips']
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        print(f"  {table}: {cursor.fetchone()[0]} rows")

def main():
    print("="*60)
    print("Database Rebuild Script - CORRECTED")
    print("="*60)
    
    required = ['Branch-Lan-IP.xlsx', 'Intranet.xlsx', 'IP_APN_WAN.xlsx', 'Tunnel_IP_Pair_APN_Mali.xlsx', 'Tunnel200_IPs-APN-INT.xlsx']
    missing = [f for f in required if not os.path.exists(os.path.join(EXCEL_DIR, f))]
    
    if missing:
        print(f"Missing: {missing}")
        print(f"Please place files in: {EXCEL_DIR}")
        return
    
    backup_existing()
    
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    
    create_tables(conn)
    province_map = build_province_map(EXCEL_DIR)
    
    import_branch_lan_ips(conn, EXCEL_DIR, province_map)
    import_intranet_tunnels(conn, EXCEL_DIR)
    import_apn_int(conn, EXCEL_DIR)
    import_apn_mali(conn, EXCEL_DIR)
    import_tunnel_mali(conn, EXCEL_DIR)
    import_tunnel200(conn, EXCEL_DIR)
    
    verify_data(conn)
    
    conn.close()
    print("\nDatabase rebuild complete!")
    print(f"Saved to: {DB_PATH}")

if __name__ == '__main__':
    main()
