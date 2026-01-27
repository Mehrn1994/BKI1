"""
Excel to SQLite Database Update Script
بروزرسانی دیتابیس از فایل‌های اکسل

Usage:
    python update_database.py --lan-ips ipplan.xlsx
    python update_database.py --apn-ips APN-INT-HUB.xlsx
    python update_database.py --apn-mali ISR-APN-RO-IP-PLAN-2.xlsx
    python update_database.py --tunnels Guilanet-Information.xlsx
    python update_database.py --all   (update all from default files)
"""

import sqlite3
import pandas as pd
from pathlib import Path
import argparse
import sys
from datetime import datetime

# Database path
DATA_DIR = Path(__file__).parent / 'data'
DB_PATH = DATA_DIR / 'network_ipam.db'

# Default Excel files (relative to data folder)
DEFAULT_FILES = {
    'lan_ips': 'ipplan.xlsx',
    'apn_ips': 'APN-INT-HUB.xlsx',
    'apn_mali': 'ISR-APN-RO-IP-PLAN-2.xlsx',
    'intranet_tunnels': 'Guilanet-Information.xlsx',
}


def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn


def backup_database():
    """Create backup before update"""
    backup_path = DATA_DIR / f'network_ipam_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
    try:
        import shutil
        shutil.copy(DB_PATH, backup_path)
        print(f"✅ Backup created: {backup_path}")
        return True
    except Exception as e:
        print(f"⚠️ Warning: Could not create backup: {e}")
        return False


def update_lan_ips(excel_file):
    """
    Update lan_ips table from Excel file
    Expected columns: province, octet1, octet2, octet3, branch_name (optional)
    """
    print(f"\n{'='*60}")
    print(f"📊 Updating LAN IPs from: {excel_file}")
    print('='*60)

    try:
        # Read Excel file
        df = pd.read_excel(excel_file)
        print(f"✓ Read {len(df)} rows from Excel")

        # Show columns found
        print(f"  Columns found: {list(df.columns)}")

        conn = get_db()
        cursor = conn.cursor()

        # Create table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS lan_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                province TEXT,
                octet1 INTEGER DEFAULT 10,
                octet2 INTEGER,
                octet3 INTEGER,
                branch_name TEXT,
                username TEXT,
                reservation_date TEXT,
                UNIQUE(octet2, octet3)
            )
        """)

        updated = 0
        inserted = 0
        errors = 0

        for idx, row in df.iterrows():
            try:
                # Map columns (adjust based on your Excel structure)
                province = str(row.get('province', row.get('Province', row.get('استان', '')))).strip()
                
                # Handle different column names for octets
                octet1 = int(row.get('octet1', row.get('Octet1', 10)))
                octet2 = int(row.get('octet2', row.get('Octet2', row.get('X', 0))))
                octet3 = int(row.get('octet3', row.get('Octet3', row.get('Y', 0))))
                branch_name = str(row.get('branch_name', row.get('Branch', row.get('شعبه', '')))).strip()

                if octet2 == 0 or octet3 == 0:
                    continue

                if branch_name.lower() in ['nan', 'none', '']:
                    branch_name = None

                # Try to update first
                cursor.execute("""
                    UPDATE lan_ips 
                    SET province = ?
                    WHERE octet2 = ? AND octet3 = ?
                """, (province, octet2, octet3))

                if cursor.rowcount == 0:
                    # Insert new
                    cursor.execute("""
                        INSERT INTO lan_ips (province, octet1, octet2, octet3, branch_name)
                        VALUES (?, ?, ?, ?, ?)
                    """, (province, octet1, octet2, octet3, branch_name))
                    inserted += 1
                else:
                    updated += 1

            except Exception as e:
                errors += 1
                if errors <= 5:
                    print(f"  ⚠️ Row {idx} error: {e}")

        conn.commit()
        conn.close()

        print(f"\n✅ LAN IPs Update Complete:")
        print(f"   - Updated: {updated}")
        print(f"   - Inserted: {inserted}")
        print(f"   - Errors: {errors}")

    except Exception as e:
        print(f"❌ Error updating LAN IPs: {e}")
        import traceback
        traceback.print_exc()


def update_apn_ips(excel_file):
    """
    Update apn_ips table from Excel file (غیرمالی - 10.250.66.x)
    """
    print(f"\n{'='*60}")
    print(f"📊 Updating APN IPs (غیرمالی) from: {excel_file}")
    print('='*60)

    try:
        df = pd.read_excel(excel_file)
        print(f"✓ Read {len(df)} rows from Excel")
        print(f"  Columns found: {list(df.columns)}")

        conn = get_db()
        cursor = conn.cursor()

        # Create table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS apn_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                "IP WAN APN" TEXT UNIQUE,
                "Branche Name" TEXT,
                Username TEXT,
                "Reservation Date" TEXT
            )
        """)

        updated = 0
        inserted = 0

        for idx, row in df.iterrows():
            try:
                # Adjust column names based on your Excel
                ip = str(row.get('IP WAN APN', row.get('IP', row.get('ip', '')))).strip()
                branch = str(row.get('Branche Name', row.get('Branch', row.get('شعبه', '')))).strip()

                if not ip or ip.lower() == 'nan':
                    continue

                if branch.lower() in ['nan', 'none']:
                    branch = None

                cursor.execute("""
                    INSERT OR REPLACE INTO apn_ips ("IP WAN APN", "Branche Name")
                    VALUES (?, ?)
                """, (ip, branch))

                if cursor.rowcount > 0:
                    inserted += 1

            except Exception as e:
                print(f"  ⚠️ Row {idx} error: {e}")

        conn.commit()
        conn.close()

        print(f"\n✅ APN IPs Update Complete: {inserted} records")

    except Exception as e:
        print(f"❌ Error updating APN IPs: {e}")
        import traceback
        traceback.print_exc()


def update_apn_mali(excel_file):
    """
    Update apn_mali table from Excel file (مالی - 10.250.45-51.x)
    """
    print(f"\n{'='*60}")
    print(f"📊 Updating APN مالی from: {excel_file}")
    print('='*60)

    try:
        df = pd.read_excel(excel_file)
        print(f"✓ Read {len(df)} rows from Excel")
        print(f"  Columns found: {list(df.columns)}")

        conn = get_db()
        cursor = conn.cursor()

        # Create table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS apn_mali (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                "گیلانتIP" TEXT UNIQUE,
                "نام محل استقرار" TEXT,
                Username TEXT,
                "Reservation Date" TEXT,
                "Tunnel IP Branch" TEXT,
                "Tunnel IP HUB" TEXT,
                "Tunnel Number" TEXT
            )
        """)

        inserted = 0

        for idx, row in df.iterrows():
            try:
                # Adjust column names based on your Excel
                ip = str(row.get('گیلانتIP', row.get('IP', row.get('ip', '')))).strip()
                location = str(row.get('نام محل استقرار', row.get('Location', row.get('محل', '')))).strip()

                if not ip or ip.lower() == 'nan':
                    continue

                if location.lower() in ['nan', 'none']:
                    location = None

                cursor.execute("""
                    INSERT OR REPLACE INTO apn_mali ("گیلانتIP", "نام محل استقرار")
                    VALUES (?, ?)
                """, (ip, location))

                inserted += 1

            except Exception as e:
                print(f"  ⚠️ Row {idx} error: {e}")

        conn.commit()
        conn.close()

        print(f"\n✅ APN مالی Update Complete: {inserted} records")

    except Exception as e:
        print(f"❌ Error updating APN مالی: {e}")
        import traceback
        traceback.print_exc()


def update_intranet_tunnels(excel_file):
    """
    Update intranet_tunnels table from Excel file
    """
    print(f"\n{'='*60}")
    print(f"📊 Updating Intranet Tunnels from: {excel_file}")
    print('='*60)

    try:
        df = pd.read_excel(excel_file)
        print(f"✓ Read {len(df)} rows from Excel")
        print(f"  Columns found: {list(df.columns)}")

        conn = get_db()
        cursor = conn.cursor()

        # Create table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS intranet_tunnels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                "IP Address" TEXT UNIQUE,
                Status TEXT DEFAULT 'Free',
                "Tunnel Name" TEXT,
                "IP LAN" TEXT,
                "IP Intranet" TEXT,
                Description TEXT,
                Province TEXT,
                "Reserved At" TEXT,
                "Reserved By" TEXT
            )
        """)

        inserted = 0

        for idx, row in df.iterrows():
            try:
                ip = str(row.get('IP Address', row.get('IP', row.get('ip', '')))).strip()
                status = str(row.get('Status', 'Free')).strip()

                if not ip or ip.lower() == 'nan':
                    continue

                if status.lower() in ['nan', 'none', '']:
                    status = 'Free'

                cursor.execute("""
                    INSERT OR IGNORE INTO intranet_tunnels ("IP Address", Status)
                    VALUES (?, ?)
                """, (ip, status))

                inserted += 1

            except Exception as e:
                print(f"  ⚠️ Row {idx} error: {e}")

        conn.commit()
        conn.close()

        print(f"\n✅ Intranet Tunnels Update Complete: {inserted} records")

    except Exception as e:
        print(f"❌ Error updating Intranet Tunnels: {e}")
        import traceback
        traceback.print_exc()


def show_database_stats():
    """Show current database statistics"""
    print(f"\n{'='*60}")
    print("📊 Current Database Statistics")
    print('='*60)

    try:
        conn = get_db()
        cursor = conn.cursor()

        tables = ['lan_ips', 'apn_ips', 'apn_mali', 'intranet_tunnels', 'reserved_ips', 'tunnel_ips']

        for table in tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                print(f"  {table}: {count} records")
            except:
                print(f"  {table}: (table not found)")

        conn.close()

    except Exception as e:
        print(f"❌ Error getting stats: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Update SQLite database from Excel files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python update_database.py --lan-ips data/ipplan.xlsx
  python update_database.py --apn-ips data/APN-INT-HUB.xlsx
  python update_database.py --apn-mali data/ISR-APN-RO-IP-PLAN-2.xlsx
  python update_database.py --tunnels data/Guilanet-Information.xlsx
  python update_database.py --stats
  python update_database.py --all
        """
    )

    parser.add_argument('--lan-ips', metavar='FILE', help='Update lan_ips table from Excel file')
    parser.add_argument('--apn-ips', metavar='FILE', help='Update apn_ips table from Excel file')
    parser.add_argument('--apn-mali', metavar='FILE', help='Update apn_mali table from Excel file')
    parser.add_argument('--tunnels', metavar='FILE', help='Update intranet_tunnels table from Excel file')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    parser.add_argument('--all', action='store_true', help='Update all tables from default files in data folder')
    parser.add_argument('--no-backup', action='store_true', help='Skip backup before update')

    args = parser.parse_args()

    # Check if database exists
    if not DB_PATH.exists():
        print(f"❌ Database not found: {DB_PATH}")
        print("   Please ensure the database file exists in the data folder.")
        sys.exit(1)

    print(f"\n📂 Database: {DB_PATH}")

    # Show stats if requested
    if args.stats:
        show_database_stats()
        sys.exit(0)

    # Check if any update option is specified
    if not any([args.lan_ips, args.apn_ips, args.apn_mali, args.tunnels, args.all]):
        parser.print_help()
        print("\n⚠️ Please specify at least one update option.")
        sys.exit(1)

    # Create backup unless skipped
    if not args.no_backup:
        backup_database()

    # Update tables
    if args.all:
        # Update all from default files
        for table, default_file in DEFAULT_FILES.items():
            file_path = DATA_DIR / default_file
            if file_path.exists():
                if table == 'lan_ips':
                    update_lan_ips(file_path)
                elif table == 'apn_ips':
                    update_apn_ips(file_path)
                elif table == 'apn_mali':
                    update_apn_mali(file_path)
                elif table == 'intranet_tunnels':
                    update_intranet_tunnels(file_path)
            else:
                print(f"⚠️ File not found: {file_path}")
    else:
        if args.lan_ips:
            update_lan_ips(args.lan_ips)
        if args.apn_ips:
            update_apn_ips(args.apn_ips)
        if args.apn_mali:
            update_apn_mali(args.apn_mali)
        if args.tunnels:
            update_intranet_tunnels(args.tunnels)

    # Show final stats
    show_database_stats()

    print("\n✅ Database update complete!")


if __name__ == '__main__':
    main()
