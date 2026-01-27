
"""
Database Diagnostic Script - Check reserved_ips table state
Run this to see what's actually in your database
"""
import sqlite3
from pathlib import Path

DB_PATH = Path('data/network_ipam.db')

def check_database():
    print("="*80)
    print("DATABASE DIAGNOSTIC")
    print("="*80)

    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Check all IPs in reserved_ips
    print("\n📋 ALL RECORDS IN reserved_ips table:")
    print("-"*80)
    cursor.execute("""
        SELECT lan_ip, status, point_name_persian, reserved_by, 
               reserved_date, expiry_date
        FROM reserved_ips
        ORDER BY reserved_date DESC
    """)

    rows = cursor.fetchall()
    if rows:
        for row in rows:
            print(f"IP: {row['lan_ip']}")
            print(f"  Status: {row['status']}")
            print(f"  Name: {row['point_name_persian']}")
            print(f"  Reserved by: {row['reserved_by']}")
            print(f"  Reserved: {row['reserved_date']}")
            print(f"  Expires: {row['expiry_date']}")
            print("-"*80)
    else:
        print("✅ Table is empty - no reservations")

    print(f"\n📊 Total records: {len(rows)}")

    # Check specifically for 10.23.13.0
    print("\n🔍 Checking IP 10.23.13.0 specifically:")
    print("-"*80)
    cursor.execute("""
        SELECT * FROM reserved_ips WHERE lan_ip = '10.23.13.0'
    """)
    check_ip = cursor.fetchall()
    if check_ip:
        for row in check_ip:
            print("⚠️ FOUND - This IP exists in database:")
            for key in row.keys():
                print(f"  {key}: {row[key]}")
    else:
        print("✅ IP 10.23.13.0 NOT in database - should be free to reserve")

    # Check lan_ips table
    print("\n📋 Checking lan_ips table for 10.23.13.0:")
    print("-"*80)
    cursor.execute("""
        SELECT branch_name, username, reservation_date, province
        FROM lan_ips 
        WHERE octet2 = 23 AND octet3 = 13
    """)
    lan_check = cursor.fetchone()
    if lan_check:
        print(f"Province: {lan_check['province']}")
        print(f"Branch: {lan_check['branch_name']}")
        print(f"Username: {lan_check['username']}")
        print(f"Reserved: {lan_check['reservation_date']}")
    else:
        print("✅ Not found in lan_ips")

    conn.close()
    print("\n" + "="*80)

if __name__ == '__main__':
    check_database()