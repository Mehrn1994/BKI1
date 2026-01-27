
"""
Cleanup Script - Remove all old EXPIRED records from database
This will allow you to re-reserve those IPs
"""
import sqlite3
from pathlib import Path

DB_PATH = Path('data/network_ipam.db')

def cleanup_expired_records():
    print("="*80)
    print("CLEANING UP OLD EXPIRED RECORDS")
    print("="*80)

    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Find all EXPIRED records
    print("\n🔍 Finding EXPIRED records...")
    cursor.execute("""
        SELECT lan_ip, point_name_persian, reserved_by, status
        FROM reserved_ips
        WHERE status = 'EXPIRED'
    """)

    expired_rows = cursor.fetchall()

    if not expired_rows:
        print("✅ No EXPIRED records found - database is clean!")
        conn.close()
        return

    print(f"\n⚠️ Found {len(expired_rows)} EXPIRED records:")
    print("-"*80)
    for row in expired_rows:
        print(f"  • {row['lan_ip']} - {row['point_name_persian']} (by {row['reserved_by']})")

    # Delete all EXPIRED records
    print("\n🗑️ Deleting EXPIRED records...")
    cursor.execute("""
        DELETE FROM reserved_ips
        WHERE status = 'EXPIRED'
    """)

    deleted_count = cursor.rowcount
    conn.commit()

    print(f"✅ Successfully deleted {deleted_count} EXPIRED records")

    # Also clean up lan_ips for these IPs
    print("\n🧹 Cleaning up lan_ips table...")
    for row in expired_rows:
        lan_ip = row['lan_ip']
        try:
            parts = lan_ip.split(".")
            if len(parts) >= 3:
                octet2 = int(parts[1])
                octet3 = int(parts[2])
                cursor.execute("""
                    UPDATE lan_ips
                    SET branch_name = NULL,
                        username = NULL,
                        reservation_date = NULL
                    WHERE octet2 = ? AND octet3 = ?
                """, (octet2, octet3))
                print(f"  ✓ Freed lan_ips for {lan_ip}")
        except Exception as e:
            print(f"  ⚠️ Could not clean {lan_ip}: {e}")

    conn.commit()
    conn.close()

    print("\n" + "="*80)
    print("✅ CLEANUP COMPLETE!")
    print("="*80)
    print("\nYou can now reserve these IPs again:")
    for row in expired_rows:
        print(f"  • {row['lan_ip']}")
    print("\n" + "="*80)

if __name__ == '__main__':
    cleanup_expired_records()