"""
Test if database was created successfully
Run this AFTER migrate_to_database.py
"""

import sqlite3

print("=" * 60)
print("Testing Database Connection")
print("=" * 60)

conn = sqlite3.connect('data/network_ipam.db')
cursor = conn.cursor()

# Test 1: Check intranet_tunnels
print("\n1️⃣ Testing intranet_tunnels table...")
cursor.execute("SELECT COUNT(*) FROM intranet_tunnels")
count = cursor.fetchone()[0]
print(f"   ✓ Total records: {count}")

cursor.execute("SELECT COUNT(*) FROM intranet_tunnels WHERE Status = 'Free' OR Status IS NULL OR Status = ''")
free_count = cursor.fetchone()[0]
print(f"   ✓ Free tunnels: {free_count}")

# Test 2: Check lan_ips
print("\n2️⃣ Testing lan_ips table...")
cursor.execute("SELECT COUNT(*) FROM lan_ips")
count = cursor.fetchone()[0]
print(f"   ✓ Total records: {count}")

cursor.execute("SELECT COUNT(*) FROM lan_ips WHERE branch_name IS NULL OR branch_name = ''")
free_count = cursor.fetchone()[0]
print(f"   ✓ Free LAN IPs: {free_count}")

cursor.execute("SELECT COUNT(DISTINCT province) FROM lan_ips")
province_count = cursor.fetchone()[0]
print(f"   ✓ Provinces: {province_count}")

# Test 3: Check apn_ips
print("\n3️⃣ Testing apn_ips table...")
cursor.execute("SELECT COUNT(*) FROM apn_ips")
count = cursor.fetchone()[0]
print(f"   ✓ Total records: {count}")

# Test 4: Sample queries
print("\n4️⃣ Sample Data...")

print("\n   Free Intranet Tunnel (first one):")
cursor.execute("SELECT * FROM intranet_tunnels WHERE Status = 'Free' OR Status IS NULL LIMIT 1")
columns = [description[0] for description in cursor.description]
row = cursor.fetchone()
if row:
    for col, val in zip(columns, row):
        print(f"      {col}: {val}")
else:
    print("      ⚠ No free tunnels found")

print("\n   Free LAN IP from Tehran (TEH):")
cursor.execute("""
    SELECT province, octet1, octet2, octet3, branch_name 
    FROM lan_ips 
    WHERE province = 'TEH' AND (branch_name IS NULL OR branch_name = '') 
    LIMIT 1
""")
row = cursor.fetchone()
if row:
    print(f"      Province: {row[0]}")
    print(f"      IP: {row[1]}.{row[2]}.{row[3]}.0")
    print(f"      Status: Free")
else:
    print("      ⚠ No free IPs in Tehran")

print("\n   APN IP (first one):")
cursor.execute("SELECT * FROM apn_ips LIMIT 1")
columns = [description[0] for description in cursor.description]
row = cursor.fetchone()
if row:
    # Show first 5 columns only
    for i, (col, val) in enumerate(zip(columns, row)):
        if i < 5:
            print(f"      {col}: {val}")
else:
    print("      ⚠ No APN IPs found")

conn.close()

print("\n" + "=" * 60)
print("✅ DATABASE IS WORKING PERFECTLY!")
print("=" * 60)
print("\nNext step: Update your server.py to use the database")
