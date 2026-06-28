import sqlite3
conn = sqlite3.connect("ghosttrace.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
rows = cursor.fetchall()

for row in rows:
    print(row)

print("\nAlert counts by type:")
cursor.execute("SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type")
for row in cursor.fetchall():
    print(row)

print("\nRepeat offenders (3+ alerts):")
cursor.execute("SELECT src_ip, COUNT(*) as alert_count FROM alerts GROUP BY src_ip HAVING alert_count >= 3")
for row in cursor.fetchall():
    print(row)