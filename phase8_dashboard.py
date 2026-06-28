from flask import Flask
import sqlite3

app = Flask(__name__)


@app.route("/")
def home():
    conn = sqlite3.connect("ghosttrace.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            reason TEXT
        )
    ''')
    conn.commit()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
    alerts = cursor.fetchall()
    cursor.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
    blocked = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM blocked_ips")
    total_blocked = cursor.fetchone()[0]
    conn.close()

    html = "<meta http-equiv='refresh' content='5'>"
    html += "<h1>GhostTrace Dashboards</h1>"
    html += f"<p><b>Total Alerts:</b> {total_alerts} &nbsp;&nbsp; <b>Total Blocked:</b> {total_blocked}</p>"

    html += "<h2>Alerts</h2>"
    html += "<table border='1'><tr><th>Time</th><th>Source IP</th><th>Type</th><th>Details</th></tr>"
    for alert in alerts:
        html += f"<tr><td>{alert[1]}</td><td>{alert[2]}</td><td>{alert[3]}</td><td>{alert[4]}</td></tr>"
    html += "</table>"

    html += "<h2>Blocked IPs</h2>"
    html += "<table border='1'><tr><th>Time</th><th>IP</th><th>Reason</th></tr>"
    for b in blocked:
        html += f"<tr><td>{b[1]}</td><td>{b[2]}</td><td>{b[3]}</td></tr>"
    html += "</table>"
    return html


app.run(debug=True)
