import subprocess
from datetime import datetime
import sqlite3
from scapy.all import sniff, IP, TCP
from collections import defaultdict

port_scan_tracker = defaultdict(list)
beacon_tracker = defaultdict(list)
data_tracker = defaultdict(int)
already_alerted_scan = set()
already_blocked = set()

MY_IP = "10.20.18.240"

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


def log_block(ip_address, reason):
    timestamp = datetime.now().strftime("%H:%M:%S")
    cursor.execute(
        "INSERT INTO blocked_ips (timestamp, ip_address, reason) VALUES (?, ?, ?)",
        (timestamp, ip_address, reason)
    )
    conn.commit()


def block_ip(ip_address, reason):
    if ip_address in already_blocked:
        return False
    rule_name = f"GhostTrace_Block_{ip_address}"
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in",
         "action=block", f"remoteip={ip_address}"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        already_blocked.add(ip_address)
        log_block(ip_address, reason)
        return True
    return False


def unblock_ip(ip_address):
    rule_name = f"GhostTrace_Block_{ip_address}"
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall",
            "delete", "rule", f"name={rule_name}"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        already_blocked.discard(ip_address)
        return True
    return False


def detect_port_scan(src_ip, dst_port):
    port_scan_tracker[src_ip].append(dst_port)
    unique_ports = len(set(port_scan_tracker[src_ip]))
    if unique_ports > 10 and src_ip not in already_alerted_scan:
        already_alerted_scan.add(src_ip)
        return True
    return False


def detect_beaconing(src_ip):
    timestamp = datetime.now()
    beacon_tracker[src_ip].append(timestamp)
    if len(beacon_tracker[src_ip]) < 3:
        return False
    beacon_tracker[src_ip] = beacon_tracker[src_ip][-5:]
    times = beacon_tracker[src_ip]
    intervals = []
    for i in range(1, len(times)):
        gap = (times[i] - times[i - 1]).total_seconds()
        intervals.append(gap)
    avg_gap = sum(intervals) / len(intervals)
    deviations = [abs(gap - avg_gap) for gap in intervals]
    max_deviation = max(deviations)
    if max_deviation < 2 and avg_gap > 1:
        return True
    return False


def detect_exfiltration(src_ip, packet_size):
    data_tracker[src_ip] += packet_size
    if data_tracker[src_ip] > 10 * 1024 * 1024:
        return True
    return False


def threat_handler(packet):
    if IP not in packet:
        return
    if TCP not in packet:
        return
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dst_port = packet[TCP].dport
    packet_size = len(packet)
    timestamp = datetime.now().strftime("%H:%M:%S")
    flags = packet[TCP].flags

    if flags == "S" and dst_ip == MY_IP and src_ip != MY_IP:
        if detect_port_scan(src_ip, dst_port):
            reason = f"Port scan - {len(set(port_scan_tracker[src_ip]))} unique ports"
            print(f"[{timestamp}] PORT SCAN DETECTED !!! | {src_ip}")
            if block_ip(src_ip, reason):
                print(f"BLOCKED via Windows Firewall")
            print("-" * 60)

    if detect_beaconing(src_ip):
        reason = "C2 beaconing - regular connection intervals"
        print(f"[{timestamp}] C2 BEACONING DETECTED | {src_ip}")
        if block_ip(src_ip, reason):
            print(f"BLOCKED via Windows Firewall")
        print("-" * 60)

    if detect_exfiltration(src_ip, packet_size):
        reason = f"Data exfiltration - {data_tracker[src_ip]} bytes sent"
        print(f"[{timestamp}] DATA EXFILTRATION DETECTED | {src_ip}")
        if block_ip(src_ip, reason):
            print(f"BLOCKED via Windows Firewall")
        print("-" * 60)


print("GhostTrace Phase 7 - Incident Response Engine")
print("-" * 60)
sniff(filter="tcp", prn=threat_handler, store=False)