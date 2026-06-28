from scapy.all import sniff, IP, TCP
from datetime import datetime
from collections import defaultdict

port_scan_tracker = defaultdict(list)
beacon_tracker = defaultdict(list)
data_tracker = defaultdict(int)
already_alerted_scan = set()

MY_IP = "10.20.18.240"


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
            print(f"[{timestamp}] PORT SCAN DETECTED !!! | {src_ip}")
            print(f"Unique ports hit: {len(set(port_scan_tracker[src_ip]))}")
            print("-" * 60)
    if detect_beaconing(src_ip):
        print(f"[{timestamp}] C2 BEACONING DETECTED | {src_ip}")
        print("-" * 60)
    if detect_exfiltration(src_ip, packet_size):
        print(f"[{timestamp}] DATA EXFILTRATION DETECTED | {src_ip}")
        print(f"Total bytes sent: {data_tracker[src_ip]}")
        print("-" * 60)


print("GhostTrace Phase 5 - Threat Detection Engine")
print("-" * 60)
sniff(filter="tcp", prn=threat_handler, store=False)