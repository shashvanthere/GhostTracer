from scapy.all import sniff,IP,TCP,UDP
from datetime import datetime

def packet_handler(packet):
    if IP not in packet:
        return
    timestamp = datetime.now().strftime("%H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        print(f"[{timestamp}] TCP {src_ip}:{sport} -> {dst_ip}:{dport} flags = {flags}")
    elif UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        print(f"[{timestamp}] UDP {src_ip}:{sport} -> {dst_ip}:{dport}")
print("GhostTracer's Packet Sniffer running... Press Ctrl + C to stop")
print("-" * 55)
sniff(prn=packet_handler, store = False)