from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from datetime import datetime
PROTOCOL_INFO = {
    53:   {"name":"DNS",   "proto":"UDP", "risk":"DNS tunneling, C2 callbacks, DNS poisoning"},
    80:   {"name":"HTTP",  "proto":"TCP", "risk":"Cleartext data, MITM attacks, credential theft"},
    443:  {"name":"HTTPS", "proto":"TCP", "risk":"Malware in encrypted traffic, expired certs"},
    445:  {"name":"SMB",   "proto":"TCP", "risk":"EternalBlue, ransomware, pass-the-hash"},
    22:   {"name":"SSH",   "proto":"TCP", "risk":"Brute force, weak credentials, key theft"},
    3389: {"name":"RDP",   "proto":"TCP", "risk":"BlueKeep, ransomware entry, brute force"},
    161:  {"name":"SNMP",  "proto":"UDP", "risk":"Community string enumeration, info leakage"},
    23:   {"name":"Telnet","proto":"TCP", "risk":"Cleartext credentials, no encryption"},
    21:   {"name":"FTP",   "proto":"TCP", "risk":"Cleartext credentials, anonymous access"},
    25:   {"name":"SMTP",  "proto":"TCP", "risk":"Email spoofing, open relay abuse"},
}
def dns_handler(packet):
    if IP not in packet:
        return
    if DNS not in packet:
        return
    if DNSQR not in packet:
        return
    timestamp = datetime.now().strftime("%H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    domain = packet[DNSQR].qname.decode()
    print(f"[{timestamp}] DNS QUERY | {src_ip} --> {dst_ip}")
    info = PROTOCOL_INFO.get(53, {"name":"UNKNOWN","proto":"UNKNOWN","risk":"UNKNOWN"})
    print(f"           Domain   : {domain}")
    print(f"           Port     : 53 ({info['name']})")
    print(f"           Protocol : {info['proto']}")
    print(f"           Risks    : {info['risk']}")
    print("-" * 60)
print("GhostTrace Phase 3 - Protocol Analyzer")
print("-" * 60)
sniff(filter = "udp port 53", prn = dns_handler, store = False)