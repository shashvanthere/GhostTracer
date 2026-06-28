from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
from scapy.all import load_layer
import hashlib
import json

KNOWN_MALICIOUS_JA3 = {
    "4d7a28d6f2263ed61de88ca66eb011e3": "Emotet malware",
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike C2",
    "b32309a26951912be7dba376398abc3b": "Dridex banking trojan",
    "a0e9f5d64349fb13191bc781f81f42e1": "TrickBot malware",
    "c35b4e9974dcd4b618bf38e3f760002b": "Trickbot/BazarLoader",
}

def compute_ja3(packet):
    if TLSClientHello not in packet:
        return None
    try:
        hello = packet[TLSClientHello]
        tls_version = str(hello.version)
        ciphers = "-".join([str(c) for c in hello.ciphers])
        extensions = ""
        curves = ""
        formats = ""
        if hello.ext:
            ext_types = []
            for ext in hello.ext:
                ext_types.append(str(ext.type))
                if ext.type == 10:
                    curves = "-".join([str(c) for c in ext.groups])
                if ext.type == 11:
                    formats = "-".join([str(f) for f in ext.ecpl])
            extensions = "-".join(ext_types)
        ja3_string = f"{tls_version},{ciphers},{extensions},{curves},{formats}"
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        return ja3_hash
    except Exception:
        return None

load_layer("tls")

def tls_handler(packet):
    if IP not in packet:
        return
    ja3 = compute_ja3(packet)
    if ja3 is None:
        return
    timestamp = datetime.now().strftime("%H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if ja3 in KNOWN_MALICIOUS_JA3:
        threat = KNOWN_MALICIOUS_JA3[ja3]
        print(f"[{timestamp}] ALERT ⚠️ | {src_ip} --> {dst_ip}")
        print(f"JA3 --> {ja3}")
        print(f"Threat --> {threat}")
    else:
        print(f"[{timestamp}] CLEAR ✅ | {src_ip} --> {dst_ip}")
        print(f"JA3 --> {ja3}")
    print("-" * 60)
print("GhostTrace Phase 4 - JA3 TLS Fingerprinter")
print("-" * 60)
sniff(filter="tcp port 443", prn = tls_handler, store = False)