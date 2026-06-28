import nmap
from datetime import datetime
import sys

print("Phase 2 - Network Discovery Engine")
print("-" * 50)

if len(sys.argv) < 2:
    print("Usage: python phase2_discovery.py 10.101.218.0/24")
    sys.exit(1)

target = sys.argv[1]
print(f"Scanning network: {target}")
print(f"Running scan on {target}...")
scanner = nmap.PortScanner()
scanner.scan(hosts=target,arguments="-sn")
print("Scan complete")
for host in scanner.all_hosts():
    state = scanner[host].state()
    name = scanner[host].hostname()
    time = datetime.now().strftime("%H:%M:%S")
    print(f"[{time}] {host} | state={state} | hostname = {name}")
total = len(scanner.all_hosts())
print(f"\nTotal live hosts found: {total}")