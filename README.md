# GhostTrace — Network Security Monitoring & Automated Response Toolkit

GhostTrace is a Python-based network security toolkit built in eight phases.
Each phase is a standalone, independently runnable script that demonstrates
one real, working security capability — packet capture, network discovery,
protocol analysis, encrypted traffic fingerprinting, behavioral threat
detection, SIEM-style logging, automated firewall response, and a live
monitoring dashboard.

All phases share one SQLite database (`ghosttrace.db`), so later phases
build on and read the data produced by earlier ones.

---

## Why this project exists

Most internet traffic today is encrypted, and most "resume security skills"
are learned at a definitional level only. GhostTrace was built to close both
gaps at once: detect threats using traffic behavior and metadata — without
decrypting anything — while implementing every concept from scratch instead
of just running someone else's tool.

---

## Phase breakdown

| Phase | File | Capability | Key concepts |
|---|---|---|---|
| 1 | `phase1_sniffer.py` | Packet sniffer | Scapy, callbacks, TCP/IP, BPF filters |
| 2 | `phase2_discovery.py` | Network discovery | python-nmap, subnetting, CIDR, CLI args |
| 3 | `phase3_analyzer.py` | Protocol analyzer | DNS interception, protocol/port mapping |
| 4 | `phase4_ja3.py` | JA3 TLS fingerprinter | TLS ClientHello internals, MD5 hashing |
| 5 | `phase5_threats.py` | Threat detection engine | defaultdict, behavioral analysis, false-positive debugging |
| 6 | `phase6_siem.py` + `phase6_query.py` | SIEM & log analysis | SQLite, parameterized queries, GROUP BY / HAVING |
| 7 | `phase7_response.py` | Incident response automation | subprocess, Windows Firewall (netsh), audit logging |
| 8 | `phase8_dashboard.py` | Live dashboard | Flask, auto-refreshing web UI |

Phase 7 is the most complete standalone script — it includes the full
detection engine (Phase 5), the full logging engine (Phase 6), and the
firewall automation layer, all in one file. Phase 8 reads the same
database and visualizes it in a browser.

---

## Running it

Each phase runs independently with its own command:

```
python phase1_sniffer.py
python phase2_discovery.py 10.20.18.0/24
python phase3_analyzer.py
python phase4_ja3.py
python phase5_threats.py
python phase6_siem.py        (and separately: python phase6_query.py)
python phase7_response.py
python phase8_dashboard.py
```

**To see detection, logging, and the dashboard together**, run two scripts
in two terminals:

```
Terminal 1:  python phase7_response.py     (detects, blocks, and logs threats)
Terminal 2:  python phase8_dashboard.py    (reads ghosttrace.db, shown at
                                             http://127.0.0.1:5000)
```

Both read and write the same `ghosttrace.db` file, so anything Phase 7
detects appears on the Phase 8 dashboard within seconds.

---

## What it actually detects and does

- **Port scans** — flags any external IP probing 10+ unique ports on the host
- **C2 beaconing** — flags connections occurring at suspiciously regular intervals
- **Data exfiltration** — flags any single IP responsible for 10MB+ outbound traffic
- **JA3 fingerprinting** — generates a TLS client fingerprint without decrypting traffic, checked against a small known-malicious-hash list
- **Automated response** — confirmed threats are blocked in real time via the Windows Firewall (`netsh advfirewall`), with every block permanently logged

---

## Known, honestly-documented limitations

- **JA3 on Windows**: Windows' built-in TLS stack (Schannel) uses proprietary
  cipher suite IDs not in Scapy's lookup table, so JA3 fingerprinting is
  inconsistent on Windows clients. This is a documented limitation of
  Scapy + Schannel, not a bug in the JA3 implementation — the same logic
  works cleanly against OpenSSL-based clients (e.g. Linux, curl on Linux).
- **Cross-session block memory**: `already_blocked` is stored in memory, so
  restarting the script can result in a duplicate (but harmless) firewall
  rule for an IP blocked in a previous run. The permanent fix is checking
  the `blocked_ips` table directly before calling `netsh`, instead of
  relying solely on the in-memory set.
- **PAN-OS integration**: containment currently targets the Windows Firewall
  for local testing. The same `block_ip()` function signature maps directly
  onto Palo Alto's PAN-OS REST API (Dynamic Address Groups) — replacing the
  `subprocess.run(netsh...)` call with a `requests.post()` call would deploy
  the same logic to a real PAN-OS firewall without touching the detection
  or logging layers.
- **AWS CloudWatch**: the same `log_alert()` pattern can be extended with a
  `boto3` call to push alerts to AWS CloudWatch Logs; this was designed but
  not deployed against a live AWS account.

---

## Tech stack

Python, Scapy, python-nmap, SQLite3, Flask, subprocess, hashlib

---

## Author's note

Every line in this project was written, debugged, and tested personally —
including real bugs discovered during testing (ephemeral port false
positives in the port scan detector, Windows interface selection issues,
Windows Firewall self-scan quirks, and Schannel/Scapy TLS incompatibilities)
and the fixes applied for each one.
