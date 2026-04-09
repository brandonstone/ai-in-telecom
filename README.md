# Tool Comparison: Suricata vs Zeek

Part of the AI in Telecom capstone project at Norfolk State University. This component evaluates signature-based intrusion detection (Suricata) against behavioral anomaly detection (Zeek) across four attack scenarios in a containerized lab environment.

---

## Background

Traditional IDS tools like Suricata detect threats by matching network traffic against known attack signatures. They are fast and precise but blind to anything without a matching rule. AI-based behavioral tools like Zeek build a statistical baseline of normal traffic and flag deviations, making them capable of detecting novel attack patterns that no signature yet describes.

This comparison tests both approaches against the same traffic to document where each succeeds, where it fails, and what the gap means for telecommunications security operations.

### Networking concepts

- **TCP/IP packet structure** — every packet has a header with source/destination IP, ports, and flags. The SYN flag means "start a connection." Port scans send SYN-only packets to many ports without completing the handshake. SYN floods send thousands of SYN packets to one port, exhausting connection tables. Both are identifiable from flag and volume patterns which is exactly what Suricata's rules match on.

- **Docker bridge networking** — Docker creates a virtual Ethernet switch (`docker0`). Each container gets a virtual network card (`eth0`) connected to that bridge. Packets between containers travel through the bridge like packets on a physical LAN. `network_mode: host` does not work on Mac because Docker Desktop runs inside a Linux VM and cannot see Mac's physical interfaces. A custom bridge network (`ids_network`) gives all three containers an isolated LAN.

- **Promiscuous mode** — normally a network card only passes packets addressed to its own MAC address. Promiscuous mode disables that filter so the card passes every packet it sees to the OS. Suricata and Zeek require this to capture all traffic on a segment. `cap_add: NET_ADMIN, NET_RAW` in Docker enables this capability.

- **Layer 2 vs Layer 3 (why `sendp()` is used)** — Scapy's `send()` operates at Layer 3 (IP), handing packets to the OS kernel routing stack which bypasses the Docker bridge on Mac. `sendp()` operates at Layer 2 (Ethernet), writing frames directly to `eth0` so they physically traverse the bridge and arrive at Suricata and Zeek's interfaces.

- **Connection state** — Suricata matches rules against individual packets. Zeek tracks the full connection lifecycle from SYN to FIN, building a complete record with total packets, bytes, and duration. The `connection_state_remove` event fires when the connection closes, giving Zeek a behavioral picture that Suricata's per-packet matching cannot produce.

### Why these rules are telecom-specific

| Rule | Pattern | Telecom relevance |
|---|---|---|
| Port scan | 10 SYN packets in 60s from same source | Reconnaissance precursor to targeting telecom infrastructure and signaling services |
| DDoS | 100 SYN packets in 10s to same destination | SYN flood is the dominant volumetric attack against telecom core nodes and exposed APIs |
| Slow exfiltration | No rule (by design) | Mirrors CDR (call detail record) theft high value, low volume, evades rate-based detection |

Port scanning in telecom is particularly significant because signaling protocols (SS7, Diameter, SIP) expose services on discoverable ports. A DDoS against a telecom node disrupts service for entire subscriber segments, not just one target. Slow exfiltration has no signature because the pattern is novel by definition and the value of Zeek is detecting it without one.

---

## Setup

Requires Docker Desktop and Docker Compose. Clone the repo and run from the project root.

```bash
docker compose up -d
```

Verify all three containers are running:

```bash
docker compose ps
```

Expected output:
```
ai-in-telecom-snort-1        Up
ai-in-telecom-zeek-1         Up
ai-in-telecom-traffic_gen-1  Up
```

---

## Usage

### Run the full test sequence

```bash
# Install Scapy in the traffic generator container
docker exec -it ai-in-telecom-traffic_gen-1 pip install scapy -q

# Copy the traffic generator script
docker cp ./traffic_generator.py ai-in-telecom-traffic_gen-1:/traffic_generator.py

# Run traffic generation (~4 minutes total)
docker exec -it ai-in-telecom-traffic_gen-1 python /traffic_generator.py
```

Or use the helper script:

```bash
chmod +x start_containers.sh
./start_containers.sh
```

### Monitor alerts in real time (open two terminals)

```bash
# Terminal 1 — Suricata
docker exec -it ai-in-telecom-snort-1 tail -f /var/log/suricata/fast.log

# Terminal 2 — Zeek
docker exec -it ai-in-telecom-zeek-1 tail -f /var/log/zeek/notice.log
```

### Traffic sequence

The generator runs four phases in order:

| Phase | Duration | Source IP | Attack type |
|---|---|---|---|
| 1 | 60s | `172.18.0.2` | Normal HTTP traffic |
| 2 | ~3.5min | `192.168.1.200` | Port scan (ports 1–100) |
| 3 | 30s | `192.168.1.201` | SYN flood DDoS |
| 4 | 60s | `192.168.1.202` | Slow exfiltration (port 443) |

### Verify containers are capturing traffic

```bash
# Confirm Suricata rules loaded correctly
docker exec -it ai-in-telecom-snort-1 suricata -T -c /etc/suricata/rules/suricata.yaml

# Confirm Zeek interface is up
docker exec -it ai-in-telecom-zeek-1 ip link show

# Confirm log directories exist
docker exec -it ai-in-telecom-snort-1 ls -la /var/log/suricata/
docker exec -it ai-in-telecom-zeek-1 ls -la /var/log/zeek/
```

---

## Generate comparison charts

```bash
python tool_comparison.py
open ids_comparison_results.png
```

Produces a 4-panel figure:
- **Panel 1** — Alert counts by attack type (Suricata vs Zeek)
- **Panel 2** — Detection coverage scorecard
- **Panel 3** — Detection accuracy per scenario (hit / partial / miss)
- **Panel 4** — Detection timeline by attack type

---

## Understanding the results

### What to expect

| Attack | Suricata | Zeek |
|---|---|---|
| Port scan | Detected (signature match) | Detected (packet rate anomaly) |
| DDoS | Detected (rate threshold) | Detected (volume anomaly) |
| Slow exfiltration | Misclassified (wrong rule fires) | Correctly classified (behavioral deviation) |
| Normal traffic false positives | ~3 | ~18 |

### Key finding

Suricata does not fully miss slow exfiltration. It fires an alert but applies the wrong classification because no exfiltration-specific rule exists. This is the more important result: signature systems can detect anomalous volume but cannot characterize novel attack patterns without the right rule. Zeek correctly identifies the behavioral deviation with no prior knowledge of the attack pattern.

The tradeoff is Zeek's higher false positive rate on normal traffic. In this lab, thresholds were tuned down from production defaults to trigger on small packet counts. In a production carrier environment, thresholds would be calibrated against a real baseline of millions of connections per hour, substantially reducing false positive noise.

### How results differ by network

| Environment | Effect on results |
|---|---|
| This lab | Synthetic traffic, single subnet, low thresholds as both systems alert frequently |
| Small carrier | Low analyst headcount; Zeek's false positives would cause alert fatigue without tuning |
| Large carrier | Higher baseline volume means Zeek's behavioral baseline is more accurate; Suricata signature library needs regular updates |
| 5G core network | Signaling protocols (HTTP/2 N-interfaces, PFCP, GTP) require Zeek scripts specific to those protocols; port-based Suricata rules less meaningful in service-based architecture |

### Reproducing results

Results are deterministic so the same traffic generator script produces the same packet sequence every run. To reset and rerun from scratch:

```bash
docker compose down
docker compose up -d
docker exec -it ai-in-telecom-traffic_gen-1 pip install scapy -q
docker cp ./traffic_generator.py ai-in-telecom-traffic_gen-1:/traffic_generator.py
docker exec -it ai-in-telecom-traffic_gen-1 python /traffic_generator.py
```

Suricata alert counts may vary slightly by timing. Zeek notice counts vary slightly based on connection batching window. Attack type classifications are consistent across runs.

---

## What was changed to make the containers work

| Issue | Fix |
|---|---|
| Snort AMD64-only, broken under Apple Silicon | Switched to Suricata to support native ARM64 and same rule syntax |
| Containers couldn't capture packets | Added `cap_add: NET_ADMIN, NET_RAW` to all containers |
| Zeek logs not appearing in mounted volume | Set `working_dir: /var/log/zeek` in docker-compose.yml |
| `network_mode: host` not working on Mac | Switched to custom Docker bridge network (`ids_network`) |
| Scapy packets bypassing Docker bridge | Switched from `send()` to `sendp()` with explicit `iface='eth0'` |
| Broadcast MAC warnings | Resolved MAC with `getmacbyip()` at script startup |
| Zeek never firing (zero bytes in conn.log) | Changed threshold from `orig_bytes > 100000` to `orig_pkts > 2` |
| Suricata reputation preprocessor error | Commented out and not compiled into the image |

---

## Notes

- Suricata is used in place of Snort throughout. Both are signature-based IDS tools using identical rule syntax. The substitution was made due to ARM64 platform constraints (Apple Silicon), and the `linton/docker-snort` image is AMD64-only and its rule engine fails silently under QEMU emulation.
- Zeek detection thresholds are tuned below production defaults for lab purposes. This inflates false positive counts and should be noted when interpreting Panel 3.
