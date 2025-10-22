# Suricata IDS lab

## STEP 1 — Lab topology

- Two VMs on the same **host-only** VirtualBox network (`vboxnet0` / `192.168.56.0/24`):
    - **Ubuntu IDS VM** (server) — installs Suricata, monitors traffic
        - Adapter1: NAT (optional internet)
        - Adapter2: Host‑only (`vboxnet0`) — e.g. `192.168.56.107` on `enp0s8`
    - **Kali attacker VM**
        - Adapter1: NAT (optional)
        - Adapter2: Host‑only (`vboxnet0`) — e.g. `192.168.56.108` on `enp0s8`

Why host‑only? isolates the lab, keeps traffic deterministic, and avoids hitting real networks.

---

## STEP 2 — Install & prepare the IDS VM (Ubuntu                       Server)

Run these on the **Ubuntu IDS VM**:

```bash
# update + install suricata and helpers
sudo apt update
sudo apt install -y suricata jq net-tools python3

# create log dir and ensure permissions
sudo mkdir -p /var/log/suricata
sudo chown -R suricata:suricata /etc/suricata /var/log/suricata || true
```

Explanation: `jq` helps parse JSON logs; `net-tools` gives `ifconfig`/`route` if you prefer.

---

## STEP 3 — Confirm network interface & IP

Find the interface carrying the host‑only IP (on the IDS VM):

```bash
ip -4 addr show
# look for 192.168.56.x on a device (e.g., enp0s8)
```

Note the interface name (e.g., `enp0s8`) — **this is what Suricata must sniff**.

---

## STEP 4 — Configure Suricata to sniff the correct interface (af‑packet)

Edit `/etc/suricata/suricata.yaml`. by using `nano/etc/suricata/suricata.yaml`

Minimal example excerpts to place in `suricata.yaml`:

( you can filter or search by using [ctrl + w] and we filter based on the text )

```yaml
default-rule-path: /etc/suricata/rules

rule-files:
  - local.rules
  - http-events.rules
  - dns-events.rules
  - ssh-events.rules

af-packet:
  - interface: enp0s8
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: 200000
    block-size: 1048576
    copy-mode: tap
    tso: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
        - http:
        - dns:
        - tls:
        - flow
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast.log
```

Save changes, but **do not restart yet** — next create rules.

---

## STEP 5 — Create `local.rules`

Create `/etc/suricata/rules/local.rules` and give each rule a unique `sid`:

open `nano/etc/suricata/rules/local.rules`

```bash
# /etc/suricata/rules/local.rules

# TCP generic test
alert tcp any any -> any any (msg:"Test rule"; sid:1000001; rev:1;)

# ICMP ping test
alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000002; rev:1;)

# HTTP UA probe (Nmap User-Agent)
alert http any any -> any any (msg:"HTTP probe: UA contains Nmap"; http.user_agent; content:"Nmap"; nocase; sid:1000010; rev:1;)

# SYN scan threshold example (lab)
alert tcp any any -> any any (msg:"SYN scan detected"; flags:S; threshold:type both, track by_src, count 10, seconds 60; sid:1000003; rev:1;)
```

Permissions:

```bash
sudo chown root:suricata /etc/suricata/rules/local.rules
sudo chmod 640 /etc/suricata/rules/local.rules
```

Explain: `sid` unique numeric IDs; `http.user_agent` inspects application layer UA; threshold prevents one-off scans.

---

## STEP 6 — Test configuration & start Suricata

Validate config and rules:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -T -v
# look for: "rules_loaded: N" and "Configuration provided was successfully loaded"
```

Then start/restart the service:

```bash
sudo systemctl restart suricata
sudo systemctl enable suricata
sudo systemctl status suricata --no-pager
```

Check logs are created:

```bash
ls -l /var/log/suricata/fast.log /var/log/suricata/eve.json
```

(At this moment the suricata is ready to detect the intrusion )

---

## STEP 8 — Quick tests (from Kali attacker VM)

Use these to trigger rules. Replace target IP with your IDS IP (e.g. `192.168.56.107`).

1. **Ping (ICMP)** — triggers `ICMP Ping Detected`:

```bash
ping -c 3 192.168.56.107
```

1. **Simple TCP connect to SSH (port 22)** — triggers `Test rule` (any TCP):

```bash
nc -vz 192.168.56.107 22
```

1. **HTTP user‑agent probe** — start a simple HTTP server on the IDS (if not running):
    
    On IDS:
    

```bash
# choose a port (8000 or 8080)
python3 -m http.server 8000 --bind 0.0.0.0 &
```

From Kali:

```bash
curl -A "Nmap" http://192.168.56.107:8000/
```

1. **SYN scan** — triggers SYN scan threshold (if rule configured):

```bash
sudo nmap -sS -p 1-2000 -Pn 192.168.56.107
```

---

## STEP 9 — Where alerts are stored & how to read                     them

- `fast.log` — human readable one-line alerts:
    
    ```bash
    sudo tail -f /var/log/suricata/fast.log
    ```
    
    Example line:
    
    ```
    10/22/2025-10:19:33.331396  [**] [1:1000001:1] Test rule [**] {TCP} 192.168.56.108:52364 -> 192.168.56.107:22
    ```
    
- `eve.json` — JSON structured log for automated processing:
    
    ```bash
    sudo tail -f /var/log/suricata/eve.json | jq .
    ```
    

Useful `jq` queries:

- Latest alerts in columns:

```bash
sudo tail -n 500 /var/log/suricata/eve.json \
  | jq -r 'select(.alert) | [.timestamp, .src_ip, .src_port, .dest_ip, .dest_port, .alert.signature] | @tsv' \
  | column -t
```

- Top attacker IPs:

```bash
sudo jq -r 'select(.alert) | .src_ip' /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head
```

- Top destination ports:

```bash
sudo jq -r 'select(.alert) | .dest_port' /var/log/suricata/eve.json | sort -n | uniq -c | sort -rn | head
```

---

## STEP 10 — Interpreting `fast.log` lines (example)

```
10/22/2025-10:19:33.331396  [**] [1:1000001:1] Test rule [**] {TCP} 192.168.56.108:52364 -> 192.168.56.107:22
```

- Timestamp (when alert fired)
- `[1:1000001:1]` → generation id : SID : revision
- `Test rule` → `msg` text from your rule
- `{TCP}` → protocol
- `src_ip:src_port -> dest_ip:dest_port` → flow

Use these fields to build timelines and attribute attacks to ports/services.

---

## STEP 11 — Capture packets for forensics (optional)

If you want full packet capture around an incident:

```bash
sudo tcpdump -i enp0s8 port 21 or port 22 or port 80 -w /tmp/ids_capture.pcap -c 1000
# copy this pcap to your host and open in Wireshark for analysis
```

---

## Troubleshooting common issues

- **`fast.log` empty**:
    - Suricata not sniffing correct interface → check `af-packet` interface matches `ip -4 addr` output.
    - No matching traffic → generate test traffic (ping, curl, nmap).
    - Rules not loaded → run `sudo suricata -T -v` and check `rules_loaded`.
- **“No rule files match …”**:
    - `default-rule-path` wrong or `rule-files` references missing filenames. Make `default-rule-path: /etc/suricata/rules` and list filenames only.
- **Duplicate `sid` error**:
    - Ensure every rule `sid:` is unique.
- **vsftpd `500 OOPS` on chroot**:
    - Either set `allow_writeable_chroot=YES` for lab or change home ownership to root + writable `uploads` folder.

---

## Final notes / quick commands summary

- Test config:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -T -v

```

- Restart suricata:

```bash
sudo systemctl restart suricata

```

- Watch human alerts:

```bash
sudo tail -f /var/log/suricata/fast.log

```

- Watch structured JSON:

```bash
sudo tail -f /var/log/suricata/eve.json | jq .

```

- List rules folder:

```bash
ls -l /etc/suricata/rules/

```