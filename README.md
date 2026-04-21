# Aruba Network Agent

A monitoring and automation agent for Aruba switch infrastructure, designed to run as a systemd service on **AlmaLinux 9**.

## Features

| Feature | Description |
|---|---|
| **Switch Reachability** | Active REST API polling every 30s per switch; alerts after 3 consecutive failures, clears on recovery |
| **Auto-Discovery** | ICMP scan of configured subnets discovers Aruba switches by hostname; newly found switches are automatically added to reachability monitoring |
| **Config Backup** | Downloads running-config from every discovered switch via AOS-CX REST API; rolling 7-day retention |
| **ARP Discovery** | Queries router ARP tables per campus location via CLI API; enriches with nmap DNS data; outputs timestamped CSVs |
| **Firmware Update** | Two-phase concurrent firmware compliance check and upload (on-demand) |
| **Web Dashboard** | Flask-based dark UI with live switch status, backup results, and manual Run Now triggers |

## Project Structure

```
Aruba-Network-Agent/
├── main.py                          # Entry point
├── requirements.txt
├── aruba-agent.service              # Systemd unit file
├── config.ini                       # Configuration template (not committed — contains credentials)
└── aruba_agent/
    ├── cx_session.py                # Unified AOS-CX REST API client
    ├── notifier.py                  # Thread-safe SMTP email notifier
    ├── state.py                     # Shared in-memory state (monitors → web UI)
    ├── scheduler.py                 # Daily HH:MM task scheduler
    ├── monitors/
    │   └── switch_poller.py         # Switch reachability poller + dynamic manager
    ├── tasks/
    │   ├── backup.py                # Config backup task
    │   ├── scanner.py               # ICMP network scanner
    │   ├── arp.py                   # ARP discovery task
    │   └── firmware.py              # Firmware updater (on-demand)
    └── web/
        ├── app.py                   # Flask app + REST API routes
        └── templates/
            └── dashboard.html       # Bootstrap 5 dark dashboard
```

## Requirements

- AlmaLinux 9 (Python 3.9+)
- Aruba AOS-CX 6300M switches running AOS-CX 10.13
- `nmap` installed on the agent host (for ARP discovery)

```bash
sudo dnf install -y python3 python3-pip nmap
pip3 install -r requirements.txt
```

**Python dependencies:**
```
requests, urllib3, flask, scapy, python-dotenv
```

## Installation

### 1 — Create directories and service account

```bash
sudo useradd -r -s /sbin/nologin aruba-agent

sudo mkdir -p \
  /opt/aruba-agent \
  /etc/aruba-agent/subnets \
  /var/lib/aruba-agent/backups \
  /var/lib/aruba-agent/arp \
  /var/lib/aruba-agent/firmware
```

### 2 — Copy files

```bash
# Clone the repo
git clone https://github.com/LuckyBasartd/Aruba-Network-Agent.git
cd Aruba-Network-Agent

# Copy code
sudo cp -r aruba_agent main.py requirements.txt /opt/aruba-agent/

# Copy and secure config
sudo cp config.ini /etc/aruba-agent/config.ini
sudo chown root:aruba-agent /etc/aruba-agent/config.ini
sudo chmod 640 /etc/aruba-agent/config.ini

# Copy subnet lists
sudo cp subnets/*.txt /etc/aruba-agent/subnets/

# Install systemd unit
sudo cp aruba-agent.service /etc/systemd/system/
```

### 3 — Set permissions

```bash
sudo chown -R root:aruba-agent /opt/aruba-agent
sudo chmod -R 750 /opt/aruba-agent
sudo chown -R aruba-agent:aruba-agent /var/lib/aruba-agent
```

### 4 — Edit config

```bash
sudo nano /etc/aruba-agent/config.ini
```

Fill in:
- `[credentials]` — switch admin username/password
- `[smtp]` — SMTP host, port, credentials, and recipients
- `[switch.*]` — static switch IPs to monitor before first scan
- `[scanner]` — subnets to scan
- `[arp.*]` — router IPs and subnet lists per location

### 5 — Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aruba-agent
```

### 6 — Open firewall ports

```bash
sudo firewall-cmd --permanent --add-port=8080/tcp   # Web UI
sudo firewall-cmd --reload
```

## Usage

### Web Dashboard

Access at `http://<server-ip>:8080`

- **Switch Reachability** — live UP/DOWN status for all monitored switches
- **Config Backup** — last run summary with success/failure counts; Run Now button
- **Network Scanner** — last scan time, device count; Run Now button
- **ARP Discovery** — last run timestamp per campus location

### Logs

```bash
journalctl -u aruba-agent -f
```

### Firmware Update (on-demand)

```bash
# Copy firmware image to the server first
scp ArubaOS-CX_6400-6300_10_13_1150.swi \
    user@server:/var/lib/aruba-agent/firmware/

# Run the updater
sudo -u aruba-agent python3 /opt/aruba-agent/main.py \
    /etc/aruba-agent/config.ini --firmware-update
```

## Workflow

```
00:00  Network Scanner
         ICMP ping all configured subnets
         Filter hosts by DNS keyword (6300, 6100, Aruba)
         Write /var/lib/aruba-agent/ip_list.txt
         Auto-register new switches with reachability monitor

01:00  ARP Discovery (per location)
         nmap ping-sweep subnets
         Query router ARP tables via CLI API
         Write timestamped CSV to /var/lib/aruba-agent/arp/<location>/

02:00  Config Backup
         Read ip_list.txt
         Save running-config → startup-config on each switch
         Download and store locally with 7-day rolling retention
         Email summary report

Continuous  Switch Reachability Poller
         Poll /system endpoint every 30s per switch
         Alert after 3 consecutive failures
         Clear alert on recovery
```

## Configuration Reference

```ini
[credentials]
username = admin
password = YourSwitchPassword

[smtp]
host     = smtp.gmail.com
port     = 587
use_tls  = true
username = alerts@example.com
password = YourAppPassword
to       = noc@example.com, admin@example.com

[web]
host     = 0.0.0.0
port     = 8080
username =                   # leave blank to disable Basic Auth
password =

[switch.<name>]         # Static switch — monitored immediately at startup
host              = 192.168.1.1
verify_ssl        = false
poll_interval     = 30
failure_threshold = 3

[scanner]
enabled          = true
schedule         = 00:00
subnets          = 10.40.0.0/24,10.80.0.0/24
exclude_suffixes = 1,2,3,255
filter_keywords  = 6100,6300,Aruba
device_file      = /var/lib/aruba-agent/network_devices.csv
ip_list_output   = /var/lib/aruba-agent/ip_list.txt

[backup]
enabled        = true
schedule       = 02:00
ip_list        = /var/lib/aruba-agent/ip_list.txt
backup_path    = /var/lib/aruba-agent/backups
retention_days = 7

[arp.<location>]
enabled    = true
schedule   = 01:00
routers    = 10.253.0.12,10.253.0.13
ip_list    = /etc/aruba-agent/subnets/location_ip_list.txt
output_dir = /var/lib/aruba-agent/arp/<location>

[firmware]
ip_list        = /var/lib/aruba-agent/ip_list.txt
target_version = 10.13.1150
image_path     = /var/lib/aruba-agent/firmware/ArubaOS-CX_6400-6300_10_13_1150.swi
max_workers    = 2
```

## AOS-CX API Versions

The agent automatically tries API versions in order: `v10.13 → v10.10 → v10.04`. To pin a specific version for backup:

```ini
[backup]
api_version = v10.13
```
