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
| **RADIUS Login** | Session-based web login validated against an external RADIUS server (PAP, UDP 1812); HTTPOnly signed-cookie sessions with configurable timeout |

## Project Structure

```
Aruba-Network-Agent/
├── main.py                          # Entry point
├── requirements.txt
├── aruba-agent.service              # Systemd unit file
├── config.ini.example               # Configuration template (commit-safe; copy to /etc/aruba-agent/config.ini)
├── apache/
│   └── aruba-switch-manager.conf    # Apache2 vhost (HTTP→HTTPS + reverse proxy to Flask)
├── scripts/
│   ├── generate-self-signed-cert.sh # OpenSSL helper — mints the TLS cert/key
│   └── install-apache.sh            # One-shot httpd + mod_ssl installer
└── aruba_agent/
    ├── cx_session.py                # Unified AOS-CX REST API client
    ├── notifier.py                  # Thread-safe SMTP email notifier
    ├── state.py                     # Shared in-memory state (monitors → web UI)
    ├── scheduler.py                 # Daily HH:MM task scheduler
    ├── auth.py                      # RADIUS PAP authenticator (pyrad)
    ├── monitors/
    │   └── switch_poller.py         # Switch reachability poller + dynamic manager
    ├── tasks/
    │   ├── backup.py                # Config backup task
    │   ├── scanner.py               # ICMP network scanner
    │   ├── arp.py                   # ARP discovery task
    │   └── firmware.py              # Firmware updater (on-demand)
    └── web/
        ├── app.py                   # Flask app + REST API routes + login/logout
        └── templates/
            ├── dashboard.html       # Bootstrap 5 dark dashboard
            └── login.html           # RADIUS sign-in page
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
requests, urllib3, flask, scapy, pyrad
```

`pyrad` is required for RADIUS authentication on the login page.

## Installation

For a fresh AlmaLinux 9 server, see **[INSTALL.md](INSTALL.md)** for an end-to-end walkthrough (system updates → service account → Apache + TLS → first login). The condensed reference below assumes you have read that.

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

# Copy code (rsync skips unchanged files; --delete drops stale ones on update)
sudo rsync -a --delete aruba_agent/ /opt/aruba-agent/aruba_agent/
sudo rsync -a main.py requirements.txt /opt/aruba-agent/

# Copy and secure config (real config.ini is gitignored — repo ships an example)
# Owned by aruba-agent so the Settings page can write back to it.
sudo install -m 640 -o aruba-agent -g aruba-agent \
    config.ini.example /etc/aruba-agent/config.ini

# Copy subnet lists
sudo rsync -a subnets/ /etc/aruba-agent/subnets/

# Install systemd unit
sudo rsync -a aruba-agent.service /etc/systemd/system/
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
- `[web]` — generate a `secret_key` for session signing (see below)
- `[radius]` — RADIUS server, shared secret, and NAS identifier for login
- `[switch.*]` — static switch IPs to monitor before first scan
- `[scanner]` — subnets to scan
- `[arp.*]` — router IPs and subnet lists per location

Generate a stable session signing key:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Paste the output into `[web] secret_key`. Without this, the agent generates an ephemeral key on every restart and all sessions are invalidated.

### 5 — Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aruba-agent
```

### 6 — Front the dashboard with HTTPS (Apache2)

In production the dashboard is served via Apache2 over HTTPS on port 443. The Flask app binds to `127.0.0.1:8080` only — Apache is the public face.

```bash
# 1. Mint a self-signed cert (valid 10 years, internal-only deployment).
#    Pass an explicit hostname/IP if your box is reachable by something
#    other than `hostname -f` returns.
sudo ./scripts/generate-self-signed-cert.sh

# 2. Install Apache + mod_ssl, drop in the vhost, fix SELinux + firewall,
#    and restart httpd.
sudo ./scripts/install-apache.sh

# 3. Restart the agent so it picks up host=127.0.0.1 and trust_proxy_headers.
sudo systemctl restart aruba-agent
```

The dashboard is now at `https://<server-ip>/`. Browsers will warn about the self-signed cert; click through, or import `/etc/pki/tls/certs/aruba-switch-manager.crt` into your workstation's trust store to silence it.

If you instead want to expose Flask directly without Apache (development/testing only), set `host = 0.0.0.0`, `secure_cookies = false`, `trust_proxy_headers = false` in `[web]` and open the Flask port:

```bash
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

## Usage

### Web Dashboard

Access at `http://<server-ip>:8080` (or via the Apache2 HTTPS reverse proxy on port 443 in production).

You will be redirected to a sign-in page. Enter your RADIUS credentials — the agent forwards them to the configured RADIUS server using PAP. On success, a signed session cookie is set (HTTPOnly, SameSite=Lax) that lasts `[web] session_timeout_hours`. Click **Logout** in the navbar to end the session immediately.

- **Switch Reachability** — live UP/DOWN status for all monitored switches
- **Config Backup** — last run summary with success/failure counts; Run Now button
- **Network Scanner** — last scan time, device count; Run Now button
- **ARP Discovery** — last run timestamp per campus location

### Authentication

Logins are validated against an external RADIUS server. There is no local admin fallback; if `[radius] enabled = false` or the server is unreachable, the dashboard is inaccessible.

Behaviour:
- **PAP on UDP 1812** — the standard RADIUS auth flow.
- **Per-attempt audit log** — every login attempt is logged with username, source IP, and result. Passwords are never logged.
- **NAS-Identifier** — sent to the RADIUS server as `[radius] nas_identifier` (defaults to the agent's hostname). Configure your RADIUS server to authorise this NAS.

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
host                  = 127.0.0.1   # 0.0.0.0 only when running without Apache
port                  = 8080
secret_key            =             # python3 -c "import secrets; print(secrets.token_urlsafe(48))"
session_timeout_hours = 8
secure_cookies        = true        # false only for direct-HTTP development
trust_proxy_headers   = true        # ProxyFix — required when fronted by Apache

[radius]
enabled        = true
server         = 10.0.0.50
secret         = SharedSecretHere
port           = 1812
nas_identifier = aruba-switch-manager
timeout        = 5
retries        = 2

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
