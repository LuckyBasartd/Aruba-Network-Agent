# Install Guide — Clean AlmaLinux 9

End-to-end install of the Aruba Network Agent on a fresh AlmaLinux 9
server with HTTPS, RADIUS login, and Apache2 reverse proxy.

Allow ~20 minutes start to finish.

---

## 0 — Prerequisites

You will need:

- A clean AlmaLinux 9 server with internet access (or an internal repo mirror).
- An account with `sudo`.
- The hostname/IP that the dashboard will be reached at (used in the TLS cert).
- A reachable RADIUS server (IP, shared secret, NAS-IP allowlisted).
- (Optional) SMTP relay credentials for email alerts.

```bash
# Confirm the OS, take a snapshot of useful info before starting
cat /etc/redhat-release
hostname -f
hostname -I
```

---

## 1 — System updates and base packages

```bash
sudo dnf -y update
sudo dnf install -y \
    git python3 python3-pip nmap openssl \
    httpd mod_ssl firewalld
```

Make sure firewalld is running (it is by default on AlmaLinux 9):

```bash
sudo systemctl enable --now firewalld
```

---

## 2 — Service account and directory tree

```bash
# Dedicated low-privilege account — never logs in interactively
sudo useradd -r -s /sbin/nologin aruba-agent

# Code, config, and runtime data live under FHS-friendly paths
sudo mkdir -p \
    /opt/aruba-agent \
    /etc/aruba-agent/subnets \
    /var/lib/aruba-agent/backups \
    /var/lib/aruba-agent/arp \
    /var/lib/aruba-agent/firmware
```

---

## 3 — Clone the repository

```bash
cd /tmp
git clone https://github.com/LuckyBasartd/Aruba-Network-Agent.git
cd Aruba-Network-Agent
```

If you maintain a private fork or run this air-gapped, clone from there
instead and skip ahead.

---

## 4 — Install the application files

`rsync` is preferred over `cp -r` for both the initial install and
later updates: it skips unchanged files (faster), and `--delete`
removes anything that was deleted from the repo so stale `.py` files
can't linger in `/opt/aruba-agent` and shadow newer modules.

```bash
# Code
sudo rsync -a --delete aruba_agent/ /opt/aruba-agent/aruba_agent/
sudo rsync -a main.py requirements.txt /opt/aruba-agent/

# Config template — secured because it will hold credentials.
# The real config.ini is gitignored; the repo ships config.ini.example.
# Owned by aruba-agent so the Settings page can write back to it.
sudo install -m 640 -o aruba-agent -g aruba-agent \
    config.ini.example /etc/aruba-agent/config.ini

# Subnet lists for ARP discovery (if you have any)
[ -d subnets ] && sudo rsync -a subnets/ /etc/aruba-agent/subnets/ || true

# Systemd unit
sudo rsync -a aruba-agent.service /etc/systemd/system/
```

---

## 5 — Python dependencies

```bash
sudo pip3 install -r /opt/aruba-agent/requirements.txt
```

This installs `requests`, `urllib3`, `flask`, `scapy`, and `pyrad`.

---

## 6 — Permissions

```bash
sudo chown -R root:aruba-agent /opt/aruba-agent
sudo chmod -R 750              /opt/aruba-agent
sudo chown -R aruba-agent:aruba-agent /var/lib/aruba-agent
```

---

## 7 — Generate a session signing key

The key is what makes login sessions survive an agent restart:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Copy the output — you will paste it into `[web] secret_key` in the next step.

---

## 8 — Edit the config

```bash
sudo nano /etc/aruba-agent/config.ini
```

Fill in:

- `[credentials]` — switch admin username/password (used as defaults).
- `[smtp]` — set `enabled = true` and fill in host/port/from/to if you want email alerts.
- `[web]`
  - `secret_key`           = the key generated in step 7
  - `host`                 = `127.0.0.1` (Apache will front it; do not change)
  - `secure_cookies`       = `true`
  - `trust_proxy_headers`  = `true`
- `[radius]`
  - `enabled`        = `true`
  - `server`         = your RADIUS server IP
  - `secret`         = the shared secret configured for this NAS
  - `nas_identifier` = e.g. `aruba-switch-manager`
  - On the RADIUS server, register this host's IP as a NAS with the same shared secret.
- `[switch.<name>]` — optionally pre-seed any switches you already know.
- `[scanner]` — list the subnets that contain Aruba switches.
- `[arp.<location>]` — one block per campus location, with router IPs.
- `[firmware]` — only matters if you plan to run firmware updates.

Save and exit.

---

## 9 — Generate the self-signed TLS certificate

```bash
cd /tmp/Aruba-Network-Agent
sudo ./scripts/generate-self-signed-cert.sh
```

The script auto-detects the hostname and primary IP, so the cert SANs
will already cover the obvious access paths. To pin a specific name:

```bash
sudo ./scripts/generate-self-signed-cert.sh switches.example.local
```

Output goes to `/etc/pki/tls/certs/aruba-switch-manager.crt` and
`/etc/pki/tls/private/aruba-switch-manager.key`.

---

## 10 — Install Apache + reverse proxy

```bash
sudo ./scripts/install-apache.sh
```

This script:

1. Installs `httpd` + `mod_ssl` (idempotent).
2. Drops `/etc/httpd/conf.d/aruba-switch-manager.conf` into place.
3. Sets `setsebool -P httpd_can_network_connect 1` so Apache can talk
   to the Flask backend on `127.0.0.1:8080`.
4. Opens TCP/443 in firewalld and removes any leftover TCP/8080 rule.
5. Validates the config (`apachectl configtest`) and restarts httpd.

If `configtest` fails, fix the error it reports before continuing — the
script will not start httpd with a broken config.

---

## 11 — Start the agent

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aruba-agent
```

Tail the journal in another window to watch it boot:

```bash
sudo journalctl -u aruba-agent -f
```

You should see the scheduler register tasks, the switch poller start,
and a line like:

```
Web UI: ProxyFix enabled — trusting one upstream proxy hop
Web UI: session-based login with RADIUS PAP enabled
Web UI available at http://localhost:8080
```

---

## 12 — (Optional) Enable the Settings → Restart Now button

The Settings page in the dashboard has a **Restart Agent** button so
you can apply config changes without dropping to a shell. It works by
shelling out to `systemctl restart aruba-agent` via sudo, which means
the `aruba-agent` service account needs a NOPASSWD sudoers rule.

```bash
sudo tee /etc/sudoers.d/aruba-agent-restart > /dev/null <<'EOF'
# Allow the aruba-agent service account to restart its own service
# from the web UI. No other systemctl operations are permitted.
aruba-agent ALL=(root) NOPASSWD: /bin/systemctl restart aruba-agent
EOF
sudo chmod 440 /etc/sudoers.d/aruba-agent-restart

# Validate before reloading systemd
sudo visudo -c -f /etc/sudoers.d/aruba-agent-restart
```

If the rule is missing, the dashboard hides the Restart button and
shows the manual command instead — settings still save correctly,
they just don't auto-apply.

---

## 13 — Verify

From a workstation on the same network:

```
https://<server-ip>/
```

Expect:

1. A browser warning about the self-signed cert. Click through, or
   import `/etc/pki/tls/certs/aruba-switch-manager.crt` into your
   workstation's trust store to silence it.
2. The login page appears.
3. **First login** — sign in as `admin` / `admin`. The agent ships
   with this default local account flagged "must change". You'll be
   redirected to the password-change page and required to pick a real
   password before reaching the dashboard. Local credentials are stored
   scrypt-hashed in `/var/lib/aruba-agent/users.json` (mode 0600).
4. **Subsequent logins** — local accounts continue to work, and if
   `[radius] enabled = true`, RADIUS works as a second auth path.
   Login order is local → RADIUS, so a RADIUS outage can't lock you out.
5. The dashboard loads with Switch Reachability, Config Backup,
   Network Scanner, and ARP Discovery cards. The sprocket icon in the
   navbar opens **Settings**, where you can edit Authentication
   (RADIUS + local users) and Email Alerts (SMTP + test send) directly
   from the browser. The other config sections (Switch Credentials,
   Scanner, Backup, ARP, Firmware, Web Server) are still edited via
   `/etc/aruba-agent/config.ini` until Phase B2 fills them in.

Confirm the audit trail:

```bash
sudo journalctl -u aruba-agent | grep -E "logged in|failed login|manual"
```

Confirm Apache is logging:

```bash
sudo tail /var/log/httpd/aruba-switch-manager_ssl_access.log
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `apachectl configtest` fails with `SSLCertificateFile: file '/etc/pki/tls/certs/localhost.crt' does not exist or is empty` | AlmaLinux 10's mod_ssl no longer auto-creates the dummy `localhost.crt`; the default `ssl.conf` then references a missing file | The current `install-apache.sh` patches this automatically. If you ran an older script: `sudo sed -i.bak -e 's\|^SSLCertificateFile.*\|SSLCertificateFile /etc/pki/tls/certs/aruba-switch-manager.crt\|' -e 's\|^SSLCertificateKeyFile.*\|SSLCertificateKeyFile /etc/pki/tls/private/aruba-switch-manager.key\|' /etc/httpd/conf.d/ssl.conf` then `apachectl configtest` |
| Browser shows the "AlmaLinux Test Page" instead of the dashboard login | Our vhost ServerName didn't match the URL you used; Apache fell through to the default `_default_:443` vhost or `welcome.conf` | Current `install-apache.sh` adds `ServerAlias *` and disables `welcome.conf` automatically. If you ran an older script: edit `/etc/httpd/conf.d/aruba-switch-manager.conf` and add `ServerAlias *` under both `ServerName` lines, then `sudo mv /etc/httpd/conf.d/welcome.conf{,.disabled}` and `sudo systemctl reload httpd` |
| Browser says `ERR_CONNECTION_REFUSED` on :443 | httpd not running, or firewall blocking 443 | `sudo systemctl status httpd`; `sudo firewall-cmd --list-all` |
| 502 Bad Gateway on the dashboard | Flask not running, or SELinux blocking httpd→localhost:8080 | `systemctl status aruba-agent`; `sudo setsebool -P httpd_can_network_connect 1` |
| "Authentication service is not configured" on login | `[radius] enabled` is false or server/secret missing | Edit `/etc/aruba-agent/config.ini`, then `systemctl restart aruba-agent` |
| All logins say "Invalid username or password" | NAS not authorized on RADIUS server, wrong shared secret, or PAP disabled | Check RADIUS server logs; verify `nas_identifier` and `secret` |
| Sessions die on every agent restart | `[web] secret_key` is blank | Generate one (step 7) and paste it in |
| ARP discovery rows stay empty | nmap missing, or router credentials wrong | `which nmap`; check `[arp.<location>]` |

---

## Updating

```bash
cd /tmp/Aruba-Network-Agent
sudo git pull
sudo rsync -a --delete aruba_agent/ /opt/aruba-agent/aruba_agent/
sudo rsync -a main.py requirements.txt /opt/aruba-agent/
sudo pip3 install -r /opt/aruba-agent/requirements.txt
sudo systemctl restart aruba-agent
```

`rsync -a --delete` is the preferred update command — it copies only
changed files and removes anything that was deleted from the repo so
no stale module shadows the newer one.

Apache + the cert do not need to change unless the vhost or scripts
themselves were updated.

---

## Uninstall

```bash
sudo systemctl disable --now aruba-agent
sudo rm /etc/systemd/system/aruba-agent.service
sudo rm /etc/httpd/conf.d/aruba-switch-manager.conf
sudo systemctl restart httpd
sudo rm -rf /opt/aruba-agent /var/lib/aruba-agent /etc/aruba-agent
sudo userdel aruba-agent
sudo rm -f /etc/pki/tls/certs/aruba-switch-manager.crt \
           /etc/pki/tls/private/aruba-switch-manager.key
```
