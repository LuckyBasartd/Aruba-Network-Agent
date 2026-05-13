# Install Guide — Clean AlmaLinux 10

End-to-end install of the Aruba Network Agent on a fresh AlmaLinux 10
server with HTTPS, RADIUS login, and an nginx reverse proxy (Apache
also supported — see the appendix).

Allow ~25 minutes start to finish.

> **For sysadmin-managed hosts:** if your config-management already
> handles OS updates, base package installs, and TLS/reverse-proxy
> provisioning, you can skip the steps marked **[CFGMGMT]** and use
> only the application-layer steps. Both kinds of step are flagged
> inline.

---

## 0 — Prerequisites

You will need:

- A clean AlmaLinux 10 server with internet access (minimal install is
  fine), with system packages already up to date.
- An account with `sudo`.
- The hostname or IP the dashboard will be reached at.
- (Optional, recommended) A RADIUS server: IP, shared secret, and this
  host's IP allowlisted as a NAS.
- (Optional) SMTP relay credentials for email alerts.
- A GitHub account with admin access to the repository (to add a
  deploy key).

```bash
# Confirm the OS, take a snapshot of useful info before starting
cat /etc/redhat-release
hostname -f
hostname -I
```

---

## 1 — Base packages **[CFGMGMT — skip if your sysadmin handles it]**

Base OS packages the agent needs. If your config-management already
keeps these in place, skip to step 2.

```bash
sudo dnf -y update
sudo dnf install -y \
    git python3 python3-pip python3-virtualenv \
    nmap openssl rsync nano \
    policycoreutils-python-utils firewalld
sudo systemctl enable --now firewalld
```

`policycoreutils-python-utils` provides `semanage` / `setsebool` used
by the SELinux step later.

The reverse-proxy daemon (`nginx` or `httpd` + `mod_ssl`) is in step 8
since you may already have one running.

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
    /var/lib/aruba-agent/firmware \
    /var/log/aruba-agent
```

---

## 3 — Set up a GitHub deploy key

The agent's code is pulled from a private GitHub repository using a
read-only SSH deploy key scoped to **that repository only**. This is
safer than using a personal account's key, which would give access to
all your repositories and could be disrupted if the account changes
or the person leaves.

All commands in this section should be run as a dedicated deployment
user (or `root`), **not your personal account**. A personal account
that rotates keys or leaves the team takes the agent host's git
access with it.

### 3a. Configure SSH to use the deploy key

Create (or append to) `~/.ssh/config` so SSH automatically selects
the right key for GitHub:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat >> ~/.ssh/config <<'EOF'
# Aruba Network Agent — deploy key for the upstream repo
Host github.com
    HostName        github.com
    User            git
    IdentityFile    ~/.ssh/aruba_agent_github
    IdentitiesOnly  yes
EOF
chmod 600 ~/.ssh/config
```

`IdentitiesOnly yes` is critical — without it, SSH offers every
private key it can find to GitHub, and after too many wrong offers
GitHub will reject the connection with "Too many authentication
failures."

### 3b. Create the key

```bash
ssh-keygen -t ed25519 -C "aruba-agent@$(hostname -s)" \
           -f ~/.ssh/aruba_agent_github -N ""
```

Flag-by-flag:

- `-t ed25519` — modern curve; smaller and faster than RSA, supported
  by GitHub.
- `-C "aruba-agent@<host>"` — comment baked into the public key so
  you can recognise it later.
- `-f ~/.ssh/aruba_agent_github` — keeps this key separate from any
  personal keys on this host.
- `-N ""` — no passphrase. The key file is mode 600 and only this
  account can read it; a passphrase would block unattended pulls.

The command produces two files:

```
~/.ssh/aruba_agent_github      # private key — NEVER share
~/.ssh/aruba_agent_github.pub  # public key — paste into GitHub
```

### 3c. Add the public key as a **repository deploy key**

Print the public key and copy it to your clipboard:

```bash
cat ~/.ssh/aruba_agent_github.pub
```

In your browser:

1. Go to the repository on GitHub (e.g.
   `https://github.com/LuckyBasartd/Aruba-Network-Agent`).
2. Click **Settings** → **Deploy keys** (left sidebar, under
   "Security").
3. Click **Add deploy key**.
4. **Title**: something you'll recognise, e.g. `aruba-agent server`.
5. **Key**: paste the entire line you just `cat`-ed, starting with
   `ssh-ed25519 AAAA…`.
6. **Leave "Allow write access" unchecked** — this key only pulls.
7. Click **Add key**.

Deploy keys are scoped to this single repo and can be revoked
independently of any user account.

### 3d. Test the connection

```bash
ssh -T git@github.com
```

Accept the host fingerprint prompt the first time (`yes`). A
successful auth replies with:

```
Hi <repo-owner>! You've successfully authenticated, but GitHub does not provide shell access.
```

(For deploy keys, GitHub greets the repo's owner rather than your
personal username.) The message itself is the success state — GitHub
never offers a real shell.

---

## 4 — Clone the repository

Clone into a stable working directory **outside `/tmp`** (files there
can be read or tampered with by other local users and may be cleared
on reboot):

```bash
sudo mkdir -p /opt/aruba-agent-src
sudo chown "$(whoami)":"$(whoami)" /opt/aruba-agent-src
cd /opt/aruba-agent-src
git clone git@github.com:LuckyBasartd/Aruba-Network-Agent.git
cd Aruba-Network-Agent
git log --oneline -5
```

You should see the latest release commit at the top of the log.

---

## 5 — Install application files

`rsync` is preferred over `cp -r` for both the initial install and
later updates: it copies only changed files, and `--delete` removes
anything no longer in the repo so stale `.py` files can't linger in
`/opt/aruba-agent` and shadow newer modules.

```bash
cd /opt/aruba-agent-src/Aruba-Network-Agent

# Code
sudo rsync -a --delete aruba_agent/ /opt/aruba-agent/aruba_agent/
sudo rsync -a main.py requirements.txt /opt/aruba-agent/

# The systemd ExecStart wrapper — picks venv vs system python at
# runtime. Lives in /opt/aruba-agent/bin/ so the systemd unit can
# stay stable across deploys.
sudo install -d -m 755 /opt/aruba-agent/bin
sudo install -m 755 scripts/aruba-agent-wrapper.sh \
    /opt/aruba-agent/bin/aruba-agent

# Config template — secured because it will hold credentials.
# The real config.ini is gitignored; the repo ships config.ini.example.
# Owned by aruba-agent so the Settings page can write back to it.
sudo install -m 640 -o aruba-agent -g aruba-agent \
    config.ini.example /etc/aruba-agent/config.ini

# Subnet lists for ARP discovery (if you have any)
[ -d subnets ] && sudo rsync -a subnets/ /etc/aruba-agent/subnets/ || true

# Systemd unit
sudo rsync -a aruba-agent.service /etc/systemd/system/

# logrotate.d rule for the audit log
sudo install -m 644 scripts/aruba-agent.logrotate \
    /etc/logrotate.d/aruba-agent

# Optional but recommended: daily backup-integrity cron
sudo install -m 755 scripts/aruba-agent-verify-backups.cron \
    /etc/cron.daily/aruba-agent-verify-backups
```

---

## 6 — Python dependencies (virtual environment)

**Never run `pip` as root against the system Python.** Doing so can
corrupt system packages that the OS depends on. The agent installs
into a virtual environment owned by root and consumed by the service
account.

```bash
# Create the venv inside the application directory
sudo python3 -m venv /opt/aruba-agent/venv

# Install dependencies into the venv (no root-as-pip, no system-wide changes)
sudo /opt/aruba-agent/venv/bin/pip install --upgrade pip
sudo /opt/aruba-agent/venv/bin/pip install \
     -r /opt/aruba-agent/requirements.txt
```

This installs `requests`, `urllib3`, `flask`, `flask-wtf`, `waitress`,
`scapy`, `pyrad`, `pysnmp<6.2`, `napalm`, `prometheus-client`,
`pyotp`, and `qrcode`. The `cryptography` library used by the
secret-storage layer comes in as a transitive dependency.

The systemd unit's `ExecStart` points at
`/opt/aruba-agent/bin/aruba-agent`, which picks
`/opt/aruba-agent/venv/bin/python` automatically when the venv
exists. No further unit edits are needed.

---

## 7 — Permissions

```bash
sudo chown -R root:aruba-agent /opt/aruba-agent
sudo chmod -R 750              /opt/aruba-agent
sudo chown -R aruba-agent:aruba-agent /var/lib/aruba-agent
sudo chown -R aruba-agent:aruba-agent /etc/aruba-agent
sudo chown -R aruba-agent:aruba-agent /var/log/aruba-agent
sudo chmod 750 /var/log/aruba-agent
```

`/etc/aruba-agent/` must be writable by the service account so the
agent can write `master.key` on first start and the Settings UI can
save config changes back to `config.ini`. `/var/log/aruba-agent/`
holds the audit log written by the agent.

---

## 8 — Edit the config

```bash
sudo -u aruba-agent nano /etc/aruba-agent/config.ini
```

Minimum settings to touch on a fresh install:

- **`[credentials]`** — switch admin username + password (used as
  defaults across vendors).
- **`[smtp]`** — `enabled = true` + host/port/from/to if you want
  email alerts.
- **`[web]`**
  - `secret_key` — leave blank for now; the Settings page can
    generate one later. Or run
    `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`
    and paste.
  - `host = 127.0.0.1` (the reverse proxy fronts it — don't change).
  - `secure_cookies = true`
  - `trust_proxy_headers = true`
- **`[radius]`** (optional) — `enabled = true`, server IP, shared
  secret, `nas_identifier`. Register this host on the RADIUS server
  with the matching secret.
- **`[scanner]`** — comma-separated CIDRs for subnets.
- **`[arp.<location>]`** — one block per campus location with router
  IPs.

Save and exit. Don't worry about encrypting the password fields
yourself — the agent will auto-encrypt every cleartext value on first
start.

---

## 9 — TLS certificate **[CFGMGMT — skip if your sysadmin handles TLS]**

If your team provisions TLS certs centrally, skip this step and make
sure your cert is in place where the reverse-proxy expects it
(default: `/etc/pki/tls/certs/aruba-switch-manager.crt` +
`/etc/pki/tls/private/aruba-switch-manager.key`).

Otherwise, generate a self-signed cert for testing or internal-only
deployments:

```bash
cd /opt/aruba-agent-src/Aruba-Network-Agent
sudo ./scripts/generate-self-signed-cert.sh
```

To pin a specific hostname:

```bash
sudo ./scripts/generate-self-signed-cert.sh switches.example.local
```

---

## 10 — Reverse proxy: nginx **[CFGMGMT — your sysadmin may handle this]**

The agent ships drop-in vhosts for both nginx (recommended) and
Apache. If your team handles the reverse-proxy layer separately,
point your existing config at `127.0.0.1:8080` and add the security
headers from the shipped vhost; otherwise:

```bash
# Install nginx if not already present
sudo dnf install -y nginx
sudo systemctl enable --now nginx

# Drop in the vhost
sudo install -m 644 nginx/aruba-switch-manager.conf \
    /etc/nginx/conf.d/aruba-switch-manager.conf

# SELinux: allow nginx to reach the Flask backend on 127.0.0.1:8080
sudo setsebool -P httpd_can_network_connect 1

# Firewall: open 443, close 8080 if it ever got opened
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --remove-port=8080/tcp 2>/dev/null || true
sudo firewall-cmd --reload

# Validate and reload
sudo nginx -t && sudo systemctl reload nginx
```

For Apache instead, see [Appendix A — Apache](#appendix-a--apache).

Both vhosts set HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Content-Security-Policy, Cache-Control: no-store,
and Permissions-Policy headers. Hardening that's hard to get back
later if you forget to bake it in now.

---

## 11 — Allow the Settings → Restart Now button (optional but recommended)

The Settings page has a **Restart Agent** button that calls
`systemctl restart aruba-agent` via `sudo`. Without this rule, the
dashboard hides the button and prints the manual command instead —
config still saves correctly, it just doesn't auto-apply.

```bash
sudo tee /etc/sudoers.d/aruba-agent-restart > /dev/null <<'EOF'
# Allow the aruba-agent service account to restart its own service
# from the web UI. No other systemctl operations are permitted.
aruba-agent ALL=(root) NOPASSWD: /bin/systemctl restart aruba-agent
EOF
sudo chmod 440 /etc/sudoers.d/aruba-agent-restart
sudo visudo -c -f /etc/sudoers.d/aruba-agent-restart
```

---

## 12 — Start the agent

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aruba-agent
sudo journalctl -u aruba-agent -f
```

On the first boot you should see, in order:

```
No master key at /etc/aruba-agent/master.key — generating a new one. ...
Migrate: wrote one-time backup of /etc/aruba-agent/config.ini to /etc/aruba-agent/config.ini.bak
Migrate: encrypted N field(s) in /etc/aruba-agent/config.ini: [credentials] password, ...
Switch poller: SNMPv3 reachability ENABLED      (or REST fallback)
Web UI: local authentication enabled
Web UI: ProxyFix enabled — trusting one upstream proxy hop
Aruba agent running (PID …)
```

`Ctrl-C` out of the journal tail.

---

## 13 — Back up the master key

**The only truly irreversible step in the install.** Losing
`master.key` means every encrypted password becomes unrecoverable.

```bash
sudo ls -la /etc/aruba-agent/master.key
sudo cp /etc/aruba-agent/master.key /root/master.key.backup-$(date +%F)
```

Expected ownership: `-rw------- 1 aruba-agent aruba-agent`.

Move the backup copy somewhere off this host — password manager,
encrypted USB, your team's secrets vault. Once you've confirmed the
agent decrypts cleanly across a restart, delete the plaintext config
backup:

```bash
sudo rm /etc/aruba-agent/config.ini.bak
```

See [DISASTER-RECOVERY.md](DISASTER-RECOVERY.md) for the recovery
recipes if anything ever goes sideways.

---

## 14 — Optional: configure verify-backups notifications

The cron job installed in step 5 runs `--verify-backups` daily. To
get emailed when corruption is detected, list recipients (one per
line) in `/etc/aruba-agent/verify-backups.notify`:

```bash
sudo tee /etc/aruba-agent/verify-backups.notify > /dev/null <<EOF
noc@example.com
admin@example.com
EOF
sudo chown aruba-agent:aruba-agent /etc/aruba-agent/verify-backups.notify
sudo chmod 640 /etc/aruba-agent/verify-backups.notify
```

The script uses `mail(1)` — install `s-nail` or `mailx` if you don't
already have it.

---

## 15 — Verify

From a workstation on the same network:

```
https://<server-ip>/
```

Walk through:

1. The login page appears. (Browser may warn about the cert
   depending on your TLS setup.)
2. Sign in as `admin` / `admin`. The agent ships this default
   account flagged "must change". You'll be redirected to a
   password-change page before reaching the dashboard. Credentials
   are scrypt-hashed in `/var/lib/aruba-agent/users.json` (mode 0600).
3. The dashboard loads. The search box above the Switch Reachability
   table narrows by name / hostname / IP as you type.
4. Open Settings (sprocket icon) → **Email Alerts** → "Send test
   email" to confirm SMTP.
5. Settings → **SNMPv3** → "Test profile" against a switch IP to
   confirm SNMP credentials.
6. (Optional) Settings → **Two-Factor Auth** → "Begin enrolment" to
   add TOTP 2FA. Save the recovery codes off-host.
7. (Optional) Settings → **API Tokens** → "Mint token" to script the
   agent from CI / Grafana.

Smoke tests on the host:

```bash
sudo journalctl -u aruba-agent | grep -E "logged in|failed login|Migrate"
sudo tail -f /var/log/aruba-agent/audit.log    # leave this running
                                                # in another shell
sudo tail /var/log/nginx/aruba-switch-manager_ssl_access.log
```

Restart once to confirm encrypted secrets round-trip cleanly:

```bash
sudo systemctl restart aruba-agent
sudo journalctl -u aruba-agent -n 50 --no-pager | grep -iE "error|migrate|enabled"
```

You should see
`Migrate: every sensitive field already encrypted — nothing to do`.

Run the integrity check manually once so you know what success
looks like:

```bash
sudo /etc/cron.daily/aruba-agent-verify-backups
echo "exit status: $?"        # should be 0 if no .cfg.enc files exist yet
```

---

## Prometheus scraping (optional)

The agent exposes a Prometheus `/metrics` endpoint with switch
reachability, backup/scanner/ARP run ages, and login counters.

Open (trusted LAN): leave `[web] metrics_token` blank — Prometheus
scrapes `https://<host>/metrics` directly.

Authenticated: set `[web] metrics_token` to a long random string
(the agent encrypts it at rest):

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: aruba-agent
    metrics_path: /metrics
    scheme: https
    tls_config:
      insecure_skip_verify: true     # self-signed cert
    authorization:
      type: Bearer
      credentials: <paste the same string from config.ini>
    static_configs:
      - targets: ["arubaagent.example.local"]
```

Useful Grafana queries:

- `aruba_switches_down` — gauge of unreachable switches.
- `aruba_backup_last_run_age_seconds / 3600` — hours since last
  backup ran (alert if > 26).
- `rate(aruba_login_failures_total[5m])` — login-failure rate.
  Sustained > 0.1/sec is a brute-force signal.
- `aruba_arp_last_run_age_seconds{location="hq"} / 3600` — hours
  since the per-location ARP run.

---

## Updating

```bash
cd /opt/aruba-agent-src/Aruba-Network-Agent
sudo git pull
sudo rsync -a --delete aruba_agent/ /opt/aruba-agent/aruba_agent/
sudo rsync -a main.py requirements.txt /opt/aruba-agent/
sudo install -m 755 scripts/aruba-agent-wrapper.sh \
    /opt/aruba-agent/bin/aruba-agent
sudo /opt/aruba-agent/venv/bin/pip install \
    --upgrade -r /opt/aruba-agent/requirements.txt
sudo systemctl restart aruba-agent
sudo journalctl -u aruba-agent -n 30 --no-pager
```

Master key persists across updates — no re-migration prompts.

---

## Uninstall

```bash
sudo systemctl disable --now aruba-agent
sudo rm /etc/systemd/system/aruba-agent.service
sudo systemctl daemon-reload

# Wipe runtime state, config, and the encryption key.
# Make sure you no longer need any of this first.
sudo rm -rf /opt/aruba-agent /opt/aruba-agent-src \
            /var/lib/aruba-agent /etc/aruba-agent /var/log/aruba-agent

# Reverse-proxy vhost (whichever you used)
sudo rm -f /etc/nginx/conf.d/aruba-switch-manager.conf
sudo rm -f /etc/httpd/conf.d/aruba-switch-manager.conf

# Cron + logrotate + sudoers
sudo rm -f /etc/cron.daily/aruba-agent-verify-backups \
           /etc/logrotate.d/aruba-agent \
           /etc/sudoers.d/aruba-agent-restart

sudo userdel aruba-agent

# Optional: remove the deploy SSH key from this host. The public side
# stays on GitHub until you remove it under repo → Settings → Deploy keys.
rm -f ~/.ssh/aruba_agent_github ~/.ssh/aruba_agent_github.pub
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ssh -T git@github.com` says "Permission denied (publickey)" | Public key wasn't added as a deploy key, or `~/.ssh/config` doesn't point at the right key | Re-check step 3c. `ssh -vT git@github.com` and look for "Offering public key" — the path should match your config |
| `git clone` says "Too many authentication failures" | SSH is offering every key it has; GitHub rejected after the limit | Ensure `IdentitiesOnly yes` is in `~/.ssh/config` for `Host github.com` |
| `ModuleNotFoundError: No module named 'aruba_agent.notifier'` | rsync didn't run after a git pull | Re-run the `rsync` lines from step 5 + restart |
| `Could not initialise secret manager at /etc/aruba-agent/master.key` | `/etc/aruba-agent/` not writable by the agent | `sudo chown -R aruba-agent:aruba-agent /etc/aruba-agent` |
| `Could not decrypt a stored secret` | `master.key` was replaced after config was encrypted | See [DISASTER-RECOVERY.md §1](DISASTER-RECOVERY.md) |
| 502 Bad Gateway | Flask not running OR SELinux blocking the reverse proxy → localhost:8080 | `sudo systemctl status aruba-agent`; `sudo setsebool -P httpd_can_network_connect 1` |
| Sessions invalidated on every agent restart | `[web] secret_key` is blank | Generate one or open Settings → Web Server → "Regenerate secret_key" |
| ARP discovery rows stay empty | `nmap` missing, or router credentials wrong | `which nmap`; verify `[arp.<location>]` |
| Login locked out with "Too many failed attempts" | Rate limiter active (5 fails / 15 min) | Wait 15 min, or restart the agent to clear the in-memory counters |
| Browser sees "your connection is not private" | Self-signed cert | Add the cert to your trust store, or use a real CA-signed cert |

---

## Appendix A — Apache

If your team standardises on Apache instead of nginx, the agent
ships a parallel vhost at `apache/aruba-switch-manager.conf` and an
installer script:

```bash
cd /opt/aruba-agent-src/Aruba-Network-Agent
sudo dnf install -y httpd mod_ssl
sudo ./scripts/install-apache.sh
```

The script:

1. Installs `httpd` + `mod_ssl` (idempotent).
2. Patches `ssl.conf` to point at the agent cert (AlmaLinux 10 no
   longer ships a `localhost.crt` placeholder).
3. Disables `welcome.conf` so the AlmaLinux test page doesn't shadow
   the vhost.
4. Drops `/etc/httpd/conf.d/aruba-switch-manager.conf` with
   `ServerAlias *`.
5. Sets `httpd_can_network_connect` for SELinux.
6. Opens 443 in firewalld; removes any leftover 8080 rule.
7. Validates the config and restarts httpd.

Both vhosts ship the same security headers; pick whichever matches
your shop's standards.
