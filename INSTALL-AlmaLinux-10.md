# Install Guide — Clean AlmaLinux 10

End-to-end install of the Aruba Network Agent on a fresh AlmaLinux 10
server with HTTPS, RADIUS login, and an Apache2 reverse proxy.

Allow ~25 minutes start to finish.

---

## Quick start (one command)

If you trust the upstream repo and want the fastest path from blank VM
to working dashboard, run the bundled installer:

```bash
curl -fsSL https://raw.githubusercontent.com/LuckyBasartd/Aruba-Network-Agent/main/install.sh \
    | sudo bash
```

The script is idempotent — re-run it any time to upgrade an existing
install. It NEVER touches `/etc/aruba-agent/config.ini`,
`/etc/aruba-agent/master.key`, or `/var/lib/aruba-agent/*`, so your
state and secrets survive every upgrade.

When it finishes (~5 minutes on a fresh VM), it prints:

- The encryption master-key path with a big "back this up" reminder.
- A list of `config.ini` sections you should fill in.
- The dashboard URL (`https://<host>/`).
- Default first-login credentials (`admin` / `admin`, must change).

Want to customise the install? The script honours these environment
variables (all optional):

```bash
sudo REPO_REF=v3.0.1 \
     CERT_HOST=switches.example.local \
     SKIP_APACHE=1 \
     bash install.sh
```

Full list: `REPO_URL`, `REPO_REF`, `STAGING_DIR`, `INSTALL_DIR`,
`CONFIG_DIR`, `STATE_DIR`, `SVC_USER`, `SKIP_APACHE`, `SKIP_CERT`,
`CERT_HOST`. See the comment block at the top of `install.sh`.

The manual walkthrough below remains the source of truth for what the
script does — read it once if you're rolling this out to a fleet or
need to deviate from defaults.

---

## 0 — Prerequisites

You will need:

- A clean AlmaLinux 10 server with internet access (minimal install is fine).
- An account with `sudo`.
- The hostname or IP the dashboard will be reached at (used in the TLS cert).
- (Optional, recommended) A RADIUS server: IP, shared secret, and this
  host's IP allowlisted as a NAS.
- (Optional) SMTP relay credentials for email alerts.
- A GitHub account with read access to the repository.

```bash
# Confirm the OS, take a snapshot of useful info before starting
cat /etc/redhat-release
hostname -f
hostname -I
```

---

## 1 — System update and base packages

```bash
sudo dnf -y update
sudo dnf install -y \
    git python3 python3-pip nmap openssl \
    httpd mod_ssl firewalld policycoreutils-python-utils nano
sudo systemctl enable --now firewalld
```

`policycoreutils-python-utils` ships `semanage` / `setsebool`, used by
`install-apache.sh` to fix SELinux up so Apache can reach the Flask
backend on `127.0.0.1:8080`.

---

## 2 — Generate an SSH key for GitHub

GitHub turned off password auth for git operations in 2021. The cleanest
long-lived option is an SSH key dedicated to this host. (Personal Access
Tokens work too — covered at the end of this section.)

### 2a. Create the key

```bash
ssh-keygen -t ed25519 -C "aruba-agent@$(hostname -s)" -f ~/.ssh/aruba_agent_github -N ""
```

What each flag does:

- `-t ed25519` — modern curve; smaller and faster than RSA, supported by GitHub.
- `-C "aruba-agent@<host>"` — comment baked into the public key so you
  can recognise it later in the GitHub UI.
- `-f ~/.ssh/aruba_agent_github` — keep this key separate from any
  personal keys you may have on this host.
- `-N ""` — no passphrase. The key file itself is mode `600` and only
  this account can read it; a passphrase would block unattended pulls.
  If your security policy requires one, drop `-N ""` and you'll be
  prompted to set a passphrase (you'll then need `ssh-agent` for
  passwordless pulls).

The command produces two files:

```
~/.ssh/aruba_agent_github      # private key — NEVER share
~/.ssh/aruba_agent_github.pub  # public key  — paste into GitHub
```

### 2b. Tell SSH to use this key for github.com

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

`IdentitiesOnly yes` is the key line — without it, SSH offers every
private key it can find to GitHub, and after too many wrong offers
GitHub will reject the connection with "Too many authentication
failures."

### 2c. Add the public key to GitHub

Print it and copy to your clipboard:

```bash
cat ~/.ssh/aruba_agent_github.pub
```

In your browser:

1. GitHub → click your avatar → **Settings**.
2. Left sidebar → **SSH and GPG keys**.
3. **New SSH key**.
4. **Title**: something you'll recognise, e.g. `aruba-agent server`.
5. **Key type**: Authentication Key.
6. **Key**: paste the entire line you just `cat`-ed, starting with
   `ssh-ed25519 AAAA…` and ending with the comment you set.
7. **Add SSH key**. GitHub may ask you to re-enter your GitHub
   password to confirm.

### 2d. Test the connection

```bash
ssh -T git@github.com
```

Accept the host fingerprint prompt the first time (`yes`). A successful
auth replies with:

```
Hi <your-github-username>! You've successfully authenticated, but GitHub does not provide shell access.
```

That message is the success state — GitHub never offers a real shell.

### Plan B — Personal Access Token (PAT)

If you can't use SSH (egress firewall blocks port 22, corporate policy,
etc.), use an HTTPS clone with a PAT instead:

1. GitHub → Settings → Developer settings → Personal access tokens →
   **Tokens (classic)** → **Generate new token**.
2. Scope: `repo` (or `public_repo` if the repository is public).
3. Set an expiration you can live with — 90 days is a reasonable
   default; renew when it lapses.
4. Copy the token (`ghp_…`). You won't see it again.
5. Clone using HTTPS:

   ```bash
   git clone https://github.com/LuckyBasartd/Aruba-Network-Agent.git
   # Username:  your GitHub username (e.g. LuckyBasartd)
   # Password:  paste the ghp_… token
   ```

6. Optional — cache the token so subsequent pulls don't prompt:

   ```bash
   git config --global credential.helper store
   ```

   The token gets stored in plaintext at `~/.git-credentials` (mode 600).
   On a root-only deploy host that's acceptable; on a multi-user host
   prefer `credential.helper cache` (memory only) or SSH.

---

## 3 — Service account and directory tree

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

## 4 — Clone the repository

Using the SSH key you set up in step 2:

```bash
cd /tmp
git clone git@github.com:LuckyBasartd/Aruba-Network-Agent.git
cd Aruba-Network-Agent
git log --oneline -5
```

You should see recent v3.0.1 commits at the top of the log (encryption
+ dashboard search). If you used a PAT instead, clone the HTTPS URL:

```bash
cd /tmp
git clone https://github.com/LuckyBasartd/Aruba-Network-Agent.git
cd Aruba-Network-Agent
```

---

## 5 — Install application files

`rsync` is preferred over `cp -r` for both the initial install and
later updates: it copies only changed files, and `--delete` removes
anything that's no longer in the repo so stale `.py` files can't
linger in `/opt/aruba-agent` and shadow newer modules.

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

## 6 — Python dependencies

```bash
sudo pip3 install -r /opt/aruba-agent/requirements.txt
```

This installs `requests`, `urllib3`, `flask`, `waitress`, `scapy`,
`pyrad`, `pysnmp`, and `napalm`. The `cryptography` library used by
v3.0.1 secret storage comes in as a transitive dependency. If you ever
see a `cryptography` import error in the journal:

```bash
sudo pip3 install cryptography
```

---

## 7 — Permissions

```bash
sudo chown -R root:aruba-agent /opt/aruba-agent
sudo chmod -R 750              /opt/aruba-agent
sudo chown -R aruba-agent:aruba-agent /var/lib/aruba-agent
sudo chown -R aruba-agent:aruba-agent /etc/aruba-agent
```

`/etc/aruba-agent/` must be writable by the service account so the
agent can write `master.key` on first start and the Settings UI can
save config changes back to `config.ini`.

---

## 8 — Edit the config

```bash
sudo -u aruba-agent nano /etc/aruba-agent/config.ini
```

Minimum you'll want to touch on a fresh install:

- **`[credentials]`** — switch admin username + password (used as defaults across vendors).
- **`[smtp]`** — `enabled = true` + host/port/from/to if you want email alerts.
- **`[web]`**
  - `secret_key`         = leave blank for now; the Settings page can
                           generate one later. Or run
                           `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`
                           and paste.
  - `host`               = `127.0.0.1` (Apache fronts it — don't change).
  - `secure_cookies`     = `true`
  - `trust_proxy_headers` = `true`
- **`[radius]`** (optional) — `enabled = true`, server IP, shared secret,
  `nas_identifier`. Register this host on the RADIUS server with the
  matching secret.
- **`[scanner]`** — comma-separated CIDRs for `subnets`.
- **`[arp.<location>]`** — one block per campus location with router IPs.

Save and exit. **Don't worry about encrypting the password fields
yourself** — the agent will auto-encrypt every cleartext value on first
start.

---

## 9 — Generate the TLS certificate

```bash
cd /tmp/Aruba-Network-Agent
sudo ./scripts/generate-self-signed-cert.sh
```

The script auto-detects this host's hostname and primary IP and writes
both into the cert's SANs, so the obvious access paths are covered
without further config. To pin a specific hostname:

```bash
sudo ./scripts/generate-self-signed-cert.sh switches.example.local
```

Output lands at `/etc/pki/tls/certs/aruba-switch-manager.crt` and
`/etc/pki/tls/private/aruba-switch-manager.key`.

---

## 10 — Install Apache + reverse proxy

```bash
sudo ./scripts/install-apache.sh
```

The script handles every AlmaLinux 10 quirk in one shot:

1. Installs `httpd` + `mod_ssl` (idempotent — safe to re-run).
2. Patches the stock `ssl.conf` to point at the agent cert (AlmaLinux 10
   stopped shipping the `localhost.crt` placeholder).
3. Disables `welcome.conf` so the "AlmaLinux Test Page" doesn't shadow
   your vhost.
4. Drops `/etc/httpd/conf.d/aruba-switch-manager.conf` into place with
   `ServerAlias *` so the vhost matches every hostname/IP you might hit
   it on.
5. Sets `setsebool -P httpd_can_network_connect 1` so SELinux lets
   Apache talk to Flask on `127.0.0.1:8080`.
6. Opens TCP/443 in firewalld and removes any leftover TCP/8080 rule.
7. Runs `apachectl configtest` and refuses to start with a broken
   config.

If `configtest` fails, the script stops and prints the error — fix it
before continuing.

---

## 11 — Allow the Settings → Restart Now button (optional but recommended)

The Settings page has a **Restart Agent** button that shells out to
`systemctl restart aruba-agent` via sudo. The rule:

```bash
sudo tee /etc/sudoers.d/aruba-agent-restart > /dev/null <<'EOF'
# Allow the aruba-agent service account to restart its own service
# from the web UI. No other systemctl operations are permitted.
aruba-agent ALL=(root) NOPASSWD: /bin/systemctl restart aruba-agent
EOF
sudo chmod 440 /etc/sudoers.d/aruba-agent-restart
sudo visudo -c -f /etc/sudoers.d/aruba-agent-restart
```

Without this rule, the dashboard hides the Restart button and prints
the manual `systemctl` command instead — config still saves correctly,
it just doesn't auto-apply.

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
Migrate: encrypted N field(s) in /etc/aruba-agent/config.ini: [credentials] password, [smtp] password, ...
Switch poller: SNMPv3 reachability ENABLED      (or REST fallback if [snmp] is not configured)
Web UI: local authentication enabled
Web UI: ProxyFix enabled — trusting one upstream proxy hop
Aruba agent running (PID …)
```

Ctrl-C out of the journal tail.

---

## 13 — Back up the master key

This is the only step in the whole install that's truly irreversible.
If you lose `master.key`, every encrypted password in `config.ini`
becomes unrecoverable and you'll have to re-enter them through the
Settings UI.

```bash
sudo ls -la /etc/aruba-agent/master.key
sudo cp /etc/aruba-agent/master.key /root/master.key.backup-$(date +%F)
```

Expected ownership: `-rw------- 1 aruba-agent aruba-agent`.

Move the backup copy somewhere off this host — a password manager, an
encrypted USB stick, your team's secrets vault, a sealed envelope in a
safe. Whatever your org's standard is for "single small file that
cannot leak and cannot be lost."

Once you've confirmed the agent decrypts cleanly across a restart
(next step), you can also delete `/etc/aruba-agent/config.ini.bak` so
the cleartext copy isn't sitting on disk indefinitely:

```bash
sudo rm /etc/aruba-agent/config.ini.bak
```

---

## 14 — Verify

From a workstation on the same network:

```
https://<server-ip>/
```

Walk through:

1. Browser warns about the self-signed cert — click through, or import
   `/etc/pki/tls/certs/aruba-switch-manager.crt` into your workstation's
   trust store to silence it.
2. The login page appears.
3. Sign in as `admin` / `admin`. The agent ships this default account
   flagged "must change". You'll be redirected to a password-change
   page and required to pick a real password before reaching the
   dashboard. Local credentials are scrypt-hashed in
   `/var/lib/aruba-agent/users.json` (mode 0600).
4. The dashboard loads with Switch Reachability, Config Backup, Network
   Scanner, and ARP Discovery cards. The search box above the Switch
   Reachability table narrows by name / hostname / IP as you type.
5. Open Settings (sprocket icon) → **Email Alerts** → click "Send test
   email" to confirm SMTP works.
6. Settings → **SNMPv3** → "Test profile" against a switch IP to confirm
   SNMP credentials, if you've configured any.

Smoke tests on the host:

```bash
sudo journalctl -u aruba-agent | grep -E "logged in|failed login|Migrate"
sudo tail /var/log/httpd/aruba-switch-manager_ssl_access.log
```

Restart once to confirm encrypted secrets round-trip cleanly:

```bash
sudo systemctl restart aruba-agent
sudo journalctl -u aruba-agent -n 50 --no-pager | grep -iE "error|migrate|enabled"
```

You should see
`Migrate: every sensitive field already encrypted — nothing to do` —
that confirms the secrets layer is healthy and there's nothing left to
encrypt.

---

## Prometheus scraping (optional)

The agent exposes a Prometheus `/metrics` endpoint with switch
reachability, backup/scanner/ARP run ages, and login counters. Two
deployment modes:

**Open (trusted LAN)** — leave `[web] metrics_token` blank. Prometheus
scrapes `https://<host>/metrics` directly. Apache's TLS still applies.

**Authenticated** — set `[web] metrics_token` to a long random string
(the agent encrypts it at rest like every other secret):

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

Useful queries to drop into Grafana:

- `aruba_switches_down` — gauge of unreachable switches right now.
- `aruba_backup_last_run_age_seconds / 3600` — hours since the last
  backup ran (alert if > 26).
- `rate(aruba_login_failures_total[5m])` — login-failure rate.
  Sustained > 0.1/sec is a brute-force signal.
- `aruba_arp_last_run_age_seconds{location="hq"} / 3600` — hours
  since the per-location ARP discovery last ran.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ssh -T git@github.com` says "Permission denied (publickey)" | Public key wasn't added to GitHub, or `~/.ssh/config` doesn't point at the right key | Re-check step 2c (paste the entire line from the `.pub` file). Then `ssh -vT git@github.com` and look for "Offering public key" — the path should match your config |
| `git clone` says "Too many authentication failures" | SSH is offering every key it has; GitHub rejected after the limit | Ensure `IdentitiesOnly yes` is in `~/.ssh/config` for `Host github.com` |
| `ModuleNotFoundError: No module named 'aruba_agent.notifier'` | rsync didn't run after a `git pull` | `cd /tmp/Aruba-Network-Agent && sudo rsync -a --delete aruba_agent/ /opt/aruba-agent/aruba_agent/ && sudo systemctl restart aruba-agent` |
| `Could not initialise secret manager at /etc/aruba-agent/master.key` | `/etc/aruba-agent/` not writable by the agent | `sudo chown -R aruba-agent:aruba-agent /etc/aruba-agent` |
| `Could not decrypt a stored secret` | `master.key` was replaced after config was encrypted | Restore the original key from your backup. If lost: delete `master.key` and re-enter every password through Settings |
| Browser shows the "AlmaLinux Test Page" | Apache fell through to `welcome.conf` | `install-apache.sh` already handles this; if you ran an older script: `sudo mv /etc/httpd/conf.d/welcome.conf{,.disabled} && sudo systemctl reload httpd` |
| `apachectl configtest` complains about `localhost.crt` | AlmaLinux 10 mod_ssl no longer ships the dummy cert | Rerun `sudo ./scripts/install-apache.sh` — current version patches this |
| 502 Bad Gateway on the dashboard | Flask not running, OR SELinux blocking httpd → localhost:8080 | `sudo systemctl status aruba-agent` and `sudo setsebool -P httpd_can_network_connect 1` |
| Sessions invalidated on every agent restart | `[web] secret_key` is blank | Generate one or open Settings → Web Server → "Regenerate secret_key" |
| ARP discovery rows stay empty | `nmap` missing, or router credentials wrong | `which nmap` and verify `[arp.<location>]` |

---

## Updating later

```bash
cd /tmp/Aruba-Network-Agent
sudo git pull
sudo rsync -a --delete aruba_agent/ /opt/aruba-agent/aruba_agent/
sudo rsync -a main.py requirements.txt /opt/aruba-agent/
sudo pip3 install -r /opt/aruba-agent/requirements.txt
sudo systemctl restart aruba-agent
sudo journalctl -u aruba-agent -n 30 --no-pager
```

The master key persists across updates — no re-migration prompts on
subsequent restarts. Apache and the TLS cert only need touching if
`apache/aruba-switch-manager.conf` or `scripts/install-apache.sh`
themselves changed.

---

## Uninstall

```bash
sudo systemctl disable --now aruba-agent
sudo rm /etc/systemd/system/aruba-agent.service
sudo rm /etc/httpd/conf.d/aruba-switch-manager.conf
sudo systemctl restart httpd

# Wipe runtime state, config, and the encryption key.
# Make sure you no longer need any of this first.
sudo rm -rf /opt/aruba-agent /var/lib/aruba-agent /etc/aruba-agent

sudo userdel aruba-agent

# TLS material
sudo rm -f /etc/pki/tls/certs/aruba-switch-manager.crt \
           /etc/pki/tls/private/aruba-switch-manager.key

# Sudoers carve-out
sudo rm -f /etc/sudoers.d/aruba-agent-restart

# Optional: remove the SSH key from this host (the public side stays
# on GitHub until you delete it there too)
rm -f ~/.ssh/aruba_agent_github ~/.ssh/aruba_agent_github.pub
```
