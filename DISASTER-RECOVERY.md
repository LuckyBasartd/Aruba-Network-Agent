# Disaster Recovery Runbook

Short recipes for the five "I can't get into my agent" scenarios that
locking yourself out of the encryption / auth layers can produce.

Every recipe assumes you have root on the agent host. If you've lost
root too, you're in a different runbook — restore from backups.

All commands here are non-destructive unless explicitly called out.
Read the whole section before you start typing.

---

## 1 — Lost / destroyed `master.key`

**Symptom.** Agent boots but the journal floods with
`Could not decrypt a stored secret` warnings, and the dashboard / RADIUS /
SMTP / SNMP all fail with "authentication" errors.

**Why this happens.** `/etc/aruba-agent/master.key` is the Fernet key
that encrypts every sensitive field in `config.ini` plus every
`.cfg.enc` backup file. If it's deleted, replaced, or restored from a
mismatched snapshot, the agent has the ciphertext but no way to read it.

**If you have a backup of the original key:**

```bash
# 1. Stop the agent so it doesn't keep retrying with the wrong key.
sudo systemctl stop aruba-agent

# 2. Put the backup in place. Match ownership + mode exactly.
sudo install -m 600 -o aruba-agent -g aruba-agent \
     /path/to/your/master.key.backup /etc/aruba-agent/master.key

# 3. Start the agent and watch the migration message.
sudo systemctl start aruba-agent
sudo journalctl -u aruba-agent -n 50 | grep -iE "Migrate|decrypt"
```

If `journalctl` shows `Migrate: every sensitive field already encrypted
— nothing to do`, you're done. Existing `.cfg.enc` backups are now
decryptable again.

**If the backup is also lost — accept the reset:**

```bash
sudo systemctl stop aruba-agent

# 1. Move the broken key aside.
sudo mv /etc/aruba-agent/master.key{,.broken-$(date +%F)}

# 2. Restore config.ini from its plaintext backup (kept once, on the
#    very first start after v3.0.1 was deployed):
sudo ls /etc/aruba-agent/config.ini.bak                       # confirm it exists
sudo cp /etc/aruba-agent/config.ini.bak /etc/aruba-agent/config.ini
sudo chown aruba-agent:aruba-agent /etc/aruba-agent/config.ini
sudo chmod 640 /etc/aruba-agent/config.ini

# 3. Start the agent — it generates a fresh master.key and re-encrypts
#    every cleartext value from the restored config.
sudo systemctl start aruba-agent
sudo cp /etc/aruba-agent/master.key /root/master.key.backup-$(date +%F)
```

If `config.ini.bak` is also gone, you're down to manually re-entering
every password in the Settings UI. Encrypted backup files
(`.cfg.enc`) can no longer be decrypted in that case — keep them
around in case you ever recover the original key, but treat them as
unreadable for now.

---

## 2 — Forgotten password / locked-out admin

**Symptom.** The login page rejects every attempt; the only local user
either has no working password or you've forgotten it.

```bash
# 1. Inspect the user store.
sudo cat /var/lib/aruba-agent/users.json

# 2. Strip the broken user out. Replace the WHOLE users.json with a
#    bootstrap admin/admin entry (mode 0600). The agent will treat it
#    as if it were a clean install and force a must_change on first
#    login.
sudo systemctl stop aruba-agent
sudo cp /var/lib/aruba-agent/users.json /var/lib/aruba-agent/users.json.bak
sudo tee /var/lib/aruba-agent/users.json > /dev/null <<'EOF'
{ "users": [] }
EOF
sudo chown aruba-agent:aruba-agent /var/lib/aruba-agent/users.json
sudo chmod 600 /var/lib/aruba-agent/users.json
sudo systemctl start aruba-agent
```

Log in as `admin` / `admin`. You'll be forced to set a new password
immediately. Recreate any other operator accounts from Settings →
Authentication.

---

## 3 — Lost 2FA device AND recovery codes

**Symptom.** You enrolled in TOTP 2FA, then lost the device, and the
ten one-time recovery codes printed at enrolment are also gone.

```bash
# 1. SSH to the host and edit the user store.
sudo systemctl stop aruba-agent
sudo cp /var/lib/aruba-agent/users.json /var/lib/aruba-agent/users.json.bak

# 2. Use jq (or your editor) to strip the totp_* keys from your user.
#    The 'totp_secret', 'totp_recovery', and 'totp_enrolled' fields
#    are the entire 2FA state — removing them drops the second factor
#    cleanly while leaving the password intact.
sudo jq '(.users[] | select(.username == "YOUR_USERNAME"))
        |= del(.totp_secret, .totp_recovery, .totp_enrolled)' \
    /var/lib/aruba-agent/users.json.bak \
    | sudo tee /var/lib/aruba-agent/users.json > /dev/null
sudo chown aruba-agent:aruba-agent /var/lib/aruba-agent/users.json
sudo chmod 600 /var/lib/aruba-agent/users.json

sudo systemctl start aruba-agent
```

You'll be back to password-only login. Re-enroll from Settings →
Two-Factor Auth as soon as you're back in.

If you don't have `jq` installed and don't want to install it, opening
`users.json` in `nano` and deleting the three `"totp_..."` lines by
hand works just as well — the file is tiny and human-readable.

---

## 4 — `config.ini` corrupted or accidentally wiped

**Symptom.** Agent refuses to start with `configparser` errors in the
journal, or every section is silently empty.

```bash
sudo systemctl stop aruba-agent

# 1. If the migration backup is still around, that's the cleanest path.
ls /etc/aruba-agent/config.ini.bak
sudo cp /etc/aruba-agent/config.ini.bak /etc/aruba-agent/config.ini

# 2. Otherwise, start from the template and rebuild credentials
#    through the Settings UI.
ls /opt/aruba-agent/aruba_agent  # confirm code is present
sudo cp /opt/aruba-agent-src/Aruba-Network-Agent/config.ini.example \
        /etc/aruba-agent/config.ini

sudo chown aruba-agent:aruba-agent /etc/aruba-agent/config.ini
sudo chmod 640 /etc/aruba-agent/config.ini
sudo systemctl start aruba-agent
```

Note: if you bootstrap from the example and have not preserved
`master.key`, you may as well treat this like scenario 1's "accept the
reset" path — old `.cfg.enc` backups are unreadable.

---

## 5 — Switch poller appears stuck / `/healthz` returns 503

**Symptom.** Dashboard hangs on the loading spinner, or external
monitoring's `/healthz` probe returns 503 with `{"status":"degraded"}`.

This is almost always one of three things:

```bash
# A. AgentState deadlocked (rare — extremely unlikely with the v3.0.x
#    RLock model, but the symptom is "every dashboard request hangs").
sudo systemctl status aruba-agent          # is the process alive?
sudo journalctl -u aruba-agent -n 100 --no-pager | tail
sudo systemctl restart aruba-agent

# B. SNMP profile mismatch — every switch shows DOWN with auth errors.
#    Open Settings → SNMPv3 → Test profile against one switch IP. The
#    test endpoint surfaces the specific failure (auth_failure /
#    engine_id_mismatch / privacy_failure / unknown_user).

# C. waitress worker pool exhausted — 200+ switches polled in
#    lockstep saturating the GIL. Bump threads:
#       Settings → Web Server → threads = 32
#    then Restart Now.
```

If a restart doesn't clear it, capture a thread dump for postmortem
and reach out for help:

```bash
# Send SIGUSR1 to the agent if you've wired in py-spy or faulthandler;
# otherwise pyrasite is the lowest-friction option:
sudo dnf install -y python3-pyrasite
sudo pyrasite-shell $(systemctl show -p MainPID aruba-agent | cut -d= -f2)
# Inside the shell:
#   import sys, traceback
#   for tid, frame in sys._current_frames().items():
#       print(f"--- Thread {tid} ---")
#       traceback.print_stack(frame)
```

---

## Belt-and-braces: what to back up off-host

If you take regular backups, these are the files that matter most.
Everything else can be rebuilt from the repo.

| Path | Why |
|---|---|
| `/etc/aruba-agent/master.key` | Decryption key for everything else. Single most important file. |
| `/etc/aruba-agent/config.ini` | Operator-edited configuration with encrypted secrets. |
| `/var/lib/aruba-agent/users.json` | Local accounts + 2FA secrets. |
| `/var/lib/aruba-agent/api_tokens.json` | API tokens (scrypt hashes; cleartext is gone forever after mint). |
| `/var/lib/aruba-agent/state.json` | Persistent snapshot of monitored switches and last-run timestamps. Nice to have, not critical. |
| `/var/lib/aruba-agent/backups/` | Encrypted config backups. Useless without `master.key`. |

A nightly tarball of `/etc/aruba-agent/` plus `/var/lib/aruba-agent/`
encrypted with the operator's own key (separate from `master.key`!) and
shipped off-host is enough for full recovery.

---

## Last-resort full reset

If everything above fails and you just want a working agent again at
the cost of losing all encrypted state:

```bash
sudo systemctl stop aruba-agent
sudo rm -rf /etc/aruba-agent /var/lib/aruba-agent
sudo mkdir -p /etc/aruba-agent/subnets \
              /var/lib/aruba-agent/{backups,arp,firmware}
sudo chown -R aruba-agent:aruba-agent /etc/aruba-agent /var/lib/aruba-agent
sudo install -m 640 -o aruba-agent -g aruba-agent \
    /opt/aruba-agent-src/Aruba-Network-Agent/config.ini.example \
    /etc/aruba-agent/config.ini
sudo systemctl start aruba-agent
```

This is equivalent to a fresh install — fresh `master.key`, fresh
admin/admin bootstrap, no history. Use only when nothing else works.
