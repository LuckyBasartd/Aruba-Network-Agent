#!/usr/bin/env bash
#
# Aruba Network Agent — one-command installer.
#
# Idempotent end-to-end install for AlmaLinux 9 / 10 (also works on
# Rocky Linux 9 / 10 and RHEL 9 / 10). Designed for two invocation
# styles:
#
#   1. From a local clone of the repo
#      sudo ./install.sh
#
#   2. As a curl | sudo bash one-liner (no clone needed)
#      curl -fsSL https://raw.githubusercontent.com/LuckyBasartd/Aruba-Network-Agent/main/install.sh \
#         | sudo bash
#
# Re-running the script upgrades an existing install. It NEVER touches
# /etc/aruba-agent/config.ini, /etc/aruba-agent/master.key, or
# /var/lib/aruba-agent/* — your state and secrets survive.
#
# Environment-variable overrides (all optional):
#   REPO_URL     URL of the upstream repo. Default:
#                https://github.com/LuckyBasartd/Aruba-Network-Agent.git
#   REPO_REF     Branch / tag / commit to install. Default: main
#   STAGING_DIR  Where to clone the repo while installing.
#                Default: /opt/aruba-agent.src
#   INSTALL_DIR  Where the deployed code lives.   Default: /opt/aruba-agent
#   CONFIG_DIR   Where /etc/aruba-agent/ lives.   Default: /etc/aruba-agent
#   STATE_DIR    Where /var/lib/aruba-agent/ lives. Default: /var/lib/aruba-agent
#   SVC_USER     Service account name.            Default: aruba-agent
#   SKIP_APACHE  Set to "1" to skip Apache + TLS setup (run agent
#                stand-alone on a network you trust). Default: unset.
#   SKIP_CERT    Set to "1" to skip cert generation (e.g. you already
#                have one provisioned). Default: unset.
#   CERT_HOST    Hostname to bake into the cert SANs. Default:
#                $(hostname -f).
#
# Exit codes:
#   0  success
#   1  OS not supported / preflight failed
#   2  package install failed
#   3  repo fetch failed
#   4  deploy / pip / permission step failed
#   5  service didn't come up healthy

set -euo pipefail

# ─── pretty logging ──────────────────────────────────────────────────────
log()  { printf '\033[1;34m[+]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit "${2:-1}"; }

# ─── defaults ────────────────────────────────────────────────────────────
REPO_URL="${REPO_URL:-https://github.com/LuckyBasartd/Aruba-Network-Agent.git}"
REPO_REF="${REPO_REF:-main}"
STAGING_DIR="${STAGING_DIR:-/opt/aruba-agent.src}"
INSTALL_DIR="${INSTALL_DIR:-/opt/aruba-agent}"
CONFIG_DIR="${CONFIG_DIR:-/etc/aruba-agent}"
STATE_DIR="${STATE_DIR:-/var/lib/aruba-agent}"
SVC_USER="${SVC_USER:-aruba-agent}"
SKIP_APACHE="${SKIP_APACHE:-}"
SKIP_CERT="${SKIP_CERT:-}"
CERT_HOST="${CERT_HOST:-$(hostname -f 2>/dev/null || hostname)}"

# ─── preflight ───────────────────────────────────────────────────────────

[[ $EUID -eq 0 ]] || die "Run as root (use sudo)." 1

# Detect EL9 / EL10. The agent is tested on AlmaLinux but works on any
# RHEL-compatible 9 or 10 (Rocky, AlmaLinux, RHEL, CentOS Stream).
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    almalinux:9*|almalinux:10*|rocky:9*|rocky:10*|rhel:9*|rhel:10*|centos:9*|centos:10*) ;;
    *)
      warn "Detected ${ID:-unknown} ${VERSION_ID:-?} — only RHEL-family 9/10 is tested."
      warn "Continuing anyway. Hit Ctrl-C in the next 5s to abort."
      sleep 5
      ;;
  esac
else
  die "Cannot determine OS — /etc/os-release missing." 1
fi

log "Aruba Network Agent installer"
log "  REPO    ${REPO_URL} (ref: ${REPO_REF})"
log "  CODE    ${INSTALL_DIR}"
log "  CONFIG  ${CONFIG_DIR}"
log "  STATE   ${STATE_DIR}"
log "  USER    ${SVC_USER}"

# ─── 1. OS packages ──────────────────────────────────────────────────────
log "Installing OS packages (dnf)…"
dnf install -y --setopt=install_weak_deps=False \
  git python3 python3-pip nmap openssl rsync \
  policycoreutils-python-utils firewalld \
  ${SKIP_APACHE:+} ${SKIP_APACHE:-httpd mod_ssl} \
  > /tmp/aruba-install-dnf.log 2>&1 \
  || die "dnf install failed — see /tmp/aruba-install-dnf.log" 2
systemctl enable --now firewalld >/dev/null 2>&1 || true
ok "OS packages installed"

# ─── 2. service account + directories ────────────────────────────────────
if ! id -u "${SVC_USER}" >/dev/null 2>&1; then
  log "Creating service account: ${SVC_USER}"
  useradd -r -s /sbin/nologin "${SVC_USER}"
else
  ok "Service account ${SVC_USER} already exists"
fi

log "Creating directory tree"
install -d -m 755 "${INSTALL_DIR}"
install -d -m 750 -o "${SVC_USER}" -g "${SVC_USER}" "${CONFIG_DIR}"
install -d -m 750 -o "${SVC_USER}" -g "${SVC_USER}" "${CONFIG_DIR}/subnets"
install -d -m 755 -o "${SVC_USER}" -g "${SVC_USER}" "${STATE_DIR}"
install -d -m 755 -o "${SVC_USER}" -g "${SVC_USER}" "${STATE_DIR}/backups"
install -d -m 755 -o "${SVC_USER}" -g "${SVC_USER}" "${STATE_DIR}/arp"
install -d -m 755 -o "${SVC_USER}" -g "${SVC_USER}" "${STATE_DIR}/firmware"
# Audit log lives under /var/log so logrotate.d picks it up by convention.
install -d -m 750 -o "${SVC_USER}" -g "${SVC_USER}" /var/log/aruba-agent
ok "Directories ready"

# ─── 3. fetch source ─────────────────────────────────────────────────────
# Two paths:
#   a) We're already running from a clone (./install.sh) — use the repo
#      we're in as the source.
#   b) We're being piped from curl — clone REPO_URL into STAGING_DIR.

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
if [[ -n "${SCRIPT_PATH}" && -f "${SCRIPT_PATH}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)"
else
  SCRIPT_DIR=""
fi

if [[ -n "${SCRIPT_DIR}" && -f "${SCRIPT_DIR}/main.py" && -d "${SCRIPT_DIR}/aruba_agent" ]]; then
  SOURCE_DIR="${SCRIPT_DIR}"
  ok "Using local checkout at ${SOURCE_DIR}"
else
  log "Cloning ${REPO_URL} (ref ${REPO_REF}) → ${STAGING_DIR}"
  if [[ -d "${STAGING_DIR}/.git" ]]; then
    git -C "${STAGING_DIR}" fetch --depth=1 origin "${REPO_REF}" >/dev/null 2>&1 \
      || die "git fetch failed in ${STAGING_DIR}" 3
    git -C "${STAGING_DIR}" reset --hard "FETCH_HEAD" >/dev/null 2>&1 \
      || die "git reset failed" 3
  else
    rm -rf "${STAGING_DIR}"
    git clone --depth=1 --branch "${REPO_REF}" "${REPO_URL}" "${STAGING_DIR}" \
      >/dev/null 2>&1 \
      || die "git clone failed (private repo? try setting REPO_URL to an HTTPS URL with PAT)" 3
  fi
  SOURCE_DIR="${STAGING_DIR}"
  ok "Cloned to ${SOURCE_DIR}"
fi

# ─── 4. deploy code ──────────────────────────────────────────────────────
log "Deploying code → ${INSTALL_DIR}"
rsync -a --delete \
  --exclude '__pycache__' --exclude '*.pyc' --exclude '.git' \
  "${SOURCE_DIR}/aruba_agent/" "${INSTALL_DIR}/aruba_agent/"
rsync -a "${SOURCE_DIR}/main.py" "${SOURCE_DIR}/requirements.txt" "${INSTALL_DIR}/"
ok "Code deployed"

# Config template — but DO NOT overwrite an existing config.ini.
if [[ ! -f "${CONFIG_DIR}/config.ini" ]]; then
  log "Installing initial config.ini from template"
  install -m 640 -o "${SVC_USER}" -g "${SVC_USER}" \
    "${SOURCE_DIR}/config.ini.example" "${CONFIG_DIR}/config.ini"
  CONFIG_FRESH=1
  ok "config.ini created — edit ${CONFIG_DIR}/config.ini before first real use"
else
  ok "Existing ${CONFIG_DIR}/config.ini preserved"
  CONFIG_FRESH=0
fi

# Subnet lists (optional)
if [[ -d "${SOURCE_DIR}/subnets" ]]; then
  rsync -a --ignore-existing "${SOURCE_DIR}/subnets/" "${CONFIG_DIR}/subnets/"
fi

# systemd unit
log "Installing systemd unit"
install -m 644 "${SOURCE_DIR}/aruba-agent.service" /etc/systemd/system/aruba-agent.service
systemctl daemon-reload
ok "systemd unit installed"

# logrotate.d config for the audit log
if [[ -f "${SOURCE_DIR}/scripts/aruba-agent.logrotate" ]]; then
  log "Installing logrotate.d config for audit log"
  install -m 644 "${SOURCE_DIR}/scripts/aruba-agent.logrotate" \
    /etc/logrotate.d/aruba-agent
  ok "logrotate config installed"
fi

# ─── 5. python dependencies ──────────────────────────────────────────────
log "Installing Python dependencies (pip)…"
pip3 install --upgrade --quiet -r "${INSTALL_DIR}/requirements.txt" \
  > /tmp/aruba-install-pip.log 2>&1 \
  || die "pip install failed — see /tmp/aruba-install-pip.log" 4
# Belt-and-suspenders: cryptography is a transitive dep but make it explicit
# in case a future requirements.txt change drops it.
pip3 install --upgrade --quiet cryptography >> /tmp/aruba-install-pip.log 2>&1 || true
ok "Python deps installed"

# ─── 6. permissions ──────────────────────────────────────────────────────
log "Setting permissions"
chown -R root:"${SVC_USER}" "${INSTALL_DIR}"
chmod -R 750 "${INSTALL_DIR}"
chown -R "${SVC_USER}":"${SVC_USER}" "${STATE_DIR}"
chown -R "${SVC_USER}":"${SVC_USER}" "${CONFIG_DIR}"
ok "Permissions applied"

# ─── 7. TLS cert + Apache reverse proxy ──────────────────────────────────
if [[ -z "${SKIP_APACHE}" ]]; then
  if [[ -z "${SKIP_CERT}" ]]; then
    if [[ ! -s /etc/pki/tls/certs/aruba-switch-manager.crt ]]; then
      log "Generating self-signed TLS cert (host=${CERT_HOST})"
      bash "${SOURCE_DIR}/scripts/generate-self-signed-cert.sh" "${CERT_HOST}" \
        > /tmp/aruba-install-cert.log 2>&1 \
        || die "cert generation failed — see /tmp/aruba-install-cert.log" 4
      ok "TLS cert installed"
    else
      ok "Existing TLS cert preserved"
    fi
  else
    warn "SKIP_CERT set — skipping TLS cert generation"
  fi

  log "Installing Apache reverse proxy"
  bash "${SOURCE_DIR}/scripts/install-apache.sh" \
    > /tmp/aruba-install-apache.log 2>&1 \
    || die "Apache install failed — see /tmp/aruba-install-apache.log" 4
  ok "Apache reverse proxy configured"
else
  warn "SKIP_APACHE set — agent will listen directly on its [web] host:port"
fi

# ─── 8. sudoers rule for Settings → Restart Now ──────────────────────────
SUDOERS_FILE="/etc/sudoers.d/${SVC_USER}-restart"
if [[ ! -f "${SUDOERS_FILE}" ]]; then
  log "Installing sudoers rule for Settings → Restart Now"
  cat > "${SUDOERS_FILE}" <<EOF
# Allow the ${SVC_USER} service account to restart its own service
# from the web UI. No other systemctl operations are permitted.
${SVC_USER} ALL=(root) NOPASSWD: /bin/systemctl restart aruba-agent
EOF
  chmod 440 "${SUDOERS_FILE}"
  if ! visudo -c -f "${SUDOERS_FILE}" >/dev/null; then
    rm -f "${SUDOERS_FILE}"
    die "Sudoers rule failed validation — removed for safety" 4
  fi
  ok "Sudoers rule installed"
else
  ok "Sudoers rule already present"
fi

# ─── 9. enable + start the service ───────────────────────────────────────
log "Starting service"
systemctl enable aruba-agent >/dev/null
systemctl restart aruba-agent
# Give the service a few seconds to either come up or fail loudly.
sleep 3
if ! systemctl is-active --quiet aruba-agent; then
  warn "Service did not reach 'active' state — recent journal output:"
  journalctl -u aruba-agent -n 30 --no-pager
  die "aruba-agent failed to start" 5
fi
ok "Service running"

# ─── 10. summary ─────────────────────────────────────────────────────────
echo
ok "Install complete."
echo

# Was a master key created on this run? Surface that prominently — losing
# it is the only truly destructive failure mode in v3.0.1+.
if [[ -f "${CONFIG_DIR}/master.key" ]]; then
  ok "Encryption master key: ${CONFIG_DIR}/master.key"
  echo "    ┌─────────────────────────────────────────────────────────────────┐"
  echo "    │  BACK THIS FILE UP. If you lose it, every encrypted password    │"
  echo "    │  in config.ini becomes unrecoverable and you'll have to         │"
  echo "    │  re-enter them through the Settings UI.                         │"
  echo "    │                                                                 │"
  echo "    │  Suggested:                                                     │"
  echo "    │      sudo cp ${CONFIG_DIR}/master.key \\"
  echo "    │              /root/master.key.backup-\$(date +%F)"
  echo "    └─────────────────────────────────────────────────────────────────┘"
  echo
fi

if [[ "${CONFIG_FRESH:-0}" -eq 1 ]]; then
  echo "Fresh config installed at ${CONFIG_DIR}/config.ini — edit it to set:"
  echo "  [credentials]  switch admin password (default fallback)"
  echo "  [smtp]         host / from / to       if you want email alerts"
  echo "  [radius]       server / secret        if you want RADIUS login"
  echo "  [scanner]      subnets                CIDRs to scan for switches"
  echo "  [arp.*]        per-location routers   for ARP discovery"
  echo
  echo "  sudo -u ${SVC_USER} nano ${CONFIG_DIR}/config.ini"
  echo "  sudo systemctl restart aruba-agent"
  echo
fi

echo "Dashboard:"
if [[ -z "${SKIP_APACHE}" ]]; then
  echo "  https://$(hostname -f 2>/dev/null || hostname)/"
  echo "  https://$(hostname -I 2>/dev/null | awk '{print $1}')/"
else
  WEB_PORT="$(grep -E '^\s*port\s*=' "${CONFIG_DIR}/config.ini" 2>/dev/null \
              | awk -F= '/^[^#]*port/ {gsub(/ /,"",$2); print $2; exit}' \
              || echo 8080)"
  echo "  http://$(hostname -I 2>/dev/null | awk '{print $1}'):${WEB_PORT}/"
fi
echo
echo "First login:"
echo "  username: admin"
echo "  password: admin     (you'll be forced to change it immediately)"
echo
echo "Useful commands:"
echo "  sudo systemctl status aruba-agent"
echo "  sudo journalctl -u aruba-agent -f"
echo "  sudo systemctl restart aruba-agent"
echo
