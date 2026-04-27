#!/usr/bin/env bash
# install-apache.sh
#
# One-shot installer that puts Apache2 in front of the Aruba Switch Manager
# Flask backend on AlmaLinux 9.
#
# What it does:
#   1. Installs httpd + mod_ssl
#   2. Drops the vhost into /etc/httpd/conf.d/aruba-switch-manager.conf
#   3. Allows Apache to talk to the Flask backend (SELinux)
#   4. Opens TCP/443 in firewalld (and removes the now-unused 8080 rule
#      if it was opened previously)
#   5. Verifies the config, then enables + restarts httpd
#
# Run after generate-self-signed-cert.sh has produced /etc/pki/tls cert files.
#
# Usage:
#   sudo ./scripts/install-apache.sh

set -euo pipefail

# ─── Paths ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_VHOST="${REPO_ROOT}/apache/aruba-switch-manager.conf"
DEST_VHOST="/etc/httpd/conf.d/aruba-switch-manager.conf"
CERT_FILE="/etc/pki/tls/certs/aruba-switch-manager.crt"
KEY_FILE="/etc/pki/tls/private/aruba-switch-manager.key"

# ─── Sanity checks ─────────────────────────────────────────────────────
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: this script must be run as root (use sudo)." >&2
    exit 1
fi

if [[ ! -f "${SRC_VHOST}" ]]; then
    echo "ERROR: vhost template not found at ${SRC_VHOST}" >&2
    exit 1
fi

if [[ ! -f "${CERT_FILE}" || ! -f "${KEY_FILE}" ]]; then
    echo "ERROR: TLS cert/key not found." >&2
    echo "  Run scripts/generate-self-signed-cert.sh first." >&2
    exit 1
fi

# ─── 1. Install packages ───────────────────────────────────────────────
echo "==> Installing httpd + mod_ssl"
dnf install -y httpd mod_ssl

# ─── 2. Drop in the vhost ──────────────────────────────────────────────
echo "==> Installing vhost: ${DEST_VHOST}"
install -m 0644 -o root -g root "${SRC_VHOST}" "${DEST_VHOST}"

# ─── 3. SELinux: let httpd reach the Flask backend on localhost:8080 ───
if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" != "Disabled" ]]; then
    echo "==> Enabling SELinux boolean: httpd_can_network_connect"
    setsebool -P httpd_can_network_connect 1
else
    echo "==> SELinux disabled — skipping boolean tweak"
fi

# ─── 4. Firewalld: open 443, optionally close 8080 ─────────────────────
if systemctl is-active --quiet firewalld; then
    echo "==> Opening TCP/443 in firewalld"
    firewall-cmd --permanent --add-service=https >/dev/null
    # 8080 should no longer be reachable from outside — Flask binds
    # to 127.0.0.1 in production. Quietly remove the old rule if it exists.
    if firewall-cmd --permanent --list-ports | grep -qw "8080/tcp"; then
        echo "==> Removing legacy TCP/8080 firewall rule"
        firewall-cmd --permanent --remove-port=8080/tcp >/dev/null
    fi
    firewall-cmd --reload >/dev/null
else
    echo "==> firewalld not running — skipping firewall rules"
fi

# ─── 5. Validate + restart ─────────────────────────────────────────────
echo "==> Validating Apache config"
apachectl configtest

echo "==> Enabling + restarting httpd"
systemctl enable httpd >/dev/null
systemctl restart httpd

systemctl --no-pager --full status httpd | head -5 || true

echo ""
echo "Done. The dashboard is now available at:"
echo "    https://$(hostname -f 2>/dev/null || hostname)/"
echo ""
echo "Reminder: set [web] secure_cookies = true and host = 127.0.0.1 in"
echo "/etc/aruba-agent/config.ini, then restart the agent:"
echo "    sudo systemctl restart aruba-agent"
