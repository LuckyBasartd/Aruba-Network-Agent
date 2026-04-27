#!/usr/bin/env bash
# generate-self-signed-cert.sh
#
# Mints a self-signed TLS certificate for the Aruba Switch Manager web UI.
# Designed for internal-only / private-LAN deployments where a public CA
# (Let's Encrypt, etc.) is not an option.
#
# What it produces:
#   /etc/pki/tls/private/aruba-switch-manager.key   (4096-bit RSA, mode 0600)
#   /etc/pki/tls/certs/aruba-switch-manager.crt     (X.509 cert, valid 10 years)
#
# Usage:
#   sudo ./scripts/generate-self-signed-cert.sh [hostname-or-ip]
#
# If no argument is given, the system hostname is used. Additional Subject
# Alternative Names can be added by editing the SAN array below.
#
# Browsers will show "Not Secure" because the cert is not chained to a
# public CA. Internal users can either:
#   1. Click through the warning, or
#   2. Import the .crt into their workstation trust store.

set -euo pipefail

# ─── Config ────────────────────────────────────────────────────────────
COMMON_NAME="${1:-$(hostname -f 2>/dev/null || hostname)}"
CERT_DIR="/etc/pki/tls/certs"
KEY_DIR="/etc/pki/tls/private"
CERT_FILE="${CERT_DIR}/aruba-switch-manager.crt"
KEY_FILE="${KEY_DIR}/aruba-switch-manager.key"
DAYS_VALID=3650           # 10 years — internal use only
KEY_BITS=4096

# Subject Alternative Names — every name/IP a browser might use to reach
# the box. Add more lines here if your hosts have aliases.
SAN_ENTRIES=(
    "DNS:${COMMON_NAME}"
    "DNS:$(hostname -s)"
    "DNS:localhost"
    "IP:127.0.0.1"
)

# Tack on the primary IP if `hostname -I` returns one.
PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ -n "${PRIMARY_IP}" ]]; then
    SAN_ENTRIES+=("IP:${PRIMARY_IP}")
fi

# ─── Sanity checks ─────────────────────────────────────────────────────
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: this script must be run as root (use sudo)." >&2
    exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl is not installed. Install with: dnf install -y openssl" >&2
    exit 1
fi

mkdir -p "${CERT_DIR}" "${KEY_DIR}"

if [[ -f "${CERT_FILE}" || -f "${KEY_FILE}" ]]; then
    echo "WARNING: existing cert or key found:"
    [[ -f "${CERT_FILE}" ]] && echo "    ${CERT_FILE}"
    [[ -f "${KEY_FILE}"  ]] && echo "    ${KEY_FILE}"
    read -rp "Overwrite? [y/N] " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# ─── Build a temporary OpenSSL config ──────────────────────────────────
TMP_CONF="$(mktemp)"
trap 'rm -f "${TMP_CONF}"' EXIT

# Join SAN entries with commas for the openssl config block.
SAN_LINE=""
for entry in "${SAN_ENTRIES[@]}"; do
    [[ -n "${SAN_LINE}" ]] && SAN_LINE+=","
    SAN_LINE+="${entry}"
done

cat > "${TMP_CONF}" <<EOF
[ req ]
default_bits        = ${KEY_BITS}
default_md          = sha256
prompt              = no
distinguished_name  = dn
req_extensions      = v3_req
x509_extensions     = v3_req

[ dn ]
CN  = ${COMMON_NAME}
O   = Aruba Switch Manager
OU  = Internal IT
C   = US

[ v3_req ]
basicConstraints     = CA:FALSE
keyUsage             = critical, digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth
subjectAltName       = ${SAN_LINE}
EOF

# ─── Generate ──────────────────────────────────────────────────────────
echo "Generating ${KEY_BITS}-bit RSA key + self-signed cert for CN=${COMMON_NAME}"
echo "SANs: ${SAN_LINE}"

openssl req -x509 -nodes \
    -newkey "rsa:${KEY_BITS}" \
    -keyout "${KEY_FILE}" \
    -out    "${CERT_FILE}" \
    -days   "${DAYS_VALID}" \
    -config "${TMP_CONF}"

# ─── Lock down permissions ─────────────────────────────────────────────
chown root:root "${KEY_FILE}" "${CERT_FILE}"
chmod 600       "${KEY_FILE}"
chmod 644       "${CERT_FILE}"

# Restore SELinux contexts so httpd can read them (no-op if SELinux disabled).
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "${KEY_FILE}" "${CERT_FILE}" 2>/dev/null || true
fi

# ─── Summary ───────────────────────────────────────────────────────────
echo ""
echo "Certificate: ${CERT_FILE}"
echo "Key:         ${KEY_FILE}"
echo ""
openssl x509 -in "${CERT_FILE}" -noout -subject -issuer -dates -ext subjectAltName | sed 's/^/    /'
echo ""
echo "Next: install Apache (sudo ./scripts/install-apache.sh) and reload httpd."
