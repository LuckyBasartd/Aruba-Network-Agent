#!/bin/bash
#
# /opt/aruba-agent/bin/aruba-agent
#
# Tiny wrapper that the systemd unit's ExecStart points at. Its only
# job is to pick the right Python interpreter — the venv if one
# exists at /opt/aruba-agent/venv/bin/python, otherwise the system
# python3 — and exec main.py with whatever arguments systemd passed.
#
# Why a wrapper instead of putting the path in the unit file:
#   * Keeps the unit file stable across deploys that flip between
#     "venv-installed" and "system-pip-installed" layouts.
#   * Lets the install.sh upgrade path swap the venv in/out without
#     editing /etc/systemd/system/ in lockstep.
#   * Surfaces a clear journal warning when the agent falls back to
#     the system python — sysadmins who haven't migrated yet see it
#     and can fix at their own pace.

set -e

VENV_PY=/opt/aruba-agent/venv/bin/python
SYS_PY=/usr/bin/python3
APP=/opt/aruba-agent/main.py

if [[ -x "${VENV_PY}" ]]; then
    PY="${VENV_PY}"
else
    # Surface the fallback once per start so it shows up in journalctl
    # right next to the rest of the agent's startup log.
    echo "WARNING: /opt/aruba-agent/venv/bin/python not found —" \
         "falling back to ${SYS_PY}. See INSTALL-AlmaLinux-10.md §5" \
         "to migrate to a venv." >&2
    PY="${SYS_PY}"
fi

# -u forces unbuffered stdout/stderr so journald sees lines in real
# time rather than at process exit.
exec "${PY}" -u "${APP}" "$@"
