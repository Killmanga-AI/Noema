#!/usr/bin/env bash
# Installs the Noema agent as a systemd service on Linux.
#
#   sudo ./install-agent.sh --binary ./publish/Noema.Agent \
#        --server https://noema.example.com --token nmt_... --allow 192.168.1.0/24
#
# Run the enroll step as the service account so the credential is owned by it and readable by nobody else.
set -euo pipefail

BINARY=""
SERVER=""
TOKEN=""
NAME=""
ALLOW=()

usage() {
  echo "Usage: sudo $0 --binary <path to Noema.Agent> --server <https url> --token <enrollment token> [--name <agent name>] [--allow <cidr>]..." >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --server) SERVER="${2:-}"; shift 2 ;;
    --token)  TOKEN="${2:-}";  shift 2 ;;
    --name)   NAME="${2:-}";   shift 2 ;;
    --allow)  ALLOW+=("${2:-}"); shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "$BINARY" && -n "$SERVER" && -n "$TOKEN" ]] || usage
[[ $EUID -eq 0 ]] || { echo "Run this script as root (for example with sudo)." >&2; exit 1; }
[[ -f "$BINARY" ]] || { echo "Cannot find $BINARY" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "This installer needs systemd." >&2; exit 1; }

INSTALL_DIR=/opt/noema-agent
DATA_DIR=/var/lib/noema-agent
UNIT_SOURCE="$(cd "$(dirname "$0")" && pwd)/noema-agent.service"
[[ -f "$UNIT_SOURCE" ]] || { echo "Cannot find noema-agent.service next to this script." >&2; exit 1; }

echo "Creating the service account..."
if ! id -u noema-agent >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir "$DATA_DIR" --shell /usr/sbin/nologin noema-agent
fi

echo "Installing the program to $INSTALL_DIR..."
install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$BINARY" "$INSTALL_DIR/Noema.Agent"

install -d -o noema-agent -g noema-agent -m 0700 "$DATA_DIR"
install -d -m 0755 /etc/noema-agent
[[ -f /etc/noema-agent/agent.env ]] || install -m 0644 /dev/null /etc/noema-agent/agent.env

echo "Enrolling with $SERVER..."
ENROLL=(enroll --server "$SERVER" --token "$TOKEN" --data-dir "$DATA_DIR")
[[ -n "$NAME" ]] && ENROLL+=(--name "$NAME")
for range in "${ALLOW[@]:-}"; do
  [[ -n "$range" ]] && ENROLL+=(--allow "$range")
done

# The token is passed on the command line only for this one process and is single use.
sudo -u noema-agent -H env NOEMA_AGENT_DATA_DIR="$DATA_DIR" "$INSTALL_DIR/Noema.Agent" "${ENROLL[@]}"

echo "Installing and starting the service..."
install -m 0644 "$UNIT_SOURCE" /etc/systemd/system/noema-agent.service
systemctl daemon-reload
systemctl enable --now noema-agent.service

echo
echo "Done. Check it with:  systemctl status noema-agent   and   journalctl -u noema-agent -f"
