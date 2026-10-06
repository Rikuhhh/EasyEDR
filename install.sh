#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/Rikuhhh/EasyEDR.git"
INSTALL_DIR="/opt/easyedr"
LOG_DIR="/var/log/easyedr"
LOG_FILE="$LOG_DIR/edr_events.jsonl"
CONFIG_FILE="$INSTALL_DIR/config.yaml"
SERVICE_NAME="easyedr"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BIN_DIR="/usr/local/bin"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m"

info() { echo -e "${GREEN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1" >&2; }

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo ./install.sh)"
    exit 1
fi

if ! command -v apt >/dev/null 2>&1; then
    error "This script is designed for Debian or Ubuntu because apt was not found"
    exit 1
fi

info "Pre-checks passed"

info "Installing dependencies"
apt update -qq
apt install -y -qq \
    git \
    bpfcc-tools \
    python3-bpfcc \
    "linux-headers-$(uname -r)" \
    python3-pip \
    python3-yaml

if ! python3 -c "import bcc" >/dev/null 2>&1; then
    error "Python module bcc is not accessible"
    exit 1
fi

if [[ -d "$INSTALL_DIR/.git" ]]; then
    warn "$INSTALL_DIR already exists; updating the existing checkout"
    git -C "$INSTALL_DIR" checkout -- config.yaml
    git -C "$INSTALL_DIR" pull --ff-only
elif [[ -e "$INSTALL_DIR" ]]; then
    error "$INSTALL_DIR exists but is not a Git checkout"
    exit 1
else
    info "Cloning repository into $INSTALL_DIR"
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    error "config.yaml not found in the repository"
    exit 1
fi

if [[ ! -f "$INSTALL_DIR/easyedr.service" ]]; then
    error "easyedr.service not found in the repository"
    exit 1
fi

if [[ ! -d "$INSTALL_DIR/bin" ]]; then
    error "bin directory not found in the repository"
    exit 1
fi

info "Preparing log directory"
mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"
sed -i "s|^[[:space:]]*output_file:.*|  output_file: \"$LOG_FILE\"|" "$CONFIG_FILE"

chmod +x "$INSTALL_DIR/main.py"

info "Installing systemd service"
cp "$INSTALL_DIR/easyedr.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" --quiet
systemctl restart "$SERVICE_NAME"

if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "Service $SERVICE_NAME is active and enabled on boot"
else
    error "Service failed to start; check journalctl -u $SERVICE_NAME -e"
    exit 1
fi

info "Installing CLI commands"
cp "$INSTALL_DIR"/bin/easyedr* "$BIN_DIR/"
chmod +x "$BIN_DIR"/easyedr*

echo ""
info "Installation complete"
echo "  Source code: $INSTALL_DIR"
echo "  Logs: $LOG_FILE"
echo "  Config: $CONFIG_FILE"
echo "  Service: $SERVICE_NAME"
echo ""
echo "Run \"easyedr --help\" to see available commands."
