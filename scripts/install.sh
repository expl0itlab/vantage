#!/usr/bin/env bash
# ============================================================
#  Vantage — Install Script
#  Supports: Linux (x86_64, arm64), WSL2
# ============================================================
set -euo pipefail

GREEN='\033[0;32m' CYAN='\033[0;36m' YELLOW='\033[1;33m' RED='\033[0;31m' BOLD='\033[1m' NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
info() { echo -e "${CYAN}[..] $*${NC}"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*" >&2; }
hdr()  { echo -e "\n${BOLD}$*${NC}"; }

hdr "═══ Vantage Installer ═══"

# ── OS / arch ────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
[[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
[[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && ARCH="arm64"
info "platform: $OS/$ARCH"

# ── Go ───────────────────────────────────────────────────────
hdr "1. Go runtime"
if ! command -v go &>/dev/null; then
  info "installing Go 1.22..."
  GOTAR="go1.22.4.linux-${ARCH}.tar.gz"
  wget -q "https://go.dev/dl/$GOTAR" -O /tmp/$GOTAR
  sudo tar -C /usr/local -xzf /tmp/$GOTAR
  rm /tmp/$GOTAR
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
  export PATH=$PATH:/usr/local/go/bin
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
GO_VER=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+' || echo "0.0")
ok "Go $GO_VER"

# ── System deps ───────────────────────────────────────────────
hdr "2. System dependencies"
if command -v apt-get &>/dev/null; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq gcc libsqlite3-dev build-essential wget git 2>/dev/null
  ok "apt deps installed"
elif command -v yum &>/dev/null; then
  sudo yum install -y gcc sqlite-devel wget git 2>/dev/null
  ok "yum deps installed"
fi

# ── Go tools ─────────────────────────────────────────────────
hdr "3. Recon tools"
install_tool() {
  local name=$1 pkg=$2
  if command -v "$name" &>/dev/null; then
    ok "$name already installed"
  else
    info "installing $name..."
    go install "$pkg" 2>/dev/null && ok "$name installed" || warn "$name install failed — add $(go env GOPATH)/bin to PATH"
  fi
}

install_tool subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_tool assetfinder  "github.com/tomnomnom/assetfinder@latest"
install_tool httpx        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_tool naabu        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_tool dnsx         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_tool gowitness    "github.com/sensepost/gowitness@latest"

# Naabu raw socket permission (needed for SYN scan; connect scan works without)
if command -v naabu &>/dev/null; then
  NAABU_PATH=$(which naabu)
  sudo setcap cap_net_raw+ep "$NAABU_PATH" 2>/dev/null && ok "naabu: cap_net_raw set" || warn "naabu: setcap failed (connect scan will still work)"
fi

# Nuclei templates (for future use — nuclei itself not required)
hdr "4. Nuclei templates (optional)"
if command -v nuclei &>/dev/null; then
  info "updating nuclei templates..."
  nuclei -update-templates -silent 2>/dev/null && ok "templates updated" || warn "template update failed"
else
  info "nuclei not installed — skipping (not required)"
fi

# ── Build ─────────────────────────────────────────────────────
hdr "5. Build Vantage"
info "downloading dependencies..."
go mod tidy

info "building binary..."
CGO_ENABLED=1 go build -ldflags="-s -w" -o vantage ./cmd/
ok "built: ./vantage"

# ── Config ────────────────────────────────────────────────────
hdr "6. Config"
if [[ ! -f "vantage.yaml" ]]; then
  ./vantage init && ok "vantage.yaml generated"
else
  ok "vantage.yaml already exists"
fi

# ── Verify tools ─────────────────────────────────────────────
hdr "7. Tool verification"
MISSING=()
for t in subfinder assetfinder httpx naabu dnsx gowitness; do
  command -v "$t" &>/dev/null && ok "$t: found at $(which $t)" || { warn "$t: NOT FOUND"; MISSING+=("$t"); }
done

# ── Done ─────────────────────────────────────────────────────
hdr "═══ Installation Complete ═══"
echo ""
echo -e "  ${GREEN}Quick start:${NC}"
echo "    ./vantage scan -d target.com -p standard"
echo "    ./vantage scan -d target.com -p aggressive"
echo "    ./vantage serve                            # dashboard at http://127.0.0.1:8080"
echo "    ./vantage monitor                          # headless scheduler"
echo ""
echo -e "  ${CYAN}Scan profiles:${NC}"
echo "    stealth    — passive, low noise, ports 80/443/8080 only"
echo "    standard   — full recon, banner grab, screenshots, JS analysis, top-100 ports"
echo "    aggressive — bruteforce, /24 expansion, top-1000 ports, all features"
echo ""

if [[ ${#MISSING[@]} -gt 0 ]]; then
  warn "missing tools: ${MISSING[*]}"
  echo ""
  echo "  Add Go bin to PATH:"
  echo "    export PATH=\$PATH:\$(go env GOPATH)/bin"
  echo "  Or add to ~/.bashrc and reload:  source ~/.bashrc"
  echo ""
fi
