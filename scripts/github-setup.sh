#!/usr/bin/env bash
# ============================================================
#  Vantage — GitHub Private Repo Setup
#  Run this ONCE on the machine that owns the repo
# ============================================================
set -euo pipefail

GREEN='\033[0;32m' CYAN='\033[0;36m' YELLOW='\033[1;33m' RED='\033[0;31m' BOLD='\033[1m' NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
info() { echo -e "${CYAN}[..] $*${NC}"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
hdr()  { echo -e "\n${BOLD}$*${NC}"; }

hdr "═══ Vantage — GitHub Private Repo Setup ═══"

# ── Prerequisites ─────────────────────────────────────────────
if ! command -v git &>/dev/null; then
  echo "git not found — install it first"
  exit 1
fi
if ! command -v gh &>/dev/null; then
  echo "GitHub CLI not found — install it first: https://cli.github.com"
  exit 1
fi

# ── Auth ──────────────────────────────────────────────────────
hdr "1. GitHub Authentication"
if ! gh auth status &>/dev/null; then
  info "logging in to GitHub..."
  gh auth login
fi
ok "authenticated"

# ── Repo details ─────────────────────────────────────────────
hdr "2. Repository Details"
echo ""
read -rp "  GitHub username or org: " GH_OWNER
read -rp "  Repository name (e.g. vantage): " GH_REPO
echo ""

# ── Create private repo ───────────────────────────────────────
hdr "3. Creating private repository"
if gh repo view "$GH_OWNER/$GH_REPO" &>/dev/null; then
  warn "repo $GH_OWNER/$GH_REPO already exists — skipping creation"
else
  gh repo create "$GH_OWNER/$GH_REPO" \
    --private \
    --description "Vantage — Red Team Attack Surface Management Platform" \
    --confirm 2>/dev/null || \
  gh repo create "$GH_OWNER/$GH_REPO" --private --description "Vantage — Red Team ASM"
  ok "created: github.com/$GH_OWNER/$GH_REPO (private)"
fi

# ── Push code ─────────────────────────────────────────────────
hdr "4. Pushing code"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$REPO_ROOT"

if [[ ! -d ".git" ]]; then
  git init
  git add -A
  git commit -m "initial: vantage v1.0.0"
fi

# Set remote
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$GH_OWNER/$GH_REPO.git"
git branch -M main
git push -u origin main
ok "code pushed to github.com/$GH_OWNER/$GH_REPO"

# ── .gitignore ────────────────────────────────────────────────
hdr "5. Ensuring .gitignore"
cat > "$REPO_ROOT/.gitignore" << 'GITIGNORE'
# Binary
vantage
vantage.db
*.db
*.db-shm
*.db-wal

# Runtime
screenshots/
*.jsonl
/tmp/vantage-*
resume.cfg
.env

# Config — never commit
vantage.yaml

# Go
vendor/
*.test
*.out
GITIGNORE

git add .gitignore
git diff --cached --quiet || git commit -m "chore: add .gitignore"
git push origin main 2>/dev/null || true
ok ".gitignore configured — vantage.yaml excluded from commits"

# ── Summary ──────────────────────────────────────────────────
hdr "═══ Setup Complete ═══"
echo ""
echo -e "  ${GREEN}Repo:${NC} https://github.com/$GH_OWNER/$GH_REPO (private)"
echo ""
echo -e "  ${YELLOW}NOTE:${NC} vantage.yaml is in .gitignore — create your own"
echo "         from vantage.example.yaml with your target scope"
echo ""
