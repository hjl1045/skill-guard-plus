#!/usr/bin/env bash
# ============================================================
# skill-guard-plus installer
# One-click install to OpenClaw workspace
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

SKILLS_DIR="${OPENCLAW_SKILLS_DIR:-$HOME/.openclaw/skills}"
INSTALL_DIR="$SKILLS_DIR/skill-guard-plus"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}  ${BOLD}🛡️ skill-guard-plus installer${NC}                       ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Create skill directory
echo -e "${BLUE}→${NC} Installing to: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Step 2: Copy files
if [[ -f "$SCRIPT_DIR/safe-install-plus.sh" ]]; then
    cp "$SCRIPT_DIR/safe-install-plus.sh" "$INSTALL_DIR/safe-install-plus.sh"
else
    echo -e "${RED}ERROR:${NC} safe-install-plus.sh not found in $SCRIPT_DIR"
    echo "Make sure safe-install-plus.sh is in the same folder as this installer."
    exit 1
fi

if [[ -f "$SCRIPT_DIR/SKILL.md" ]]; then
    cp "$SCRIPT_DIR/SKILL.md" "$INSTALL_DIR/SKILL.md"
else
    echo -e "${RED}ERROR:${NC} SKILL.md not found in $SCRIPT_DIR"
    exit 1
fi

# Step 3: Make executable
chmod +x "$INSTALL_DIR/safe-install-plus.sh"

echo -e "${GREEN}✓${NC} Files installed"

# Step 4: Also add to PATH via symlink (optional convenience)
mkdir -p "$HOME/.local/bin"
ln -sf "$INSTALL_DIR/safe-install-plus.sh" "$HOME/.local/bin/safe-install-plus.sh"
echo -e "${GREEN}✓${NC} Symlinked to ~/.local/bin/safe-install-plus.sh"

# Step 5: Check PATH
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    echo ""
    echo -e "${YELLOW}⚠${NC}  ~/.local/bin is not in your PATH yet."
    echo "   Add this to your ~/.zshrc (or ~/.bashrc):"
    echo ""
    echo -e "   ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    echo ""
    echo "   Then run: source ~/.zshrc"
fi

# Step 6: Check dependencies
echo ""
echo -e "${BOLD}Checking dependencies...${NC}"

if command -v npx &> /dev/null; then
    echo -e "${GREEN}✓${NC} npx found (will use: npx clawhub@latest install)"
elif command -v clawhub &> /dev/null; then
    echo -e "${GREEN}✓${NC} clawhub CLI found (global install)"
else
    echo -e "${YELLOW}⚠${NC}  Neither npx nor clawhub found (needed for install mode)"
    echo "   Install Node.js: https://nodejs.org (includes npx)"
fi

if command -v uvx &> /dev/null; then
    echo -e "${GREEN}✓${NC} uvx found (mcp-scan will work)"
else
    # Try sourcing uv env
    if [[ -f "$HOME/.local/bin/env" ]]; then
        source "$HOME/.local/bin/env" 2>/dev/null || true
    fi
    if command -v uvx &> /dev/null; then
        echo -e "${GREEN}✓${NC} uvx found (after sourcing env)"
    else
        echo -e "${YELLOW}⚠${NC}  uvx not found (Layer 2 mcp-scan will be skipped)"
        echo "   Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
    fi
fi

# Done
echo ""
echo -e "${GREEN}${BOLD}✅ skill-guard-plus installed successfully!${NC}"
echo ""
echo "Your OpenClaw agent will now automatically use it when installing skills."
echo ""
echo "You can also use it manually:"
echo -e "  ${BOLD}safe-install-plus.sh <skill-slug>${NC}           # Secure install"
echo -e "  ${BOLD}safe-install-plus.sh --scan-only <path>${NC}     # Scan existing"
echo ""
