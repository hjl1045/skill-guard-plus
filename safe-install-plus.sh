#!/usr/bin/env bash
# ============================================================
# 🛡️ skill-guard-plus: Enhanced Secure Skill Installation
# ============================================================
# Combines:
#   1. skill-guard's staging + mcp-scan flow (Invariant/Snyk)
#   2. Custom static pattern scanner for macOS supply chain attacks
#
# Usage:
#   ./safe-install-plus.sh <skill-slug> [options]
#   ./safe-install-plus.sh --scan-only <path>    # Scan local files only
#
# Options:
#   --version <ver>   Install specific version
#   --force           Overwrite existing installation
#   --skip-scan       Skip ALL scans (not recommended)
#   --skip-mcp        Skip mcp-scan (use static scanner only)
#   --scan-only <path> Just scan, don't install
#   --help            Show help
# ============================================================

set -euo pipefail

# ── Configuration ──
SKILL_SLUG=""
VERSION_ARG=""
FORCE_ARG=""
SKIP_SCAN=false
SKIP_MCP=false
SCAN_ONLY=""
INSTALL_ZIP=""
SCAN_CLAUDE=false
CLAUDE_SKILLS_PATH=""
STAGING_DIR="/tmp/skill-guard-staging"
SKILLS_DIR="${OPENCLAW_SKILLS_DIR:-$HOME/.openclaw/skills}"
CLAWHUB_CMD=""  # Set by check_clawhub(): "npx clawhub@latest" or "clawhub"

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ── Output helpers ──
print_error()   { echo -e "${RED}ERROR:${NC} $1" >&2; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_info()    { echo -e "${BLUE}→${NC} $1"; }
alert()         { echo -e "  ${RED}🚨 [CRITICAL]${NC} $1"; }
warn()          { echo -e "  ${YELLOW}⚠️  [WARNING]${NC} $1"; }
ok()            { echo -e "  ${GREEN}✅ [OK]${NC} $1"; }
section()       { echo -e "\n  ${BOLD}── $1 ──${NC}"; }

# ── Counters for static scanner ──
STATIC_ALERTS=0
STATIC_WARNS=0
STATIC_SCANNED=0

# ============================================================
# Parse arguments
# ============================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION_ARG="--version $2"
            shift 2
            ;;
        --force)
            FORCE_ARG="--force"
            shift
            ;;
        --skip-scan)
            SKIP_SCAN=true
            shift
            ;;
        --skip-mcp)
            SKIP_MCP=true
            shift
            ;;
        --scan-only)
            SCAN_ONLY="$2"
            shift 2
            ;;
        --install-zip)
            INSTALL_ZIP="$2"
            shift 2
            ;;
        --scan-claude)
            SCAN_CLAUDE=true
            if [[ $# -gt 1 ]] && [[ ! "$2" =~ ^- ]]; then
                CLAUDE_SKILLS_PATH="$2"
                shift 2
            else
                shift
            fi
            ;;
        --help|-h)
            cat <<'EOF'
🛡️ skill-guard-plus: Enhanced Secure Skill Installation

Usage:
  ./safe-install-plus.sh <skill-slug> [options]     # Mode A: from ClawHub
  ./safe-install-plus.sh --install-zip <zip> [options]  # Mode B: from downloaded zip
  ./safe-install-plus.sh --scan-only <path>          # Mode C: scan only
  ./safe-install-plus.sh --scan-claude [path]        # Mode D: scan Claude Code skills

Mode A — Install from ClawHub (uses npx clawhub@latest):
  ./safe-install-plus.sh steipete/slack
  ./safe-install-plus.sh steipete/slack --version 1.0.0
  ./safe-install-plus.sh steipete/slack --force

Mode B — Install from downloaded zip (e.g. ClawHub "Download zip"):
  ./safe-install-plus.sh --install-zip ~/Downloads/slack-v1.0.0.zip
  ./safe-install-plus.sh --install-zip ~/Downloads/slack.zip --force

Mode C — Scan only (no install):
  ./safe-install-plus.sh --scan-only ~/.openclaw/skills/some-skill/
  ./safe-install-plus.sh --scan-only ~/Downloads/SKILL.md

Mode D — Scan Claude Code skills:
  ./safe-install-plus.sh --scan-claude                    # Auto-detect .claude/skills/
  ./safe-install-plus.sh --scan-claude /path/to/project   # Scan specific project

Options:
  --version <ver>    Install specific version (Mode A only)
  --force            Overwrite existing installation
  --skip-scan        Skip ALL scans (not recommended)
  --skip-mcp         Skip mcp-scan (use static scanner only)
  --help             Show this help

Exit Codes:
  0  Clean — skill installed (or scan passed)
  1  Error — missing dependencies or network issue
  2  Threats found — skill quarantined, review before deciding
EOF
            exit 0
            ;;
        -*)
            print_error "Unknown option: $1"
            exit 1
            ;;
        *)
            SKILL_SLUG="$1"
            shift
            ;;
    esac
done

# ============================================================
# LAYER 1: Static Pattern Scanner (macOS supply chain focus)
# ============================================================
# Detects: curl|bash chains, base64 obfuscation, Gatekeeper
# bypass, persistence mechanisms, data exfiltration, prompt
# injection, binary payloads, hidden characters
# ============================================================

static_scan_file() {
    local file="$1"
    local filename=$(basename "$file")
    local dir=$(dirname "$file")
    local skill_name=$(basename "$dir")
    local file_issues=0

    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  📄 Static scan: ${BOLD}${skill_name}/${filename}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # ── 1: Network / Download ──
    section "Network Requests & Downloads"

    if grep -inE '(curl|wget)\s+.*https?://' "$file" > /dev/null 2>&1; then
        alert "curl/wget with external URL:"
        grep -inE '(curl|wget)\s+.*https?://' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    else
        ok "No external download commands"
    fi

    if grep -inE 'curl.*\|\s*(ba)?sh' "$file" > /dev/null 2>&1; then
        alert "CRITICAL: curl piped to shell (curl | bash):"
        grep -inE 'curl.*\|\s*(ba)?sh' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    fi

    if grep -inE 'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$file" > /dev/null 2>&1; then
        alert "Raw IP address URLs (legitimate services use domains):"
        grep -inE 'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    else
        ok "No raw IP URLs"
    fi

    # ── 2: Encoding / Obfuscation ──
    section "Encoding & Obfuscation"

    if grep -inE '(base64\s+(-d|--decode|-D)|echo.*\|\s*base64)' "$file" > /dev/null 2>&1; then
        alert "base64 decode operations:"
        grep -inE '(base64\s+(-d|--decode|-D)|echo.*\|\s*base64)' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    else
        ok "No base64 decode operations"
    fi

    if grep -inE '\b(eval|exec)\b.*\$' "$file" > /dev/null 2>&1; then
        alert "eval/exec with variables (code injection risk):"
        grep -inE '\b(eval|exec)\b.*\$' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    fi

    if grep -inE '\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}' "$file" > /dev/null 2>&1; then
        warn "Hex-encoded strings (could be obfuscated):"
        grep -inE '\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}' "$file" | head -3 | while read -r line; do
            echo -e "    ${YELLOW}→ $line${NC}"
        done
        ((STATIC_WARNS++))
    fi

    if grep -inE 'python.*-c.*import|python.*exec\(|python.*eval\(' "$file" > /dev/null 2>&1; then
        warn "Python inline execution"
        ((STATIC_WARNS++))
    else
        ok "No inline code execution"
    fi

    # ── 3: System Modification (macOS-focused) ──
    section "System Modification / macOS Attacks"

    if grep -inE 'chmod\s+\+x' "$file" > /dev/null 2>&1; then
        warn "chmod +x (making files executable):"
        grep -inE 'chmod\s+\+x' "$file" | while read -r line; do
            echo -e "    ${YELLOW}→ $line${NC}"
        done
        ((STATIC_WARNS++))
    else
        ok "No chmod +x commands"
    fi

    if grep -inE 'xattr.*quarantine|xattr\s+-[crd]' "$file" > /dev/null 2>&1; then
        alert "macOS Gatekeeper bypass (quarantine removal):"
        grep -inE 'xattr.*quarantine|xattr\s+-[crd]' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    else
        ok "No Gatekeeper bypass"
    fi

    if grep -inE '(LaunchAgent|LaunchDaemon|launchctl|\.plist)' "$file" > /dev/null 2>&1; then
        alert "macOS persistence mechanism (LaunchAgent/Daemon):"
        grep -inE '(LaunchAgent|LaunchDaemon|launchctl|\.plist)' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    fi

    if grep -inE '(crontab|/etc/cron)' "$file" > /dev/null 2>&1; then
        warn "Crontab references (persistence)"
        ((STATIC_WARNS++))
    fi

    if grep -inE '(\/usr\/local\/bin|\/etc\/|\/Library\/|\/System\/)' "$file" > /dev/null 2>&1; then
        warn "References to system directories:"
        grep -inE '(\/usr\/local\/bin|\/etc\/|\/Library\/|\/System\/)' "$file" | head -3 | while read -r line; do
            echo -e "    ${YELLOW}→ $line${NC}"
        done
        ((STATIC_WARNS++))
    fi

    # ── 4: Data Exfiltration ──
    section "Data Exfiltration"

    if grep -inE '(\.ssh|\.aws|\.env\b|\.git/config|\.npmrc|id_rsa|api.key|API_KEY|SECRET_KEY|ACCESS_TOKEN|GITHUB_TOKEN)' "$file" > /dev/null 2>&1; then
        warn "References to sensitive files/credentials:"
        grep -inE '(\.ssh|\.aws|\.env\b|\.git/config|\.npmrc|id_rsa|api.key|API_KEY|SECRET_KEY|ACCESS_TOKEN|GITHUB_TOKEN)' "$file" | head -5 | while read -r line; do
            echo -e "    ${YELLOW}→ $line${NC}"
        done
        ((STATIC_WARNS++))
    else
        ok "No sensitive file references"
    fi

    # Check for OpenClaw / tool-specific config file access
    # Skills should not need to read the tool's own config (tokens, policies, settings).
    # This catches attacks that target the host tool's credentials rather than
    # well-known system files like .ssh or .aws.
    if grep -inE '(openclaw\.json|clawhub\.json|\.openclaw/|\.clawhub/|config\.json.*token|credentials\.json|\.netrc\b|token\.json|keychain|keyring)' "$file" > /dev/null 2>&1; then
        warn "References to tool/platform config files (may contain credentials):"
        grep -inE '(openclaw\.json|clawhub\.json|\.openclaw/|\.clawhub/|config\.json.*token|credentials\.json|\.netrc\b|token\.json|keychain|keyring)' "$file" | head -5 | while read -r line; do
            echo -e "    ${YELLOW}→ $line${NC}"
        done
        ((STATIC_WARNS++))
    else
        ok "No tool/platform config references"
    fi

    # Check for credential-like variable/key names in code
    # Legitimate skills rarely need to read tokens, secrets, or passwords from
    # config files. This pattern catches code that extracts credential values
    # even if the file path itself isn't in the sensitive-files list.
    # Scoped to assignment/access patterns to reduce false positives from docs or comments.
    if grep -inE '([\"\x27])(bot_?token|api_?key|api_?secret|auth_?token|access_?token|refresh_?token|client_?secret|private_?key|secret_?key|password|passwd|dm_?policy)\1' "$file" > /dev/null 2>&1; then
        warn "Code references credential-like keys (token/secret/password):"
        grep -inE '([\"\x27])(bot_?token|api_?key|api_?secret|auth_?token|access_?token|refresh_?token|client_?secret|private_?key|secret_?key|password|passwd|dm_?policy)\1' "$file" | head -5 | while read -r line; do
            echo -e "    ${YELLOW}→ $line${NC}"
        done
        ((STATIC_WARNS++))
    else
        ok "No credential-like key references"
    fi

    if grep -inE '(curl.*(-X\s*POST|-d\s)|curl.*--data|\bnc\s+-|\bnetcat\b|\bncat\b)' "$file" > /dev/null 2>&1; then
        alert "Data exfiltration patterns (POST/netcat):"
        grep -inE '(curl.*(-X\s*POST|-d\s)|curl.*--data|\bnc\s+-|\bnetcat\b|\bncat\b)' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    else
        ok "No data exfiltration patterns"
    fi

    # Check for sensitive data embedded in output (covert exfiltration)
    # Instead of sending data over the network, an attacker can embed secrets
    # in the skill's normal output — HTML comments, log lines, filenames, etc.
    # The stolen data then leaves the system when the user shares the output.
    if grep -inE '(<!--.*\{|<!--.*\$|<!--.*token|<!--.*secret|<!--.*key|f["\x27].*<!--.*\{|\.format\(.*token|\.format\(.*secret|%s.*token)' "$file" > /dev/null 2>&1; then
        warn "Possible data embedding in HTML comments or formatted output:"
        grep -inE '(<!--.*\{|<!--.*\$|<!--.*token|<!--.*secret|<!--.*key|f["\x27].*<!--.*\{|\.format\(.*token|\.format\(.*secret|%s.*token)' "$file" | head -5 | while read -r line; do
            echo -e "    ${YELLOW}→ $line${NC}"
        done
        ((STATIC_WARNS++))
    else
        ok "No suspicious data embedding patterns"
    fi

    # ── 5: Prompt Injection / Hidden Commands ──
    section "Prompt Injection & Hidden Commands"

    if grep -inE '<!--.*\b(curl|wget|bash|sh|python|eval|exec)\b.*-->' "$file" > /dev/null 2>&1; then
        alert "Commands hidden in HTML comments:"
        grep -inE '<!--.*\b(curl|wget|bash|sh|python|eval|exec)\b.*-->' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    else
        ok "No hidden HTML comment commands"
    fi

    if grep -inE '(ignore (previous|above|all) instructions|do not (tell|inform|alert)|disregard.*instruction|override.*safety)' "$file" > /dev/null 2>&1; then
        alert "Prompt injection attempt:"
        grep -inE '(ignore (previous|above|all) instructions|do not (tell|inform|alert)|disregard.*instruction)' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    else
        ok "No prompt injection patterns"
    fi

    if grep -inE '(nohup|disown|screen\s+-dm|tmux\s+new.*-d)' "$file" > /dev/null 2>&1; then
        warn "Background/stealth execution"
        ((STATIC_WARNS++))
    fi

    # ── 6: Binary references ──
    section "Binary References"

    if grep -inE '\.(bin|exe|elf|dylib|so|dll|app|mach-o)\b' "$file" > /dev/null 2>&1; then
        alert "Binary/executable file references:"
        grep -inE '\.(bin|exe|elf|dylib|so|dll|app|mach-o)\b' "$file" | while read -r line; do
            echo -e "    ${RED}→ $line${NC}"
        done
        ((STATIC_ALERTS++)); ((file_issues++))
    else
        ok "No binary file references"
    fi

    # ── 7: File metadata ──
    section "File Metadata"

    local filesize=$(wc -c < "$file" 2>/dev/null)
    local linecount=$(wc -l < "$file" 2>/dev/null)

    if [ "$filesize" -gt 50000 ]; then
        warn "Unusually large file (${filesize} bytes)"
        ((STATIC_WARNS++))
    else
        ok "File size: ${filesize} bytes, ${linecount} lines"
    fi

    # Check for non-printable characters (exclude valid UTF-8 multibyte like CJK)
    local nonprint_count
    nonprint_count=$(grep -cP '[\x00-\x08\x0E-\x1F\x7F]' "$file" 2>/dev/null || true)
    # grep -c may return empty on some grep builds/files; normalize to integer
    if [[ ! "$nonprint_count" =~ ^[0-9]+$ ]]; then
        nonprint_count=0
    fi

    if [ "$nonprint_count" -gt 0 ]; then
        alert "Found ${nonprint_count} lines with non-printable characters"
        ((STATIC_ALERTS++)); ((file_issues++))
    else
        ok "No hidden non-printable characters"
    fi

    ((STATIC_SCANNED++))
    return $file_issues
}

static_scan_directory() {
    local dir="$1"
    local total_issues=0

    local files=$(find "$dir" -type f \( \
        -name "SKILL.md" -o \
        -name "*.sh" -o \
        -name "*.py" -o \
        -name "*.js" -o \
        -name "*.ts" -o \
        -name "install*" -o \
        -name "setup*" -o \
        -name "*.yaml" -o \
        -name "*.yml" -o \
        -name "*.json" \
    \) 2>/dev/null)

    if [ -z "$files" ]; then
        print_warning "No scannable files found in: $dir"
        return 0
    fi

    while IFS= read -r file; do
        local issues=0
        static_scan_file "$file" || issues=$?
        total_issues=$((total_issues + issues))
    done <<< "$files"

    return $total_issues
}

run_static_scan() {
    local target="$1"
    local issues=0

    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║  🔬 LAYER 1: Static Pattern Scan                   ║${NC}"
    echo -e "${BOLD}║     Detecting system-level attack patterns           ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"

    if [ -f "$target" ]; then
        static_scan_file "$target" || issues=$?
    elif [ -d "$target" ]; then
        static_scan_directory "$target" || issues=$?
    fi

    echo ""
    echo -e "  ${BOLD}📊 Static Scan Results:${NC}"
    echo -e "  Files scanned: ${STATIC_SCANNED}"
    if [ $STATIC_ALERTS -gt 0 ]; then
        echo -e "  ${RED}🚨 Critical: ${STATIC_ALERTS}${NC}"
    fi
    if [ $STATIC_WARNS -gt 0 ]; then
        echo -e "  ${YELLOW}⚠️  Warnings: ${STATIC_WARNS}${NC}"
    fi
    if [ $STATIC_ALERTS -eq 0 ] && [ $STATIC_WARNS -eq 0 ]; then
        echo -e "  ${GREEN}✅ All clean${NC}"
    fi

    return $issues
}

# ============================================================
# LAYER 2: mcp-scan (Invariant/Snyk AI security scanner)
# ============================================================
# Detects: prompt injections via semantic analysis, tool
# poisoning, cross-origin escalation, rug pulls
# ============================================================

run_mcp_scan() {
    local target="$1"

    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║  🤖 LAYER 2: mcp-scan (Invariant/Snyk)             ║${NC}"
    echo -e "${BOLD}║     AI semantic analysis + Prompt Injection detection ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    if ! command -v uvx &> /dev/null; then
        if [[ -f "$HOME/.local/bin/env" ]]; then
            source "$HOME/.local/bin/env" 2>/dev/null || true
        fi
        if ! command -v uvx &> /dev/null; then
            print_warning "uvx not found — skipping mcp-scan layer"
            print_info "Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
            return 0  # Don't fail, just skip
        fi
    fi

    local scan_output
    local scan_exit_code=0

    scan_output=$(uvx mcp-scan@latest --skills "$target" 2>&1) || scan_exit_code=$?

    echo "$scan_output"
    echo ""

    if echo "$scan_output" | grep -Eqi "vulnerability|injection|malware|secret found|unsafe|high risk|medium risk|critical"; then
        print_warning "mcp-scan found issues"
        return 1
    fi

    if [[ $scan_exit_code -ne 0 ]]; then
        print_warning "mcp-scan exited with code: $scan_exit_code"
        return 1
    fi

    print_success "mcp-scan: no issues detected"
    return 0
}

# ============================================================
# Install flow (staging → scan → install)
# ============================================================

check_clawhub() {
    # ClawHub's official install method is: npx clawhub@latest install <slug>
    # Also support globally installed clawhub CLI as fallback
    if command -v npx &> /dev/null; then
        CLAWHUB_CMD="npx clawhub@latest"
        print_info "Using: npx clawhub@latest (official method)"
    elif command -v clawhub &> /dev/null; then
        CLAWHUB_CMD="clawhub"
        print_info "Using: global clawhub CLI"
    else
        print_error "Neither npx nor clawhub found."
        echo "  Install Node.js (includes npx): https://nodejs.org"
        echo "  Or install clawhub globally:     npm i -g clawhub"
        exit 1
    fi
}

stage_skill() {
    print_info "Fetching $SKILL_SLUG to staging area..."

    rm -rf "$STAGING_DIR/skills/$SKILL_SLUG"
    mkdir -p "$STAGING_DIR"

    # Use detected command (npx clawhub@latest or global clawhub)
    if ! $CLAWHUB_CMD install "$SKILL_SLUG" $VERSION_ARG --workdir "$STAGING_DIR" 2>&1; then
        print_error "Failed to fetch skill from ClawHub"
        print_info "Tried: $CLAWHUB_CMD install $SKILL_SLUG $VERSION_ARG --workdir $STAGING_DIR"
        exit 1
    fi

    # clawhub installs to <workdir>/skills/<slug>/
    if [[ ! -d "$STAGING_DIR/skills/$SKILL_SLUG" ]]; then
        # Some versions may install to <workdir>/<slug>/ instead
        if [[ -d "$STAGING_DIR/$SKILL_SLUG" ]]; then
            mkdir -p "$STAGING_DIR/skills"
            mv "$STAGING_DIR/$SKILL_SLUG" "$STAGING_DIR/skills/$SKILL_SLUG"
        else
            print_error "Skill not found in staging after download"
            print_info "Checked: $STAGING_DIR/skills/$SKILL_SLUG"
            print_info "Checked: $STAGING_DIR/$SKILL_SLUG"
            print_info "Staging contents:"
            ls -la "$STAGING_DIR/" 2>/dev/null || true
            ls -la "$STAGING_DIR/skills/" 2>/dev/null || true
            exit 1
        fi
    fi

    print_success "Staged at $STAGING_DIR/skills/$SKILL_SLUG"
}

install_skill() {
    print_info "Installing $SKILL_SLUG to $SKILLS_DIR..."

    mkdir -p "$SKILLS_DIR"
    local staged_path="$STAGING_DIR/skills/$SKILL_SLUG"

    if [[ -d "$SKILLS_DIR/$SKILL_SLUG" ]]; then
        if [[ -n "$FORCE_ARG" ]]; then
            rm -rf "$SKILLS_DIR/$SKILL_SLUG"
        else
            print_error "Skill exists at $SKILLS_DIR/$SKILL_SLUG (use --force to overwrite)"
            exit 1
        fi
    fi

    mv "$staged_path" "$SKILLS_DIR/"
    print_success "Installed $SKILL_SLUG to $SKILLS_DIR/$SKILL_SLUG"
}

cleanup() {
    rm -rf "$STAGING_DIR/skills/$SKILL_SLUG" 2>/dev/null || true
}

# ============================================================
# Main
# ============================================================

print_banner() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${BOLD}🛡️ skill-guard-plus v1.1${NC}                            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${BOLD}   Enhanced Secure Skill Installation${NC}                ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  Layer 1: Static pattern scan (macOS supply chain attacks)      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  Layer 2: mcp-scan AI semantic analysis              ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── Scan Claude Code skills mode ──
if [[ "$SCAN_CLAUDE" == "true" ]]; then
    print_banner
    echo -e "${BOLD}🔍 Scanning Claude Code skills...${NC}"
    echo ""

    # Build list of .claude/skills/ directories to scan
    claude_dirs=()

    if [[ -n "$CLAUDE_SKILLS_PATH" ]]; then
        # User specified a path — look for .claude/skills/ inside it
        if [[ -d "$CLAUDE_SKILLS_PATH/.claude/skills" ]]; then
            claude_dirs+=("$CLAUDE_SKILLS_PATH/.claude/skills")
        elif [[ -d "$CLAUDE_SKILLS_PATH" ]]; then
            # Maybe they pointed directly at a .claude/skills dir or a single skill
            claude_dirs+=("$CLAUDE_SKILLS_PATH")
        else
            print_error "Path not found: $CLAUDE_SKILLS_PATH"
            exit 1
        fi
    else
        # Auto-detect: check common locations
        # 1. Current directory's .claude/skills/
        if [[ -d "./.claude/skills" ]]; then
            claude_dirs+=("$(pwd)/.claude/skills")
        fi
        # 2. Home directory ~/.claude/skills/ (global Claude Code skills)
        if [[ -d "$HOME/.claude/skills" ]]; then
            claude_dirs+=("$HOME/.claude/skills")
        fi
        # 3. Also check OpenClaw skills for completeness
        if [[ -d "$SKILLS_DIR" ]]; then
            claude_dirs+=("$SKILLS_DIR")
        fi
    fi

    if [[ ${#claude_dirs[@]} -eq 0 ]]; then
        print_error "No Claude Code skills directories found"
        print_info "Try: $0 --scan-claude /path/to/your/project"
        exit 1
    fi

    total_skills=0
    total_alerts=0
    total_warns=0
    failed_skills=()

    for skills_root in "${claude_dirs[@]}"; do
        echo ""
        echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}  📂 ${BOLD}$skills_root${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

        for skill_dir in "$skills_root"/*/; do
            [[ ! -d "$skill_dir" ]] && continue
            skill_name=$(basename "$skill_dir")

            # Skip scanning ourselves
            if [[ "$skill_name" == "skill-guard-plus" ]]; then
                echo ""
                print_info "Skipping self: $skill_name"
                continue
            fi

            total_skills=$((total_skills + 1))

            # Reset counters for each skill
            STATIC_ALERTS=0
            STATIC_WARNS=0
            STATIC_SCANNED=0

            echo ""
            echo -e "${BOLD}========== Scanning: $skill_name ==========${NC}"

            skill_issues=0
            run_static_scan "$skill_dir" || skill_issues=$?

            if [[ "$SKIP_MCP" != "true" ]]; then
                run_mcp_scan "$skill_dir" || skill_issues=$((skill_issues + $?))
            fi

            total_alerts=$((total_alerts + STATIC_ALERTS))
            total_warns=$((total_warns + STATIC_WARNS))

            if [[ $STATIC_ALERTS -gt 0 ]]; then
                failed_skills+=("$skill_name")
            fi
        done
    done

    # Summary
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  ${BOLD}📋 Claude Skills Scan Summary${NC}              ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Skills scanned: ${BOLD}$total_skills${NC}"
    if [[ $total_alerts -gt 0 ]]; then
        echo -e "  ${RED}🚨 Critical alerts: $total_alerts${NC}"
    fi
    if [[ $total_warns -gt 0 ]]; then
        echo -e "  ${YELLOW}⚠️  Warnings: $total_warns${NC}"
    fi
    if [[ ${#failed_skills[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${RED}Skills with critical issues:${NC}"
        for s in "${failed_skills[@]}"; do
            echo -e "    ${RED}⛔ $s${NC}"
        done
        echo ""
        exit 2
    else
        echo -e "  ${GREEN}${BOLD}✅ All skills passed${NC}"
        exit 0
    fi
fi

# ── Scan-only mode ──
if [[ -n "$SCAN_ONLY" ]]; then
    print_banner

    if [[ ! -e "$SCAN_ONLY" ]]; then
        print_error "Path not found: $SCAN_ONLY"
        exit 1
    fi

    static_issues=0
    mcp_issues=0

    run_static_scan "$SCAN_ONLY" || static_issues=$?

    if [[ "$SKIP_MCP" != "true" ]]; then
        run_mcp_scan "$SCAN_ONLY" || mcp_issues=$?
    fi

    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  ${BOLD}📋 Final Verdict${NC}                         ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

    if [[ $static_issues -gt 0 ]] || [[ $mcp_issues -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}⛔ Critical issues detected — review before using this skill${NC}"
        exit 2
    elif [[ $STATIC_WARNS -gt 0 ]]; then
        echo -e "  ${YELLOW}${BOLD}⚠️  ${STATIC_WARNS} warning(s) found — review recommended${NC}"
        echo -e "  Warnings don't block installation but may indicate risky behavior."
        echo -e "  Ask the agent to explain what these warnings mean in context."
        exit 0
    else
        echo -e "  ${GREEN}${BOLD}✅ All clear — skill appears safe${NC}"
        exit 0
    fi
fi

# ── Zip install mode ──
if [[ -n "$INSTALL_ZIP" ]]; then
    print_banner

    if [[ ! -f "$INSTALL_ZIP" ]]; then
        print_error "Zip file not found: $INSTALL_ZIP"
        exit 1
    fi

    # Extract to staging
    print_info "Extracting zip to staging area..."
    rm -rf "$STAGING_DIR/zip-extract"
    mkdir -p "$STAGING_DIR/zip-extract"

    if ! unzip -q "$INSTALL_ZIP" -d "$STAGING_DIR/zip-extract" 2>&1; then
        print_error "Failed to extract zip file"
        exit 1
    fi

    # Find the skill directory (look for SKILL.md)
    local_skill_dir=""
    skill_md_path=$(find "$STAGING_DIR/zip-extract" -name "SKILL.md" -type f | head -1)

    if [[ -n "$skill_md_path" ]]; then
        local_skill_dir=$(dirname "$skill_md_path")
    else
        # No SKILL.md found, use the top-level extracted directory
        local_skill_dir=$(find "$STAGING_DIR/zip-extract" -mindepth 1 -maxdepth 1 -type d | head -1)
        if [[ -z "$local_skill_dir" ]]; then
            local_skill_dir="$STAGING_DIR/zip-extract"
        fi
    fi

    # Determine skill name from directory name or zip filename
    zip_basename=$(basename "$INSTALL_ZIP" .zip)
    # Remove version suffix like -v1.0.0 or -1.0.0
    skill_name=$(echo "$zip_basename" | sed 's/-v\?[0-9][0-9.]*$//')
    print_info "Detected skill name: $skill_name"
    print_info "Skill content at: $local_skill_dir"

    # Scan
    if [[ "$SKIP_SCAN" != "true" ]]; then
        static_issues=0
        mcp_issues=0

        run_static_scan "$local_skill_dir" || static_issues=$?

        if [[ "$SKIP_MCP" != "true" ]]; then
            run_mcp_scan "$local_skill_dir" || mcp_issues=$?
        fi

        echo ""
        echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║  ${BOLD}📋 Final Verdict${NC}                         ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

        if [[ $STATIC_ALERTS -gt 0 ]] || [[ $mcp_issues -gt 0 ]]; then
            echo ""
            print_warning "Security issues detected in $skill_name"
            echo ""
            echo "  The skill is extracted but ${BOLD}NOT installed${NC}."
            echo "  Staged at: $local_skill_dir"
            echo ""
            echo "  Options:"
            echo "    1. Review the issues above"
            echo "    2. Install anyway: mv $local_skill_dir $SKILLS_DIR/$skill_name"
            echo "    3. Discard: rm -rf $STAGING_DIR/zip-extract"
            echo ""
            exit 2
        fi
    fi

    # Install
    print_info "Installing $skill_name to $SKILLS_DIR/$skill_name..."
    mkdir -p "$SKILLS_DIR"

    if [[ -d "$SKILLS_DIR/$skill_name" ]]; then
        if [[ -n "$FORCE_ARG" ]]; then
            rm -rf "$SKILLS_DIR/$skill_name"
        else
            print_error "Skill exists at $SKILLS_DIR/$skill_name (use --force to overwrite)"
            exit 1
        fi
    fi

    # Copy skill content (not the zip-extract wrapper)
    cp -r "$local_skill_dir" "$SKILLS_DIR/$skill_name"
    rm -rf "$STAGING_DIR/zip-extract"

    echo ""
    print_success "Installed $skill_name to $SKILLS_DIR/$skill_name"
    exit 0
fi

# ── Install mode ──
if [[ -z "$SKILL_SLUG" ]]; then
    print_error "No skill slug provided"
    echo "Usage: ./safe-install-plus.sh <skill-slug> [options]"
    echo "       ./safe-install-plus.sh --scan-only <path>"
    exit 1
fi

print_banner
check_clawhub
stage_skill

staged_path="$STAGING_DIR/skills/$SKILL_SLUG"

if [[ "$SKIP_SCAN" == "true" ]]; then
    print_warning "Skipping ALL scans (--skip-scan)"
    install_skill
    cleanup
    print_success "Installation complete (scans skipped)"
    exit 0
fi

# Run both scan layers
static_issues=0
mcp_issues=0

run_static_scan "$staged_path" || static_issues=$?

if [[ "$SKIP_MCP" != "true" ]]; then
    run_mcp_scan "$staged_path" || mcp_issues=$?
fi

# Final decision
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  ${BOLD}📋 Final Verdict${NC}                         ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

if [[ $STATIC_ALERTS -gt 0 ]] || [[ $mcp_issues -gt 0 ]]; then
    echo ""
    print_warning "Security issues detected in $SKILL_SLUG"
    echo ""
    echo "  The skill is staged but ${BOLD}NOT installed${NC}."
    echo "  Staged at: $staged_path"
    echo ""
    echo "  Options:"
    echo "    1. Review the issues above"
    echo "    2. Install anyway: mv $staged_path $SKILLS_DIR/"
    echo "    3. Discard: rm -rf $staged_path"
    echo ""
    exit 2
elif [[ $STATIC_WARNS -gt 0 ]]; then
    echo ""
    print_warning "Warnings found (no critical issues)"
    echo ""
    read -p "  Install anyway? [Y/n] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "  Skill left in staging: $staged_path"
        exit 2
    fi
    install_skill
    cleanup
    print_success "Installation complete"
    exit 0
else
    echo -e "  ${GREEN}${BOLD}✅ All clear${NC}"
    install_skill
    cleanup
    echo ""
    print_success "Installation complete"
    exit 0
fi
