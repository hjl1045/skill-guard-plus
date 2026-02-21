---
name: skill-guard-plus
description: Security scanner for ClawHub and Claude Code skills. Scans skills before installation to detect prompt injections, malware payloads, macOS supply chain attacks, data exfiltration, and more. Also audits existing installed skills (both OpenClaw and Claude Code/.claude/skills/).
---

# skill-guard-plus — Agent Instructions

**CRITICAL: This skill MUST be used for ALL skill installations. Never run `clawhub install` directly.**

## When to Use This Skill

Use this skill when the user says any of the following:
- "install this skill" (e.g. "帮我装一个 skill")
- "add xxx skill" / "download xxx from ClawHub" (e.g. "从 ClawHub 下载 xxx")
- "check if this skill is safe" (e.g. "帮我扫描一下这个 skill")
- "scan my existing skills" (e.g. "审计一下我已装的 skills")
- "scan my claude skills" (e.g. "扫描一下我的 Claude skills")
- Any request involving `clawhub install`

## Script Location

The scanner script can be in either location (check which exists):

```bash
# In Claude Code project skills (preferred when running inside a project)
GUARD_SCRIPT=".claude/skills/skill-guard-plus/safe-install-plus.sh"

# In OpenClaw global install
GUARD_SCRIPT="$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh"

# Or via symlink
GUARD_SCRIPT="$HOME/.local/bin/safe-install-plus.sh"
```

Use whichever path exists. Prefer the project-local `.claude/skills/` path when available.

## Core Workflow

### Task A: Install a New Skill from ClawHub (CLI)

When the user asks to install a skill by name/slug (e.g. "install steipete/slack"):

**Step 1:** Run the safe installer (NEVER use `clawhub install` or `npx clawhub@latest install` directly):

```bash
bash "$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh" <skill-slug>
```

With options:
```bash
# Specific version
bash "$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh" <skill-slug> --version 1.2.3

# Overwrite existing
bash "$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh" <skill-slug> --force

# Static scan only (if uvx is not available)
bash "$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh" <skill-slug> --skip-mcp
```

**Step 2:** Read the exit code and output:

- Exit code `0` → Skill passed both scans and was installed. Tell the user: "✅ <skill-name> passed security scan and was installed successfully"
- Exit code `1` → Error (missing dependencies, network issue). Show error to user and suggest fixes.
- Exit code `2` → Security threats detected, skill was NOT installed. Tell the user: "⛔ Security issues detected, skill was NOT installed" and show the scan findings. Ask the user how they want to proceed:
  1. Review the flagged issues
  2. Install anyway (manual override): `mv /tmp/skill-guard-staging/skills/<slug> ~/.openclaw/skills/`
  3. Discard: `rm -rf /tmp/skill-guard-staging/skills/<slug>`

**Step 3:** If there were only warnings (yellow ⚠️) but no critical alerts (red 🚨), ask the user if they want to proceed.

### Task A2: Install from Downloaded Zip

When the user has already downloaded a zip from ClawHub's "Download zip" button, or provides a zip file:

```bash
# Install from zip with security scan
bash "$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh" --install-zip <path-to-zip>

# With force overwrite
bash "$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh" --install-zip <path-to-zip> --force
```

Example:
```bash
bash "$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh" --install-zip ~/Downloads/slack-v1.0.0.zip
```

The script will:
1. Extract zip to a temp staging area
2. Auto-detect the skill name from the zip filename
3. Find and scan all SKILL.md and script files inside
4. Install to `~/.openclaw/skills/<skill-name>/` only if clean

### Task B: Scan Existing Skills (Audit)

When the user asks to check/scan/audit installed skills:

**Scan a single skill:**
```bash
bash "$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh" --scan-only <path-to-skill-directory>
```

**Scan all installed skills:**
```bash
for d in "$HOME/.openclaw/skills"/*/; do
    skill_name=$(basename "$d")
    if [ "$skill_name" = "skill-guard-plus" ]; then
        continue
    fi
    echo ""
    echo "========== Scanning: $skill_name =========="
    bash "$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh" --scan-only "$d" --skip-mcp
done
```

**Scan a specific file the user provides:**
```bash
bash "$HOME/.openclaw/skills/skill-guard-plus/safe-install-plus.sh" --scan-only <path-to-file>
```

### Task B2: Scan Claude Code Skills

When the user asks to scan/audit their Claude Code skills (`.claude/skills/` directory):

**Scan all Claude Code skills in a project:**
```bash
bash ".claude/skills/skill-guard-plus/safe-install-plus.sh" --scan-claude /path/to/project --skip-mcp
```

**Scan all Claude Code skills (auto-detect from current directory + home):**
```bash
bash ".claude/skills/skill-guard-plus/safe-install-plus.sh" --scan-claude --skip-mcp
```

**Scan a single Claude Code skill:**
```bash
bash ".claude/skills/skill-guard-plus/safe-install-plus.sh" --scan-only .claude/skills/<skill-name>/ --skip-mcp
```

The `--scan-claude` flag will:
1. Auto-discover `.claude/skills/` directories (current project, home dir, and OpenClaw)
2. Iterate through all skills (skipping skill-guard-plus itself)
3. Run Layer 1 static scan on each skill
4. Print a summary with total alerts/warnings and list any failed skills

### Task C: First-Time Setup / Dependency Check

If the script fails because of missing dependencies, help the user install them:

```bash
# Check npx (ClawHub's official install method is: npx clawhub@latest install <slug>)
# npx comes with Node.js, so just need Node installed
if ! command -v npx &> /dev/null; then
    echo "npx not found. Install Node.js from https://nodejs.org"
fi

# Check uvx (needed for Layer 2 mcp-scan)
if ! command -v uvx &> /dev/null; then
    echo "uvx not found. Layer 2 (mcp-scan) will be skipped."
    echo "To enable full protection: curl -LsSf https://astral.sh/uv/install.sh | sh"
fi
```

Note: The script supports both `npx clawhub@latest` (official, preferred) and globally installed `clawhub` CLI as fallback. If uvx is not available, the script automatically falls back to Layer 1 only.

## What the Scanner Detects

### Layer 1: Static Pattern Scan (System-level attack detection)
- `curl | bash` download-and-execute chains
- `base64 --decode` obfuscation
- `xattr -c quarantine` macOS Gatekeeper bypass
- LaunchAgent/LaunchDaemon persistence mechanisms
- Credential file access (.ssh, .aws, .env, API keys)
- Tool/platform config file access (openclaw.json, credentials.json, token.json, keychain, .netrc)
- Credential-like key names in code (botToken, apiKey, apiSecret, clientSecret, password, etc.)
- Data exfiltration via POST/netcat
- Covert data embedding in output (secrets hidden in HTML comments, formatted strings)
- Commands hidden in HTML comments
- Prompt injection keywords
- Binary executable references (.exe, .dylib, .so, .mach-o)
- Non-printable character hiding

### Layer 2: mcp-scan AI Analysis (AI semantic analysis)
- Semantic prompt injection detection (catches rephrased attacks)
- Tool poisoning and cross-origin escalation
- Rug pull detection
- Hidden instruction analysis

## Important Rules for the Agent

1. **NEVER run `clawhub install` directly** — always route through safe-install-plus.sh
2. **NEVER skip both scan layers** — at minimum Layer 1 must run
3. **NEVER auto-install a skill that has critical (🚨) alerts** — always ask the user first
4. **Show specific flagged lines** so the user can make an informed decision
5. **When in doubt, err on the side of caution** — better to block a safe skill than install a malicious one
6. **Report results in English**

## Interpreting Scan Results

The scanner outputs raw alerts and warnings — but the agent's job is to **interpret them
in context**, not just relay them. Individual warnings may look harmless, but certain
combinations form attack chains that are far more dangerous than any single warning alone.

### Warning Chain Analysis

After a scan completes, look at the warnings as a group and check for these patterns:

**Credential Theft Chain** (high risk — recommend NOT installing):
- Config/credential file access + credential key extraction + data embedding in output
- Example: reads `openclaw.json` → extracts `botToken` → embeds in HTML comment
- This is a classic exfiltration pattern: the stolen data leaves the system when the
  user copies, shares, or publishes the skill's output.

**Stealth Persistence Chain** (high risk):
- System directory references + chmod +x + crontab/LaunchAgent
- The skill installs something and makes it survive reboots.

**Download-and-Execute Chain** (critical — scanner already flags this as ALERT):
- curl/wget + base64 decode + eval/exec
- Already caught by Layer 1 as CRITICAL, but if any of these appear as separate
  warnings, treat the combination as critical too.

### How to Present Findings

When warnings are detected, the agent should:

1. **List each warning** with the specific flagged line(s)
2. **Explain what each warning means** in plain language (e.g., "This code reads the
   OpenClaw config file which contains your bot token")
3. **Identify chains** — if multiple warnings form one of the patterns above, explicitly
   call it out: "These three warnings together form a credential theft chain"
4. **Give a clear recommendation**: "I recommend NOT installing this skill because..."
   or "These warnings appear benign in context because..."
5. **Never say "All clear" if there are warnings** — even if the script exits 0, the
   agent should present warnings with context and let the user decide

The goal: the user should understand *what the code does* and *why it's risky*,
not just see a list of yellow flags they have to interpret themselves.

## Common User Queries

- "install xxx skill" → Task A (install with scan via clawhub)
- "install xxx" → Task A
- "I downloaded a zip" / "install this zip" → Task A2 (install from zip)
- "is this skill safe?" → Task B (scan only)
- "scan all my skills" → Task B (batch audit for OpenClaw) or Task B2 (Claude Code skills)
- "scan my claude skills" / "扫描一下我的 Claude skills" → Task B2
- "audit this project's skills" → Task B2 with project path
- "clawhub install xxx" / "npx clawhub@latest install xxx" → Intercept! Use Task A instead
- "why can't I install?" → Check Task C (dependencies)