# 🛡️ skill-guard-plus

**Two-layer security scanner for OpenClaw / ClawHub skills.**

Scans skills before installation to detect prompt injections, malware payloads, macOS supply chain attacks, data exfiltration, and more.

## The Problem

ClawHub skills are powerful — your agent trusts and executes whatever is in SKILL.md. One malicious skill can:

- Read your SSH keys, API tokens, and credentials
- Download and execute binaries on your machine
- Bypass macOS Gatekeeper and persist across reboots
- Modify your agent's behavior permanently

ClawHub runs VirusTotal server-side, but it doesn't catch AI-specific threats like prompt injections or disguised shell commands. **skill-guard-plus adds client-side scanning before anything touches your system.**

## How It Works

Two complementary scan layers:

| Layer | Engine | Catches |
|-------|--------|---------|
| **Layer 1** | Static pattern matching | `curl\|bash` chains, base64 obfuscation, macOS Gatekeeper bypass (`xattr -c`), LaunchAgent persistence, credential access, data exfiltration, hidden characters |
| **Layer 2** | mcp-scan (Invariant/Snyk) | Semantic prompt injection, tool poisoning, cross-origin escalation, rug pulls |

Either layer flagging a critical issue blocks the install.

## Quick Start

### Install

```bash
# Download the three files: setup.sh, safe-install-plus.sh, SKILL.md
# Put them in the same folder, then:

chmod +x setup.sh
./setup.sh
```

This installs skill-guard-plus to `~/.openclaw/skills/skill-guard-plus/` and symlinks the script to `~/.local/bin/` for convenience.

### Dependencies

| What | Why | Install |
|------|-----|---------|
| Node.js (npx) | ClawHub downloads | [nodejs.org](https://nodejs.org) |
| uv (optional) | Layer 2 mcp-scan | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

Without uv, only Layer 1 runs (still catches most system-level attacks).

## Usage

### Install a skill from ClawHub

```bash
# Instead of: npx clawhub@latest install steipete/slack
safe-install-plus.sh steipete/slack

# With version
safe-install-plus.sh steipete/slack --version 1.0.0

# Force overwrite
safe-install-plus.sh steipete/slack --force
```

### Install from downloaded zip

```bash
safe-install-plus.sh --install-zip ~/Downloads/slack-v1.0.0.zip
```

### Scan existing skills (audit)

```bash
# Scan one skill
safe-install-plus.sh --scan-only ~/.openclaw/skills/some-skill/

# Scan ALL installed skills
for d in ~/.openclaw/skills/*/; do
    safe-install-plus.sh --scan-only "$d"
done
```

### Options

```
--version <ver>    Specific version (ClawHub mode)
--force            Overwrite existing install
--skip-mcp         Skip Layer 2 (no uvx needed)
--skip-scan        Skip ALL scans (not recommended)
--install-zip <f>  Install from zip file
--scan-only <path> Scan without installing
```

## Exit Codes

| Code | Meaning | What Happens |
|------|---------|-------------|
| 0 | Clean ✅ | Skill installed (or scan passed) |
| 1 | Error | Missing deps or network issue |
| 2 | Threats ⛔ | Skill quarantined in `/tmp/`, NOT installed |

When threats are found, the skill stays in `/tmp/skill-guard-staging/`. You can review, install manually, or discard.

## Agent Integration

skill-guard-plus installs as an OpenClaw skill. The SKILL.md instructs your agent to **always** route skill installs through the scanner. After setup, just tell your agent:

> "Install steipete/slack"

And it will automatically: download → scan → install (or block).

## What Gets Detected

Real-world example — some Skill from ClawHub incident:

```
SKILL.md contains:
  base64 --decode → bash    ← Layer 1 catches this
  curl http://91.92.242.30  ← Layer 1 catches this (raw IP)
  xattr -c quarantine       ← Layer 1 catches this (Gatekeeper bypass)
  chmod +x                  ← Layer 1 flags this
  
VirusTotal: 0/76 engines    ← Traditional AV missed it completely
```

## File Structure

```
~/.openclaw/skills/skill-guard-plus/
├── SKILL.md                 # Agent instructions (don't edit)
├── safe-install-plus.sh     # The scanner script
└── README.md                # This file
```

## Customization

Set a custom skills directory:
```bash
export OPENCLAW_SKILLS_DIR="$HOME/my-custom-skills-path"
```

## Limitations

- Static scanning catches known patterns, not zero-days
- mcp-scan requires internet access for AI analysis
- Can't scan runtime behavior (only pre-install static analysis)
- May produce false positives on legitimate skills that use network commands

**This tool significantly raises the bar for attackers, but no scanner is 100%.** Always review flagged items manually.

## License

MIT

## Credits

- [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) by Invariant Labs (Snyk) — Layer 2 engine
- Inspired by the [skill-guard](https://github.com/anthropics/skill-guard) project
- Built with Claude
