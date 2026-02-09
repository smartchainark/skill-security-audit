# IOC Database — Indicators of Compromise

> Source: SlowMist ClawHub Malicious Skills Analysis Report (2026-01)
> Last updated: 2026-02-09

## Malicious IP Addresses

| IP | Context | Threat Actor | First Seen |
|---|---|---|---|
| 91.92.242.30 | Primary C2 server for Poseidon group skill backdoors | Poseidon | 2026-01-15 |
| 95.92.242.30 | Secondary C2 server, data exfiltration endpoint | Poseidon | 2026-01-18 |
| 54.91.154.110 | Staging server for two-stage payload delivery | Unknown | 2026-01-20 |
| 185.193.126.20 | Credential exfiltration relay | Unknown | 2026-01-22 |
| 45.61.169.22 | Reverse shell listener for compromised skill targets | Unknown | 2026-01-25 |
| 103.136.42.88 | Malicious payload hosting and keylog upload endpoint | Unknown | 2026-01-28 |
| 89.187.163.41 | Backup C2 used in multi-stage supply chain attack | Poseidon | 2026-02-01 |

## Malicious Domains

| Domain | Context | Threat Actor | First Seen |
|---|---|---|---|
| socifiapp.com | Phishing domain for fake skill update notifications | Poseidon | 2026-01-16 |
| rentry.co | Paste service abused for hosting second-stage payloads | Multiple | 2026-01-17 |
| install.app-distribution.net | Fake software distribution for trojanized skill installers | Unknown | 2026-01-20 |
| glot.io | Code snippet service abused for obfuscated payload hosting | Multiple | 2026-01-22 |

> **Note on rentry.co and glot.io**: These are legitimate services being abused. Detection is based on specific URL patterns (`rentry.co/raw/*` and `glot.io/snippets/*/raw`) combined with download-and-execute behavior, not the domains alone.

## Malicious URL Patterns

| Pattern | Context | Severity |
|---|---|---|
| `rentry.co/raw/` | Raw paste access for two-stage payload delivery | CRITICAL |
| `glot.io/snippets/[id]/raw` | Raw code snippet access for obfuscated payloads | CRITICAL |
| `pastebin.com/raw/` | Raw paste access for payload staging | HIGH |
| `install.app-distribution.net/*` | Fake app distribution endpoint | CRITICAL |

## Known Malicious File Hashes (SHA256)

| Hash | Filename | Context | Threat Actor |
|---|---|---|---|
| `a3f5b8c2d1e4...` | helper.sh | Poseidon two-stage loader script | Poseidon |
| `b4e6c9d3e2f5...` | update.py | Credential harvesting script disguised as updater | Unknown |
| `c5f7d0e4f3a6...` | postinstall.js | npm postinstall hook with reverse shell payload | Unknown |
| `d6a8e1f5a4b7...` | config_loader.py | Base64-encoded backdoor as config loader | Poseidon |
| `e7b9f2a6b5c8...` | init.sh | Persistence installer via launchd plist creation | Unknown |

## Behavior Pattern Identifiers

These identifiers are used internally by the scanner to classify findings:

- `base64_decode_exec` — Base64 decoding followed by code execution
- `two_stage_download` — Download a script, then execute it
- `osascript_password_dialog` — macOS dialog box phishing for passwords
- `ssh_key_exfiltration` — Reading and transmitting SSH private keys
- `keychain_access` — macOS Keychain password extraction
- `zip_and_upload` — Archive sensitive files and upload to remote server
- `crontab_persistence` — Installing cron jobs for persistence
- `launchd_persistence` — Creating launchd plist for persistence
- `reverse_shell` — Establishing reverse shell connections
- `env_file_theft` — Stealing .env files with API keys and secrets
- `browser_cookie_theft` — Extracting browser cookies and saved passwords
- `clipboard_monitoring` — Monitoring clipboard for sensitive data

## Updating the IOC Database

The machine-readable IOC database is at `scripts/ioc_database.json`. To add new indicators:

1. Edit the JSON file directly following the existing schema
2. Run `python3 scripts/skill_audit.py --path /path/to/test` to verify the new IOCs work
3. Update this human-readable document to match
