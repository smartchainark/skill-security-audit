# Remediation Guide — Incident Response for Malicious Skills

## Immediate Actions (within 30 minutes)

### 1. Isolate the Malicious Skill

```bash
# DO NOT delete yet — preserve evidence
# Move the skill to a quarantine directory
mkdir -p ~/quarantine/skills
mv ~/.claude/skills/<malicious-skill> ~/quarantine/skills/

# If using OpenClaw, also remove from config
# Edit ~/.openclaw/openclaw.json and remove the skill reference
```

### 2. Kill Active Processes

Check for any processes spawned by the malicious skill:

```bash
# Check for suspicious processes
ps aux | grep -i '<skill-name>'

# Check for unexpected network connections
lsof -i -nP | grep ESTABLISHED

# Check for unexpected cron jobs
crontab -l

# Check for LaunchAgents (macOS)
ls -la ~/Library/LaunchAgents/
```

### 3. Revoke Exposed Credentials

If the scanner found credential theft indicators, immediately rotate these:

**Priority 1 — Rotate immediately:**
- [ ] SSH keys (`~/.ssh/id_*`) — Generate new keys, update authorized_keys on all servers
- [ ] API keys in `.env` files — Rotate on all services (AWS, Stripe, OpenAI, etc.)
- [ ] AWS credentials (`~/.aws/credentials`) — Rotate in AWS IAM console
- [ ] npm/PyPI tokens (`~/.npmrc`, `~/.pypirc`) — Regenerate tokens

**Priority 2 — Rotate within 24 hours:**
- [ ] GitHub/GitLab personal access tokens
- [ ] Database passwords
- [ ] Cloud provider service account keys
- [ ] Docker Hub credentials
- [ ] Any password entered in a suspicious dialog box

**Priority 3 — Change when possible:**
- [ ] macOS Keychain passwords (if keychain access was detected)
- [ ] Browser saved passwords (if cookie/credential theft was detected)
- [ ] Wi-Fi passwords stored on the system

### 4. Check for Persistence

```bash
# macOS LaunchAgents
ls -la ~/Library/LaunchAgents/ | grep -v com.apple
ls -la /Library/LaunchAgents/ | grep -v com.apple

# crontab
crontab -l

# Shell profiles — check for unexpected additions
tail -20 ~/.bashrc ~/.zshrc ~/.bash_profile ~/.profile 2>/dev/null

# Login items (macOS)
osascript -e 'tell application "System Events" to get the name of every login item'
```

Remove any entries you don't recognize. If in doubt, compare timestamps with the skill's installation date.

## System Integrity Check

### File System

```bash
# Check recently modified files in home directory
find ~ -type f -mtime -7 -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -50

# Check for unexpected hidden files
find ~ -maxdepth 2 -name '.*' -type f -newer ~/.claude/skills/<suspicious-skill> 2>/dev/null
```

### Network

```bash
# Current connections
netstat -an | grep ESTABLISHED

# DNS cache (macOS)
sudo dscacheutil -flushcache

# Check /etc/hosts for modifications
cat /etc/hosts
```

### Browser

If browser cookie/credential theft was detected:
1. Log out of all sessions on sensitive services
2. Enable 2FA on all accounts that support it
3. Clear browser cookies and saved passwords
4. Check for unauthorized OAuth app authorizations on GitHub, Google, etc.

## Evidence Preservation

Before cleanup, preserve evidence for reporting:

```bash
# Create evidence archive
EVIDENCE_DIR=~/quarantine/evidence-$(date +%Y%m%d)
mkdir -p "$EVIDENCE_DIR"

# Copy the malicious skill
cp -r ~/quarantine/skills/<malicious-skill> "$EVIDENCE_DIR/"

# Save scan results
python3 ~/.claude/skills/skill-security-audit/scripts/skill_audit.py \
  --path ~/quarantine/skills/<malicious-skill> \
  --json > "$EVIDENCE_DIR/scan-results.json"

# Save system state
ps aux > "$EVIDENCE_DIR/processes.txt"
crontab -l > "$EVIDENCE_DIR/crontab.txt" 2>&1
ls -la ~/Library/LaunchAgents/ > "$EVIDENCE_DIR/launch-agents.txt" 2>&1
```

## Reporting Channels

### ClawHub Platform
- Report the malicious skill on ClawHub with evidence
- Include the scan results JSON and a description of the malicious behavior

### SlowMist
- Report to SlowMist for threat intelligence updates
- Include IOCs (IPs, domains, file hashes) found by the scanner

### GitHub
- If the skill was hosted on GitHub, report the repository
- Use GitHub's "Report abuse" feature with evidence

### Platform-Specific
- **npm:** `npm audit` and report to npm security team
- **PyPI:** Report via PyPI's malware reporting form

## Post-Incident Hardening

1. **Enable 2FA** on all development-related accounts
2. **Review installed skills** regularly with the security audit scanner
3. **Only install skills** from trusted, verified sources
4. **Pin skill versions** to avoid automatic updates that could introduce malicious code
5. **Use separate SSH keys** for different services
6. **Avoid storing secrets** in `.env` files — use a secret manager
7. **Set up file integrity monitoring** for critical directories

## Prevention Checklist

Before installing any new skill:

- [ ] Check the author's reputation and account age
- [ ] Read through all script files (especially `.sh`, `.py`, `.js`)
- [ ] Look for `postinstall` hooks in `package.json`
- [ ] Search for Base64 strings, `eval()`, `exec()`, `curl | bash`
- [ ] Verify the skill doesn't access `~/.ssh`, `~/.aws`, or other sensitive directories
- [ ] Run the security audit scanner against the skill before installing
- [ ] Check if the skill has been reported by other users
