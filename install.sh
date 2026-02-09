#!/usr/bin/env bash
# One-line installer for Skill Security Audit
# Usage: curl -fsSL https://raw.githubusercontent.com/smartchainark/skill-security-audit/main/install.sh | bash
set -euo pipefail

REPO="https://github.com/smartchainark/skill-security-audit.git"
TARGET="$HOME/.claude/skills/skill-security-audit"

if [ -d "$TARGET" ]; then
    echo "[*] Updating existing installation..."
    cd "$TARGET" && git pull --ff-only
else
    echo "[*] Installing skill-security-audit to $TARGET ..."
    git clone "$REPO" "$TARGET"
fi

echo "[*] Verifying installation..."
python3 "$TARGET/scripts/skill_audit.py" --path "$TARGET" --severity critical --no-color 2>/dev/null

echo ""
echo "Done! Skill installed at: $TARGET"
echo ""
echo "Usage:"
echo "  python3 $TARGET/scripts/skill_audit.py              # Scan all skills"
echo "  python3 $TARGET/scripts/skill_audit.py --severity high  # High+ only"
echo "  python3 $TARGET/scripts/skill_audit.py --json           # JSON output"
echo ""
echo "Or in Claude Code, just say: \"安全审计\" or \"security audit\""
