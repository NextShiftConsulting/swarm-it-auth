#!/bin/bash
#
# Install git hooks for swarm-it-auth
#
# Usage: ./hooks/install.sh
#

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "Installing git hooks for swarm-it-auth..."

# Install pre-commit hook
if [ -f "$HOOKS_DIR/pre-commit" ]; then
    echo "Warning: pre-commit hook already exists"
    read -p "Overwrite? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Skipping pre-commit hook"
        exit 0
    fi
fi

cp "$SCRIPT_DIR/pre-commit" "$HOOKS_DIR/pre-commit"
chmod +x "$HOOKS_DIR/pre-commit"

echo "✓ Installed pre-commit hook (credential safety check)"
echo ""
echo "The hook will:"
echo "  - Detect API keys, tokens, passwords in files"
echo "  - Block commits containing AWS keys, GitHub tokens, OpenAI keys"
echo "  - Prevent committing .pem, .key, credentials.json files"
echo "  - Warn about high-entropy strings that might be secrets"
echo ""
echo "To bypass (not recommended): git commit --no-verify"
echo ""
