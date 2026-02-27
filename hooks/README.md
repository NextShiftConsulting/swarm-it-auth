# Git Hooks

Git hooks for swarm-it-auth to prevent credential leaks.

## Installation

```bash
./hooks/install.sh
```

## Hooks

### pre-commit

**Purpose**: Prevent committing credentials and secrets.

**What it checks:**

1. **Credential Patterns** - Detects common patterns:
   - API keys (`api_key`, `apiKey`)
   - Secret keys (`secret_key`, `secretKey`)
   - Passwords (`password`)
   - Bearer tokens
   - SSH private keys
   - AWS access keys (AKIA...)
   - GitHub tokens (github_pat_..., ghp_...)
   - OpenAI keys (sk-...)
   - Hugging Face tokens (hf_...)
   - Slack tokens (xoxb-...)

2. **Forbidden File Names**:
   - `*.pem`, `*.key`
   - `credentials*.json`, `secrets*.json`
   - `*token*.txt`
   - `.env`, `.env.local`
   - SSH key files (`id_rsa`, etc.)

3. **Forbidden Directories**:
   - `keys/`, `secrets/`, `vault/`, `certs/`

4. **High Entropy Strings**:
   - Base64-like strings >40 characters (warning only)

**Bypass** (not recommended):
```bash
git commit --no-verify
```

## Why These Hooks?

Authentication libraries handle sensitive data. These hooks provide defense-in-depth:

- **Layer 1**: `.gitignore` - Prevents accidental `git add`
- **Layer 2**: Pre-commit hook - Catches credentials before commit
- **Layer 3**: GitHub secret scanning - Post-commit detection

Even though this is an open-source library without actual credentials, these hooks protect developers from accidentally committing test credentials or personal tokens.

## Testing

Test the hook works:

```bash
# This should be blocked
echo 'api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456"' > test_cred.py
git add test_cred.py
git commit -m "test"
# Should fail with credential detected

# Clean up
rm test_cred.py
```

## Customization

Edit `hooks/pre-commit` to add custom patterns or adjust sensitivity.

After editing, reinstall:
```bash
./hooks/install.sh
```
