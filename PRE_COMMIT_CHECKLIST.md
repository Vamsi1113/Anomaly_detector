# ✅ Pre-Commit Checklist - Prevent Secret Exposure

## Before Every Git Commit

Run this checklist to ensure no secrets are exposed:

### 1. Check for Hardcoded API Keys

```bash
# Search for Azure API keys (long alphanumeric strings)
git grep -E "[A-Za-z0-9]{60,}"

# Search for OpenAI keys
git grep "sk-proj-"
git grep "sk-"

# Search for "api_key =" assignments
git grep "api_key = "
```

### 2. Verify .gitignore

Ensure these files are in `.gitignore`:
- ✅ `.env`
- ✅ `.env.local`
- ✅ `llmtest.py`
- ✅ `test_env_key.py`
- ✅ `test_azure_openai.py`

### 3. Check Staged Files

```bash
# See what will be committed
git status

# Review changes
git diff --cached
```

### 4. Files That Should NEVER Be Committed

- ❌ `.env` - Contains API keys
- ❌ `llmtest.py` - Test file (may contain secrets)
- ❌ `test_env_key.py` - Test file
- ❌ Any file with hardcoded API keys

### 5. Files That Are SAFE to Commit

- ✅ `.env.example` - Template without real keys
- ✅ `.gitignore` - Excludes secret files
- ✅ All Python code files (if they load from .env)
- ✅ Documentation files
- ✅ Configuration files (without secrets)

## Quick Scan Command

Run this before committing:

```bash
# Check for potential secrets in staged files
git diff --cached | grep -E "(api_key|API_KEY|secret|password|token)" -i
```

If this shows any actual keys, DO NOT COMMIT!

## Safe Commit Process

```bash
# 1. Check what's staged
git status

# 2. Review changes
git diff --cached

# 3. Scan for secrets
git diff --cached | grep -i "api_key"

# 4. If clean, commit
git commit -m "Your commit message"

# 5. Push
git push origin main
```

## If You Accidentally Commit a Secret

1. **DO NOT PUSH** if you haven't already
2. **Undo the commit**: `git reset HEAD~1`
3. **Remove the secret** from the file
4. **Commit again** without the secret

## If You Already Pushed a Secret

1. **Rotate the key immediately** (Azure Portal → Regenerate)
2. **Rewrite Git history** (see FIX_GIT_SECRET.md)
3. **Force push** to overwrite history
4. **Update .env** with new key

## Current Status

✅ `.env` is in `.gitignore`
✅ `llmtest.py` is in `.gitignore`
✅ `llmtest.py` now loads from `.env` (no hardcoded key)
✅ All test files are in `.gitignore`

## Ready to Commit

Your code is now safe to commit! All secrets are:
- Stored in `.env` (excluded from Git)
- Loaded via environment variables
- Never hardcoded in committed files
