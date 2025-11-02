# Fix GitHub Authentication Error

## Problem
```
remote: Invalid username or token. Password authentication is not supported for Git operations.
fatal: Authentication failed
```

GitHub discontinued password authentication on August 13, 2021. You must use a **Personal Access Token (PAT)** or **SSH key** instead.

## Solution 1: Personal Access Token (PAT) - RECOMMENDED

### Step 1: Create a Personal Access Token

1. Go to GitHub: https://github.com/settings/tokens
2. Click **"Generate new token"** → **"Generate new token (classic)"**
3. Give it a descriptive name: `apk-analyzer-upload`
4. Set expiration: Choose your preference (90 days, 1 year, or no expiration)
5. Select scopes (permissions):
   - ✓ **repo** (Full control of private repositories)
   - This gives you all necessary permissions for pushing code
6. Click **"Generate token"** at the bottom
7. **⚠️ COPY THE TOKEN NOW** - You won't be able to see it again!
   - It looks like: `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

### Step 2: Use Token Instead of Password

When git asks for your password, **paste the token** instead:

```bash
git push -u origin main

Username for 'https://github.com': BinDissector
Password for 'https://BinDissector@github.com': [PASTE YOUR TOKEN HERE]
```

### Step 3: Cache Credentials (Optional)

To avoid entering the token every time:

```bash
# Store credentials (token will be saved in plain text - use with caution)
git config --global credential.helper store

# Then push (you'll need to enter token once, then it's saved)
git push -u origin main
```

**Better option** - Use credential manager:

**For Linux:**
```bash
git config --global credential.helper cache
# Credentials cached for 15 minutes (900 seconds)

# Or cache for longer (1 hour = 3600 seconds)
git config --global credential.helper 'cache --timeout=3600'
```

**For Windows:**
```bash
git config --global credential.helper wincred
```

**For macOS:**
```bash
git config --global credential.helper osxkeychain
```

---

## Solution 2: SSH Keys (More Secure)

### Step 1: Generate SSH Key

```bash
# Generate new SSH key
ssh-keygen -t ed25519 -C "your_email@example.com"

# Press Enter to accept default location
# Enter passphrase (optional but recommended)

# Start ssh-agent
eval "$(ssh-agent -s)"

# Add SSH key to agent
ssh-add ~/.ssh/id_ed25519
```

### Step 2: Add SSH Key to GitHub

```bash
# Copy your public key
cat ~/.ssh/id_ed25519.pub
# Copy the entire output (starts with ssh-ed25519)
```

1. Go to GitHub: https://github.com/settings/keys
2. Click **"New SSH key"**
3. Title: `APK Analyzer Machine`
4. Key: Paste your public key
5. Click **"Add SSH key"**

### Step 3: Test SSH Connection

```bash
ssh -T git@github.com
# Should see: "Hi BinDissector! You've successfully authenticated..."
```

### Step 4: Change Remote URL to SSH

```bash
# Remove HTTPS remote
git remote remove origin

# Add SSH remote
git remote add origin git@github.com:BinDissector/apk-obfuscation-analyzer.git

# Push using SSH
git push -u origin main
```

---

## Quick Command Reference

### Check Current Remote
```bash
git remote -v
```

### Change from HTTPS to SSH
```bash
git remote set-url origin git@github.com:BinDissector/apk-obfuscation-analyzer.git
```

### Change from SSH to HTTPS
```bash
git remote set-url origin https://github.com/BinDissector/apk-obfuscation-analyzer.git
```

### Verify Authentication
```bash
# For HTTPS with token
git ls-remote

# For SSH
ssh -T git@github.com
```

---

## Recommended Approach for You

Since you already tried with HTTPS, here's the fastest solution:

1. **Create Personal Access Token** (see steps above)
2. **Try pushing again** with token as password:
   ```bash
   git push -u origin main
   Username: BinDissector
   Password: [PASTE YOUR TOKEN]
   ```
3. **Cache it** so you don't need to enter again:
   ```bash
   git config --global credential.helper cache
   ```

---

## Troubleshooting

### "Invalid username or token"
- Token might be incorrect - regenerate it
- Username must match exactly: `BinDissector`
- Make sure token has `repo` scope

### "Permission denied"
- Token doesn't have correct permissions
- Regenerate token with `repo` scope checked

### "Repository not found"
- Repository name might be wrong
- Check if repository exists: https://github.com/BinDissector/apk-obfuscation-analyzer
- Verify you have access to the repository

---

## What Worked?

After you get it working, let me know which method you used so I can update the documentation!
