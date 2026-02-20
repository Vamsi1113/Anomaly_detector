# Git Setup and Push Guide

## Step-by-Step Instructions to Push Your Code to GitHub

### Prerequisites
- Git installed on your system
- GitHub account created
- Repository created at: https://github.com/Vamsi1113/Anomaly_detector.git

---

## Step 1: Verify Git Initialization

You've already run `git init`. Let's verify:

```bash
git status
```

You should see a list of untracked files.

---

## Step 2: Configure Git (First Time Only)

Set your Git username and email:

```bash
git config --global user.name "Vamsi"
git config --global user.email "your-email@example.com"
```

Verify configuration:

```bash
git config --list
```

---

## Step 3: Review .gitignore

The `.gitignore` file has been created to exclude:
- Python cache files (`__pycache__/`, `*.pyc`)
- Virtual environments (`venv/`, `env/`)
- IDE files (`.vscode/`, `.idea/`)
- Session data (`sessions/`, `uploads/`)
- Log files (`*.log`)
- Environment files (`.env`)

**Important**: Large files like `orglog1.csv` and `orglog2.csv` are currently tracked. If you want to exclude them, uncomment these lines in `.gitignore`:

```bash
# Uncomment these lines in .gitignore if you don't want to track large log files:
# orglog1.csv
# orglog2.csv
# advanced_synthetic_logs.log
```

---

## Step 4: Add Files to Staging

Add all files (respecting .gitignore):

```bash
git add .
```

Check what will be committed:

```bash
git status
```

You should see files in green (staged for commit).

---

## Step 5: Create Your First Commit

```bash
git commit -m "Initial commit: Enterprise Log Anomaly Detection System

- Multi-layer threat detection (4 layers)
- 14+ threat types with confidence scoring
- Universal log parser supporting 7+ formats
- ML models: Isolation Forest & Autoencoder
- Web dashboard with real-time visualization
- Session management and file upload handling
- Comprehensive documentation"
```

---

## Step 6: Connect to GitHub Repository

Add the remote repository:

```bash
git remote add origin https://github.com/Vamsi1113/Anomaly_detector.git
```

Verify the remote:

```bash
git remote -v
```

You should see:
```
origin  https://github.com/Vamsi1113/Anomaly_detector.git (fetch)
origin  https://github.com/Vamsi1113/Anomaly_detector.git (push)
```

---

## Step 7: Push to GitHub

### Option A: Push to main branch (recommended)

```bash
git branch -M main
git push -u origin main
```

### Option B: Push to master branch

```bash
git push -u origin master
```

**Note**: GitHub now uses `main` as the default branch name.

---

## Step 8: Verify on GitHub

1. Go to https://github.com/Vamsi1113/Anomaly_detector
2. Refresh the page
3. You should see all your files and the README

---

## Common Issues and Solutions

### Issue 1: Authentication Required

If prompted for username/password:

**Solution 1: Use Personal Access Token (Recommended)**
1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Generate new token (classic)
3. Select scopes: `repo` (full control)
4. Copy the token
5. Use token as password when prompted

**Solution 2: Use SSH**
```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "your-email@example.com"

# Add to SSH agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Copy public key
cat ~/.ssh/id_ed25519.pub

# Add to GitHub: Settings → SSH and GPG keys → New SSH key

# Change remote to SSH
git remote set-url origin git@github.com:Vamsi1113/Anomaly_detector.git
```

### Issue 2: Repository Not Empty

If GitHub says repository is not empty:

```bash
# Pull first, then push
git pull origin main --allow-unrelated-histories
git push -u origin main
```

### Issue 3: Large Files Warning

If you get warnings about large files:

```bash
# Remove large files from tracking
git rm --cached orglog1.csv orglog2.csv advanced_synthetic_logs.log

# Add to .gitignore
echo "orglog1.csv" >> .gitignore
echo "orglog2.csv" >> .gitignore
echo "advanced_synthetic_logs.log" >> .gitignore

# Commit the changes
git add .gitignore
git commit -m "Remove large log files from tracking"
git push
```

### Issue 4: Permission Denied

```bash
# Check remote URL
git remote -v

# If using HTTPS, ensure you have correct credentials
# If using SSH, ensure SSH key is added to GitHub
```

---

## Future Git Workflow

### Making Changes

```bash
# 1. Check current status
git status

# 2. Add changed files
git add <filename>
# or add all changes
git add .

# 3. Commit with descriptive message
git commit -m "Description of changes"

# 4. Push to GitHub
git push
```

### Creating Branches

```bash
# Create and switch to new branch
git checkout -b feature/new-feature

# Make changes, commit
git add .
git commit -m "Add new feature"

# Push branch to GitHub
git push -u origin feature/new-feature

# Switch back to main
git checkout main

# Merge feature branch
git merge feature/new-feature
```

### Pulling Latest Changes

```bash
# Pull latest changes from GitHub
git pull origin main
```

---

## Recommended Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**
```bash
git commit -m "feat: Add XSS detection pattern"
git commit -m "fix: Parser now handles comma-separated IPs"
git commit -m "docs: Update README with installation steps"
git commit -m "refactor: Improve threat classification logic"
```

---

## Files to Review Before Pushing

✅ **Include:**
- Source code (`.py` files)
- Configuration files
- Documentation (`.md` files)
- Requirements (`requirements.txt`)
- Sample files (small ones)
- Trained models (if < 100MB)

❌ **Exclude (via .gitignore):**
- `__pycache__/` directories
- `.pyc` files
- `venv/` or `env/` directories
- `.vscode/` or `.idea/` directories
- `sessions/` directory (runtime data)
- `uploads/` directory (user uploads)
- `.env` files (secrets)
- Large log files (> 10MB)

---

## Quick Reference Commands

```bash
# Check status
git status

# Add files
git add .

# Commit
git commit -m "message"

# Push
git push

# Pull
git pull

# View commit history
git log --oneline

# View remote
git remote -v

# Create branch
git checkout -b branch-name

# Switch branch
git checkout branch-name

# Delete branch
git branch -d branch-name
```

---

## Final Checklist

Before pushing:

- [ ] `.gitignore` file created
- [ ] Sensitive data removed (API keys, passwords)
- [ ] Large files excluded or removed
- [ ] README.md is up to date
- [ ] Code is tested and working
- [ ] Commit message is descriptive
- [ ] Remote repository URL is correct

---

## Need Help?

If you encounter issues:

1. Check Git status: `git status`
2. Check remote: `git remote -v`
3. Check logs: `git log`
4. Google the error message
5. Check GitHub documentation: https://docs.github.com

---

**Good luck with your first push! 🚀**
