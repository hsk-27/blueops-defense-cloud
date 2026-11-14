# BlueOps Defense Cloud™ — GitHub Deployment & Publishing Runbook

This runbook guides you step-by-step through publishing **BlueOps Defense Cloud™** to GitHub. Whether you prefer using a **web browser** or a **standard terminal command**, follow the instructions below.

---

## Pre-Flight Status Check

Your repository is already pre-configured for GitHub:
- **Clean Commit History:** 100% committed with semantic commit messages.
- **Strict `.gitignore`:** Excludes `node_modules/`, `target/`, `dist/`, `.env`, and IDE artifacts.
- **Pre-Configured GitHub Workflows:** Continuous Integration (`ci.yml`), CodeQL security scanning (`codeql.yml`), and Docker builds (`docker-build.yml`).
- **Standard Governance:** `LICENSE` (Apache 2.0), `SECURITY.md`, `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md`.

---

## Method 1: The 3-Command Terminal Git Push (Recommended & Fastest)

This method takes under **30 seconds** and authenticates directly through your web browser without entering personal access tokens.

### Step 1: Create an Empty Repository on GitHub
1. Open your web browser and go to [https://github.com/new](https://github.com/new).
2. Set **Repository name** to:
   ```text
   blueops-defense-cloud
   ```
3. *(Optional)* Add Description:
   ```text
   Enterprise Threat Detection & Automated Incident Response Platform (Spring Boot 3, React 18, Sigma Rules, MITRE ATT&CK, NIST SP 800-61r2)
   ```
4. Choose **Public** (or **Private**).
5. **CRITICAL:** Under "Initialize this repository with:", **leave all checkboxes UNCHECKED**:
   - [ ] Add a README file
   - [ ] Add .gitignore
   - [ ] Choose a license  
   *(Your project already contains production-ready versions of all three).*
6. Click the green **"Create repository"** button.

---

### Step 2: Push to GitHub from PowerShell
Open PowerShell on your laptop, navigate to the project directory, and paste these 3 commands:

```powershell
# 1. Navigate to the project directory
Set-Location C:\Users\Dell\.gemini\antigravity\scratch\blueops-defense-cloud

# 2. Link your new GitHub repository (replace YOUR-USERNAME with your actual GitHub username)
git remote add origin https://github.com/YOUR-USERNAME/blueops-defense-cloud.git

# 3. Rename branch to main and push
git branch -M main
git push -u origin main
```

> **Note on Browser Authentication:**  
> When you run `git push`, Windows Git Credential Manager will open a browser tab asking you to **"Sign in with your browser"**. Simply click **"Authorize git-ecosystem"**. The push will complete automatically.

---

## Method 2: Web Browser Upload via GitHub Web UI

If you want to upload the files directly through your web browser without using Git commands:

### Understanding GitHub Web Upload Limits:
GitHub's web upload UI (`github.com/<user>/<repo>/upload`) has a hard limit of **100 files per drag-and-drop batch** and does not support empty directories.

To upload via browser cleanly:

### Step 1: Create a Clean Source Archive (Zip)
We have prepared a PowerShell one-liner that bundles all project source files, detection rules, docs, and configurations while strictly omitting `node_modules` and compiled `target` classes:

```powershell
Set-Location C:\Users\Dell\.gemini\antigravity\scratch
Compress-Archive -Path "blueops-defense-cloud\*" -DestinationPath "$HOME\Desktop\blueops-defense-cloud-source.zip" -CompressionLevel Optimal
```
*This creates a compact, lightweight `.zip` on your Desktop ready for distribution, submission, or backup.*

### Step 2: Upload Files via Browser
1. In your new GitHub repository, click the link: **"uploading an existing file"** (or click **Add file** $\to$ **Upload files**).
2. Drag and drop your project files (e.g. `README.md`, `pom.xml`, `package.json`, `docs/`, `backend/`, `frontend/`).
3. Under **Commit changes**, type:
   ```text
   Initial release: BlueOps Defense Cloud v1.3.2
   ```
4. Click **Commit changes**.

---

## Post-Upload GitHub Repository Polish

Once uploaded, take 2 minutes to configure these repository settings to maximize the presentation quality of your project:

### 1. Add Repository Topics / Tags
On the main repository page on GitHub, click the gear icon next to **"About"** (top right) and add these tags:
- `cybersecurity`
- `siem`
- `soar`
- `threat-detection`
- `mitre-attack`
- `sigma-rules`
- `incident-response`
- `nist-800-61`
- `spring-boot`
- `react`
- `opensearch`

### 2. Verify CI Pipeline Status
1. Click the **Actions** tab on your repository.
2. Verify that the continuous integration workflows (`CI Pipeline`, `CodeQL Security Analysis`) trigger and pass automatically.

### 3. Verify README Display
Scroll down the main repository page to verify that:
- All status badges render cleanly.
- The Mermaid architecture flowchart renders interactively.
- The detection rule table and benchmark metrics display in clean tabular format.

---

## Need Help?
- Refer to [`docs/MANUAL_TESTING_GUIDE.md`](docs/MANUAL_TESTING_GUIDE.md) to test features locally.
- Refer to [`docs/audit/FINAL_ACCEPTANCE_REPORT.md`](docs/audit/FINAL_ACCEPTANCE_REPORT.md) for full engineering verification data.
