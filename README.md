# 🛡️ Vulnexa

**Vulnexa** is an advanced Security Intelligence System designed to statically analyze codebases, detect vulnerabilities, trace exploit paths, and provide human-readable remediation advice powered by AI.

It goes beyond simple pattern matching by implementing **Taint Analysis** (Source → Flow → Sink) to understand how untrusted data propagates through your application.

## ✨ Key Features

- **🔍 Advanced Static Analysis**: scans JavaScript, TypeScript, Python, and more for common vulnerabilities (OWASP Top 10).
- **🛤️ Exploit Path Tracing**: Detects not just *where* a vulnerability is, but *how* it happens. It traces data flow from entry points (Sources) to dangerous functions (Sinks).
- **🌿 Branch Scanning**: Support for scanning specific Git branches (e.g., `feature/login`, `dev`).
- **🤖 AI-Powered Remediation**: Generates human-readable "Exploit Narratives" and fix suggestions using AI, explaining vulnerabilities like a story.
- **📊 Comprehensive Dashboard**: A React-based dashboard to visualize risks, severity levels, and remediation steps.

## 🏗️ Architecture

- **Backend**: Python (FastAPI)
    - `ClonerService`: Handles Git operations and branch management.
    - `ScannerService`: Core static analysis and taint tracking engine.
    - `AIAgentService`: Generates prompts for LLMs to explain findings.
- **Frontend**: React (Vite) + Tailwind CSS
- **Database**: None (Stateless analysis usually, though results can be persisted).

## 🚀 Installation

### Prerequisites
- Python 3.8+
- Node.js 16+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/Start-In-Tech/Vulnexa.git
cd Vulnexa
```

### 2. Backend Setup
```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Run the backend
./run_backend.sh
# OR manually:
python3 -m backend.main
```
The backend will start at `http://localhost:8000`.

### 3. Frontend Setup
```bash
cd vulnexa-dashboard
npm install
npm run dev
```
The frontend will start at `http://localhost:5173`.

## 📖 Usage

### via Dashboard
1. Open the dashboard in your browser.
2. Enter the **Repository URL** (e.g., `https://github.com/user/repo`).
3. (Optional) Append the branch name if needed, or use the URL format `.../tree/branch-name`.
4. Click **Scan**.
5. View the detailed report, including risk scores and exploit paths.

### via API
**Scan a Repository:**
```http
POST /api/scan
Content-Type: application/json

{
  "repo_url": "https://github.com/user/repo",
  "branch": "main" 
}
```
*Note: `branch` is optional. You can also provide a URL like `https://github.com/user/repo/tree/dev` and Vulnexa will automatically parse the branch.*

## 🧩 Supported Vulnerabilities

- **Injection**: SQLi, NoSQLi, Command Injection
- **SSRF**: Server-Side Request Forgery
- **XSS**: Cross-Site Scripting (DOM-based)
- **Broken Access Control**
- **Cryptographic Failures**: Hardcoded secrets, weak algorithms
- **Insecure Deserialization**
- ...and more OWASP Top 10 categories.
