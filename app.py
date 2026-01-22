import re
import os

# -----------------------------
# CONFIGURATION
# -----------------------------
SOURCES = ["req.query", "req.body", "req.params", "input("]
SANITIZERS = ["sanitize", "escape", "encode", "preparedStatement"]
TRUSTED_SANITIZERS = ["sanitize", "escape", "encode", "preparedStatement", "htmlspecialchars"]

VULNERABILITIES = {
    "SQL Injection": {
        "sinks": ["db.query", "execute(", "cursor.execute"],
        "severity": "Critical"
    },
    "XSS": {
        "sinks": ["innerHTML", "document.write"],
        "severity": "High"
    },
    "Command Injection": {
        "sinks": ["os.system", "exec(", "subprocess.call"],
        "severity": "Critical"
    },
    "Code Injection": {
        "sinks": ["eval("],
        "severity": "High"
    }
}

JS_STATIC_ISSUES = {
    "Insecure Eval Usage": {
        "patterns": ["eval("],
        "severity": "High",
        "message": "Use of eval() can lead to code injection vulnerabilities."
    },
    "Unsafe setTimeout / setInterval": {
        "patterns": ["setTimeout(", "setInterval("],
        "severity": "Medium",
        "message": "Passing user-controlled input to timers can lead to code execution."
    },
    "Prototype Pollution Risk": {
        "patterns": ["__proto__", "constructor.prototype"],
        "severity": "High",
        "message": "Prototype pollution vulnerability detected."
    },
    "Insecure Randomness": {
        "patterns": ["Math.random()"],
        "severity": "Medium",
        "message": "Math.random() is not cryptographically secure."
    },
    "Missing Strict Mode": {
        "patterns": [],
        "severity": "Low",
        "message": "JavaScript file does not enforce 'use strict'."
    }
}

OWASP_TOP10_CHECKS = {
    "Injection": {
        "patterns": ["eval(", "exec(", "os.system", "subprocess.call", "db.query", "cursor.execute"],
        "severity": "Critical",
        "message": "User-controlled input may be executed or injected into commands or queries."
    },
    "Broken Access Control": {
        "patterns": ["isAdmin", "role == 'admin'", "if user.role", "checkAdmin("],
        "severity": "High",
        "message": "Authorization decisions appear to rely on insecure or hardcoded logic."
    },
    "Security Misconfiguration": {
        "patterns": ["debug=True", "DEBUG = True", "app.run(debug", "allowAllOrigins"],
        "severity": "Medium",
        "message": "Application may be running with insecure or default configurations."
    },
    "Insecure Design": {
        "patterns": ["TODO security", "FIXME security", "bypassAuth", "disableAuth"],
        "severity": "Medium",
        "message": "Security controls appear to be missing or intentionally bypassed."
    },
    "Authentication Failures": {
        "patterns": ["password ==", "plain_password", "login without token", "noAuth"],
        "severity": "High",
        "message": "Authentication logic appears weak or insecure."
    },
    "Cryptographic Failures": {
        "patterns": ["md5(", "sha1(", "Math.random", "random.random"],
        "severity": "High",
        "message": "Weak or insecure cryptographic functions detected."
    },
    "Vulnerable / Outdated Components": {
        "patterns": ["package.json", "requirements.txt", "pip install"],
        "severity": "Medium",
        "message": "Dependencies should be checked for known vulnerabilities."
    },
    "Software / Data Integrity Failures": {
        "patterns": ["pickle.loads", "yaml.load(", "eval("],
        "severity": "Critical",
        "message": "Unsafe deserialization or integrity validation detected."
    },
    "Logging Failures": {
        "patterns": ["except:", "pass  # ignore", "console.log(error)"],
        "severity": "Low",
        "message": "Errors may not be logged or monitored properly."
    },
    "Server-Side Request Forgery (SSRF)": {
        "patterns": ["requests.get(", "requests.post(", "fetch(", "axios.get("],
        "severity": "Critical",
        "message": "Server makes outbound requests using potentially user-controlled URLs."
    }
}

# -----------------------------
# REPOSITORY CONFIG
# -----------------------------
CLONE_DIR = "cloned_repo"
SUPPORTED_EXTENSIONS = (".js", ".py")

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------
def contains_any(line, items):
    return any(item in line for item in items)

def extract_assigned_var(line):
    match = re.match(r"\s*(let|var|const)?\s*(\w+)\s*=", line)
    return match.group(2) if match else None

def extract_vars(line):
    return re.findall(r"\b[a-zA-Z_]\w*\b", line)

def load_source_files():
    files_data = []
    for root, dirs, files in os.walk(CLONE_DIR):
        dirs[:] = [d for d in dirs if d not in {"node_modules", "venv", ".venv", "__pycache__", ".git"}]
        for file in files:
            if file.endswith(SUPPORTED_EXTENSIONS):
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        files_data.append((path, f.read()))
                except Exception:
                    pass
    return files_data

# -----------------------------
# ANALYSIS ENGINE
# -----------------------------
print("🔍 Running Multi-Vulnerability Static Analysis\n")

files = load_source_files()

for file_path, code in files:
    print(f"\n📂 Scanning File: {file_path}")
    is_js_file = file_path.endswith(".js")
    strict_mode_found = False
    tainted_vars = set()
    lines = code.split("\n")

    for line_no, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue

        if is_js_file and "'use strict'" in line or '"use strict"' in line:
            strict_mode_found = True

        # 1️⃣ SOURCE DETECTION
        if contains_any(line, SOURCES):
            var = extract_assigned_var(line)
            if var:
                tainted_vars.add(var)
                print(f"[Line {line_no}] SOURCE → '{var}' marked TAINTED")

        # 2️⃣ DEEP TAINT PROPAGATION
        if "=" in line:
            lhs = extract_assigned_var(line)
            rhs_vars = extract_vars(line)

            # If RHS uses tainted data and no sanitizer is applied
            if lhs and any(v in tainted_vars for v in rhs_vars):
                if not contains_any(line, TRUSTED_SANITIZERS):
                    tainted_vars.add(lhs)
                    print(f"[Line {line_no}] TAINT propagated → '{lhs}'")

        # 2️⃣b FUNCTION ARGUMENT TAINT TRACKING
        for var in list(tainted_vars):
            if f"({var})" in line or f", {var}" in line:
                tainted_vars.add(var)

        # 3️⃣ HARD-CODED SECRET DETECTION
        if re.search(r"(API_KEY|SECRET|TOKEN|PASSWORD|AUTH_KEY)\s*=\s*['\"][^'\"]+['\"]", line):
            print(f"\n🚨 Hardcoded Secret Detected at line {line_no}")
            print(f"   Severity: High")
            print(f"   Vulnerability Type: Hardcoded Secret")
            print(f"   Line: {line}")

        # 4️⃣ SINK CHECK FOR ALL VULNERABILITIES
        for vuln, info in VULNERABILITIES.items():
            if contains_any(line, info["sinks"]):
                used_vars = extract_vars(line)
                tainted_used = [v for v in used_vars if v in tainted_vars]

                if tainted_used and not contains_any(line, SANITIZERS):
                    print(f"\n🚨 {vuln} Detected at line {line_no}")
                    print(f"   Severity: {info['severity']}")
                    print(f"   Vulnerability Type: {vuln}")
                    print(f"   Tainted Variables: {tainted_used}")
                    print(f"   Code: {line}")

        # 5️⃣ OWASP TOP 10 STATIC CHECKS
        for category, info in OWASP_TOP10_CHECKS.items():
            for pattern in info["patterns"]:
                if pattern in line:
                    print(f"\n🚨 OWASP Issue Detected: {category}")
                    print(f"   Severity: {info['severity']}")
                    print(f"   Description: {info['message']}")
                    print(f"   File: {file_path}")
                    print(f"   Line: {line_no}")
                    print(f"   Code: {line}")

    if is_js_file:
        for issue, info in JS_STATIC_ISSUES.items():
            if issue == "Missing Strict Mode" and not strict_mode_found:
                print(f"\n⚠️ JavaScript Static Issue Detected")
                print(f"   Issue: {issue}")
                print(f"   Severity: {info['severity']}")
                print(f"   Reason: {info['message']}")

        for line_no, line in enumerate(lines, start=1):
            for issue, info in JS_STATIC_ISSUES.items():
                if info["patterns"]:
                    if any(p in line for p in info["patterns"]):
                        print(f"\n⚠️ JavaScript Static Issue Detected at line {line_no}")
                        print(f"   Issue: {issue}")
                        print(f"   Severity: {info['severity']}")
                        print(f"   Reason: {info['message']}")
                        print(f"   Code: {line}")

print("\n✅ Analysis Complete")