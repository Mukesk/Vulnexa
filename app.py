import re
import os
import json
from collections import defaultdict

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
    "NoSQL Injection": {
        "sinks": ["findOne(", "find(", "update(", "deleteOne("],
        "severity": "Critical"
    },
    "SSRF": {
        "sinks": ["axios.get(", "fetch(", "requests.get("],
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

OWASP_TOP50_MEAN_NEXT = {
    # ---------- BACKEND (Node / Express / MongoDB) ----------
    "NoSQL Injection (MongoDB)": {
        "patterns": ["$where", "$ne", "$gt", "$regex", "find({", "findOne({"],
        "severity": "Critical",
        "message": "Possible NoSQL Injection via untrusted MongoDB query operators."
    },
    "Missing Input Validation (Express)": {
        "patterns": ["req.body", "req.query", "req.params"],
        "severity": "High",
        "message": "User input is consumed without validation or schema enforcement."
    },
    "Insecure JWT Handling": {
        "patterns": ["jwt.verify(", "jwt.decode("],
        "severity": "High",
        "message": "JWT verification may be missing algorithm or expiration checks."
    },
    "Hardcoded JWT Secret": {
        "patterns": ["jwt.sign(", "secret =", "JWT_SECRET"],
        "severity": "Critical",
        "message": "Hardcoded JWT secret detected."
    },
    "Mass Assignment": {
        "patterns": ["Object.assign(req.body", "new Model(req.body"],
        "severity": "High",
        "message": "Mass assignment vulnerability allowing unauthorized field updates."
    },
    "Insecure CORS Configuration": {
        "patterns": ["cors()", "origin: '*'", "Access-Control-Allow-Origin"],
        "severity": "Medium",
        "message": "CORS configuration allows unrestricted cross-origin access."
    },
    "Unrestricted File Upload": {
        "patterns": ["multer(", "upload.single", "upload.array"],
        "severity": "High",
        "message": "File upload detected without validation of type or size."
    },

    # ---------- FRONTEND (Angular / Next.js / React) ----------
    "DOM-based XSS (Frontend)": {
        "patterns": ["dangerouslySetInnerHTML", "innerHTML"],
        "severity": "High",
        "message": "Direct DOM manipulation may lead to DOM-based XSS."
    },
    "Client-Side Authentication Bypass": {
        "patterns": ["if(isLoggedIn)", "localStorage.getItem('token')"],
        "severity": "High",
        "message": "Authentication enforced only on client-side logic."
    },
    "Insecure Storage of Sensitive Data": {
        "patterns": ["localStorage.setItem", "sessionStorage.setItem"],
        "severity": "Medium",
        "message": "Sensitive data stored insecurely in browser storage."
    },
    "Open Redirect (Next.js)": {
        "patterns": ["router.push(", "res.redirect(", "redirect("],
        "severity": "Medium",
        "message": "User-controlled redirects may enable phishing attacks."
    },
    "Missing CSRF Protection": {
        "patterns": ["fetch(", "axios.post(", "axios.put("],
        "severity": "High",
        "message": "State-changing requests without CSRF protection detected."
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
findings = []

print("🔍 Running Multi-Vulnerability Static Analysis\n")

files = load_source_files()

for file_path, code in files:
    print(f"\n📂 Scanning File: {file_path}")
    is_js_file = file_path.endswith(".js")
    strict_mode_found = False
    tainted_vars = {}
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
                source_type = next((s for s in SOURCES if s in line), "Unknown Source")
                tainted_vars[var] = {
                    "source": source_type,
                    "line": line_no,
                    "history": [f"Line {line_no}: Source identified via '{source_type}' assigned to '{var}'"]
                }
                print(f"[Line {line_no}] SOURCE → '{var}' marked TAINTED ({source_type})")

        # 2️⃣ DEEP TAINT PROPAGATION
        if "=" in line:
            lhs = extract_assigned_var(line)
            rhs_vars = extract_vars(line)

            # If RHS uses tainted data and no sanitizer is applied
            # Find the first tainted variable in RHS to trace back
            tainted_source_var = next((v for v in rhs_vars if v in tainted_vars), None)

            if lhs and tainted_source_var:
                if not contains_any(line, TRUSTED_SANITIZERS):
                    # Propagate taint info
                    original_taint = tainted_vars[tainted_source_var]
                    new_history = original_taint["history"].copy()
                    new_history.append(f"Line {line_no}: Value propagated to '{lhs}'")
                    
                    tainted_vars[lhs] = {
                        "source": original_taint["source"],
                        "line": line_no,
                        "history": new_history
                    }
                    print(f"[Line {line_no}] TAINT propagated → '{lhs}' (from '{tainted_source_var}')")

        # 2️⃣b FUNCTION ARGUMENT TAINT TRACKING
        # If a tainted variable is passed to a function, we don't necessarily taint the function name, 
        # but if we were tracking function calls more deeply we would. 
        # For now, we keep the existing simple logic but treating tainted_vars as dict keys works same as set.
        # However, the previous logic was:
        # for var in list(tainted_vars):
        #     if f"({var})" in line or f", {var}" in line:
        #         tainted_vars.add(var) 
        # The previous logic seemed to re-add 'var' to tainted_vars if it was used in a function call?
        # That doesn't make much sense for propagation unless it was 'func(var)' potentially modifying var? 
        # Python sets check existence, so 'add' is idempotent.
        # We will skip this specific block as it seems redundant or purely for side-effect printing which wasn't there.
        # Actually, simpler: if a tainted var is used in a function arg, we might want to flag the function result as tainted?
        # The original code was:
        # for var in list(tainted_vars):
        #    if f"({var})" in line or f", {var}" in line:
        #        tainted_vars.add(var)
        # This literally did nothing if var was already in the set.
        # We will omitting it or implementing better logic?
        # Let's stick to the propagation logic above (lhs = ... rhs...) which covers function returns if assigned.
        
        # 3️⃣ HARD-CODED SECRET DETECTION
        if re.search(r"(API_KEY|SECRET|TOKEN|PASSWORD|AUTH_KEY)\s*=\s*['\"][^'\"]+['\"]", line):
            print(f"\n🚨 Hardcoded Secret Detected at line {line_no}")
            print(f"   Severity: High")
            print(f"   Vulnerability Type: Hardcoded Secret")
            print(f"   Line: {line}")
            findings.append({
                "name": "Hardcoded Secret",
                "line": line_no,
                "severity": "High",
                "filename": file_path
            })

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
                    
                    # Generate Exploit Path for the first tainted variable found
                    taint_info = tainted_vars[tainted_used[0]]
                    sink_name = next((s for s in info["sinks"] if s in line), "Unknown Sink")
                    
                    exploit_path = {
                        "source": taint_info["source"],
                        "sink": sink_name,
                        "flow": taint_info["history"] + [f"Line {line_no}: Reached Sink '{sink_name}'"]
                    }

                    findings.append({
                        "name": vuln,
                        "line": line_no,
                        "severity": info["severity"],
                        "filename": file_path,
                        "exploit_path": exploit_path
                    })

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
                    findings.append({
                        "name": category,
                        "line": line_no,
                        "severity": info["severity"],
                        "filename": file_path
                    })

        # 6️⃣ OWASP TOP 50 (MEAN / NEXT.JS) CHECKS
        for category, info in OWASP_TOP50_MEAN_NEXT.items():
            for pattern in info["patterns"]:
                if pattern in line:
                    print(f"\n🚨 OWASP Top-50 Issue Detected: {category}")
                    print(f"   Severity: {info['severity']}")
                    print(f"   Description: {info['message']}")
                    print(f"   File: {file_path}")
                    print(f"   Line: {line_no}")
                    print(f"   Code: {line}")
                    findings.append({
                        "name": category,
                        "line": line_no,
                        "severity": info["severity"],
                        "filename": file_path
                    })

    if is_js_file:
        for issue, info in JS_STATIC_ISSUES.items():
            if issue == "Missing Strict Mode" and not strict_mode_found:
                print(f"\n⚠️ JavaScript Static Issue Detected")
                print(f"   Issue: {issue}")
                print(f"   Severity: {info['severity']}")
                print(f"   Reason: {info['message']}")
                findings.append({
                    "name": issue,
                    "line": None,
                    "severity": info["severity"],
                    "filename": file_path
                })

        for line_no, line in enumerate(lines, start=1):
            for issue, info in JS_STATIC_ISSUES.items():
                if info["patterns"]:
                    if any(p in line for p in info["patterns"]):
                        print(f"\n⚠️ JavaScript Static Issue Detected at line {line_no}")
                        print(f"   Issue: {issue}")
                        print(f"   Severity: {info['severity']}")
                        print(f"   Reason: {info['message']}")
                        print(f"   Code: {line}")
                        findings.append({
                            "name": issue,
                            "line": line_no,
                            "severity": info["severity"],
                            "filename": file_path
                        })

grouped_report = defaultdict(list)

for item in findings:
    entry = {
        "filename": item["filename"],
        "line": item["line"],
        "severity": item["severity"]
    }
    if "exploit_path" in item:
        entry["exploit_path"] = item["exploit_path"]
        
    grouped_report[item["name"]].append(entry)

final_report = []
for category, occurrences in grouped_report.items():
    final_report.append({
        "category": category,
        "count": len(occurrences),
        "occurrences": occurrences
    })

with open("vulnexa_report.json", "w") as f:
    json.dump(final_report, f, indent=4)

print(f"\n📄 Structured & grouped JSON report generated: vulnexa_report.json")

print("\n✅ Analysis Complete")