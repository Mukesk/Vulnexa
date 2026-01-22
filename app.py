import re

# -----------------------------
# CONFIGURATION
# -----------------------------
SOURCES = ["req.query", "req.body", "req.params", "input("]
SANITIZERS = ["sanitize", "escape", "encode", "preparedStatement"]

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

# -----------------------------
# SAMPLE CODE TO ANALYZE
# -----------------------------
code = """
let id = req.query.id;
let query = "SELECT * FROM users WHERE id=" + id;
db.query(query);

let name = req.body.name;
document.getElementById("output").innerHTML = name;

os.system(req.body.cmd);

let API_KEY = "sk_test_123456";
"""

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------
tainted_vars = set()
lines = code.split("\n")

def contains_any(line, items):
    return any(item in line for item in items)

def extract_assigned_var(line):
    match = re.match(r"\s*(let|var|const)?\s*(\w+)\s*=", line)
    return match.group(2) if match else None

def extract_vars(line):
    return re.findall(r"\b[a-zA-Z_]\w*\b", line)

# -----------------------------
# ANALYSIS ENGINE
# -----------------------------
print("🔍 Running Multi-Vulnerability Static Analysis\n")

for line_no, line in enumerate(lines, start=1):
    line = line.strip()
    if not line:
        continue

    # 1️⃣ SOURCE DETECTION
    if contains_any(line, SOURCES):
        var = extract_assigned_var(line)
        if var:
            tainted_vars.add(var)
            print(f"[Line {line_no}] SOURCE → '{var}' marked TAINTED")

    # 2️⃣ TAINT PROPAGATION
    if "=" in line:
        lhs = extract_assigned_var(line)
        rhs_vars = extract_vars(line)
        if lhs and any(v in tainted_vars for v in rhs_vars):
            tainted_vars.add(lhs)
            print(f"[Line {line_no}] TAINT propagated → '{lhs}'")

    # 3️⃣ HARD-CODED SECRET DETECTION
    if re.search(r"(API_KEY|SECRET|TOKEN)\s*=\s*['\"]", line):
        print(f"\n🚨 Hardcoded Secret Detected at line {line_no}")
        print(f"   Severity: High")
        print(f"   Line: {line}")

    # 4️⃣ SINK CHECK FOR ALL VULNERABILITIES
    for vuln, info in VULNERABILITIES.items():
        if contains_any(line, info["sinks"]):
            used_vars = extract_vars(line)
            tainted_used = [v for v in used_vars if v in tainted_vars]

            if tainted_used and not contains_any(line, SANITIZERS):
                print(f"\n🚨 {vuln} Detected at line {line_no}")
                print(f"   Severity: {info['severity']}")
                print(f"   Tainted Variables: {tainted_used}")
                print(f"   Code: {line}")

print("\n✅ Analysis Complete")