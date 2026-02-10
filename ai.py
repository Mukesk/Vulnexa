from collections import defaultdict
import json
from datetime import datetime
import os

INPUT_FILE = "vulnexa_report.json"
OUTPUT_FILE = "ai_prompts.json"

SEVERITY_ORDER = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4
}

def generate_master_prompt(grouped_findings):
    prompt = """
You are a Principal Cybersecurity Engineer and Secure Software Architect.

You are given a JSON security report generated from static and taint analysis
of a JavaScript / Python (MEAN / Next.js) application.

━━━━━━━━━━━━━━━━━━━━━━
📄 SECURITY REPORT (GROUPED BY CATEGORY)
━━━━━━━━━━━━━━━━━━━━━━
"""

    # Sort categories by highest severity found in each category
    def category_severity(item):
        severities = [occ.get("severity", "Low") for occ in item.get("occurrences", [])]
        return min(SEVERITY_ORDER.get(s, 4) for s in severities)

    grouped_findings = sorted(grouped_findings, key=category_severity)

    for item in grouped_findings:
        category = item.get("category")
        occurrences = item.get("occurrences", [])

        # Deduplicate occurrences
        unique = {}
        for occ in occurrences:
            line = occ.get("line")
            if line is None:
                line = "File-Level"

            key = (occ.get("filename"), line, occ.get("severity"))
            unique[key] = {
                "filename": occ.get("filename"),
                "line": line,
                "severity": occ.get("severity"),
                "exploit_path": occ.get("exploit_path")
            }

        prompt += f"\n=== CATEGORY: {category} ({len(unique)} occurrences) ===\n"

        # Sort occurrences by severity
        sorted_occurrences = sorted(
            unique.values(),
            key=lambda x: SEVERITY_ORDER.get(x["severity"], 4)
        )

        for occ in sorted_occurrences:
            prompt += (
                f"- File: {occ['filename']} | "
                f"Line: {occ['line']} | "
                f"Severity: {occ['severity']}\n"
            )
            
            if occ.get("exploit_path"):
                ep = occ["exploit_path"]
                prompt += (
                    f"  🧨 EXPLOIT PATH:\n"
                    f"     • Source: {ep.get('source', 'Unknown')}\n"
                    f"     • Sink: {ep.get('sink', 'Unknown')}\n"
                    f"     • Flow:\n"
                )
                for step in ep.get("flow", []):
                    prompt += f"       ↓ {step}\n"
                prompt += "\n"

    prompt += """
━━━━━━━━━━━━━━━━━━━━━━
🎯 OBJECTIVE
━━━━━━━━━━━━━━━━━━━━━━
Remediate ALL vulnerabilities above.
For every vulnerability with an "EXPLOIT PATH", you MUST provide a "Human-Readable Exploit Narrative".
Explain it like you are describing a heist: "The attacker inputs X, it travels through Y, and executes Z."

━━━━━━━━━━━━━━━━━━━━━━
🛠️ REQUIRED OUTPUT (FOR EACH CATEGORY)
━━━━━━━━━━━━━━━━━━━━━━
1️⃣ Vulnerability Overview
2️⃣ Human-Readable Exploit Narrative (Based on provided Exploit Path)
3️⃣ Common Root Cause Across Files
4️⃣ Secure Design Principle Applied
5️⃣ Global Fix Strategy (Reusable)
6️⃣ BEFORE Code Pattern (Generic)
7️⃣ AFTER Code Pattern (Secure & Reusable)
8️⃣ Where to Apply This Fix (Controllers, Routes, UI, Config, etc.)
9️⃣ Common Developer Mistakes
🔟 Verification Checklist

━━━━━━━━━━━━━━━━━━━━━━
🔐 FIXING RULES
━━━━━━━━━━━━━━━━━━━━━━
• Do NOT break functionality
• Prefer centralized fixes
• Follow OWASP best practices
• Avoid per-line hacks
• Apply defense-in-depth

Respond as if this will be used to refactor a production system.
"""
    return prompt

def generate_ai_prompts():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ ERROR: Input report '{INPUT_FILE}' not found.")
        print("👉 Run app.py first to generate the vulnerability report.")
        return

    with open(INPUT_FILE, "r") as f:
        findings = json.load(f)

    master_prompt = generate_master_prompt(findings)

    output = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_categories": len(findings),
        "total_occurrences": sum(len(i.get("occurrences", [])) for i in findings),
        "master_prompt": master_prompt
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=4)

    print(f"🤖 Master AI remediation prompt generated → {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_ai_prompts()
