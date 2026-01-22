from collections import defaultdict
import json
from datetime import datetime
import os

INPUT_FILE = "vulnexa_report.json"
OUTPUT_FILE = "ai_prompts.json"

def generate_master_prompt(grouped_findings):
    prompt = """
You are a Principal Cybersecurity Engineer and Secure Software Architect.

You are given a JSON security report generated from static and taint analysis
of a JavaScript / Python (MEAN / Next.js) application.

━━━━━━━━━━━━━━━━━━━━━━
📄 SECURITY REPORT (GROUPED BY CATEGORY)
━━━━━━━━━━━━━━━━━━━━━━
"""

    for item in grouped_findings:
        category = item.get("category")
        occurrences = item.get("occurrences", [])

        prompt += f"\n=== CATEGORY: {category} ===\n"
        for occ in occurrences:
            prompt += (
                f"- File: {occ.get('filename')} | "
                f"Line: {occ.get('line')} | "
                f"Severity: {occ.get('severity')}\n"
            )

    prompt += """
━━━━━━━━━━━━━━━━━━━━━━
🎯 OBJECTIVE
━━━━━━━━━━━━━━━━━━━━━━
Remediate ALL vulnerabilities above using ONE reusable fix strategy per category.

━━━━━━━━━━━━━━━━━━━━━━
🛠️ REQUIRED OUTPUT (FOR EACH CATEGORY)
━━━━━━━━━━━━━━━━━━━━━━
1️⃣ Vulnerability Overview  
2️⃣ Real-World Exploit Scenario  
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
