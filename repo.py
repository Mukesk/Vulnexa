import os
import shutil
from git import Repo

# -----------------------------
# CONFIG
# -----------------------------
SUPPORTED_LANGUAGES = {
    ".js": "JavaScript",
    ".py": "Python"
}

CLONE_DIR = "cloned_repo"

# -----------------------------
# CLONE GITHUB REPO
# -----------------------------
def clone_repo(repo_url):
    if os.path.exists(CLONE_DIR):
        shutil.rmtree(CLONE_DIR)

    print("📥 Cloning repository...")
    Repo.clone_from(repo_url, CLONE_DIR)
    print("✅ Repository cloned successfully\n")

# -----------------------------
# SCAN FILES & DETECT LANGUAGES
# -----------------------------
def scan_files():
    detected_files = []

    for root, dirs, files in os.walk(CLONE_DIR):
        for file in files:
            ext = os.path.splitext(file)[1]
            if ext in SUPPORTED_LANGUAGES:
                file_path = os.path.join(root, file)
                detected_files.append({
                    "file": file_path,
                    "language": SUPPORTED_LANGUAGES[ext]
                })

    return detected_files

# -----------------------------
# MAIN FUNCTION
# -----------------------------
def main():
    repo_url = input("🔗 Enter GitHub Repository URL: ").strip()

    clone_repo(repo_url)

    files = scan_files()

    print("🔍 Detected Source Files:\n")
    for f in files:
        print(f"📄 {f['file']}  →  {f['language']}")

    print(f"\n✅ Total JS & Python files found: {len(files)}")

if __name__ == "__main__":
    main()