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

IGNORED_DIRECTORIES = {
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "env",
    ".git"
}

IGNORED_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "setup.py",
    "pyproject.toml",
    ".env",
    ".env.example"
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
    skipped_files = []
    js_count = 0
    py_count = 0

    for root, dirs, files in os.walk(CLONE_DIR):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]

        for file in files:
            if file in IGNORED_FILES:
                skipped_files.append(os.path.join(root, file))
                continue

            ext = os.path.splitext(file)[1]
            file_path = os.path.join(root, file)

            if ext in SUPPORTED_LANGUAGES:
                detected_files.append({
                    "file": file_path,
                    "language": SUPPORTED_LANGUAGES[ext]
                })

                if ext == ".js":
                    js_count += 1
                elif ext == ".py":
                    py_count += 1
            else:
                if any(ignored in file_path for ignored in IGNORED_DIRECTORIES):
                    skipped_files.append(file_path)

    return detected_files, js_count, py_count, skipped_files

# -----------------------------
# MAIN FUNCTION
# -----------------------------
def main():
    repo_url = input("🔗 Enter GitHub Repository URL: ").strip()

    clone_repo(repo_url)

    files, js_count, py_count, skipped_files = scan_files()

    print("🔍 Detected Source Files:\n")
    for f in files:
        print(f"📄 {f['file']}  →  {f['language']}")

    print("\n📊 Language-wise File Count:")
    print(f"🟨 JavaScript Files: {js_count}")
    print(f"🟦 Python Files: {py_count}")

    if skipped_files:
        print("\n⚠️ Ignored dependency & config files detected")
        print("These files/folders were skipped to avoid false positives and noise:")
        for sf in skipped_files[:5]:
            print(f"🚫 {sf}")

        if len(skipped_files) > 5:
            print(f"... and {len(skipped_files) - 5} more skipped files")

    print(f"\n✅ Total valid source files analyzed: {len(files)}")

if __name__ == "__main__":
    main()