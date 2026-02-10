import os
import shutil
from git import Repo

# -----------------------------
# CONFIG
# -----------------------------
# -----------------------------
# CONFIG
# -----------------------------
import tempfile
# Use designated temp directory for serverless compatibility (Vercel allows write only in /tmp)
CLONE_DIR = os.path.join(tempfile.gettempdir(), "vulnexa_cloned_repo")

class ClonerService:
    @staticmethod
    def clone_repo(repo_url: str, branch: str = None) -> bool:
        if os.path.exists(CLONE_DIR):
            try:
                # Handle permission errors by changing file modes before deletion
                # This is common on Windows but good practice generally
                def on_rm_error(func, path, exc_info):
                    os.chmod(path, 0o777)
                    func(path)
                
                shutil.rmtree(CLONE_DIR, onerror=on_rm_error)
            except Exception as e:
                print(f"⚠️ Warning: Could not fully clean up {CLONE_DIR}: {e}")

        print(f"📥 Cloning repository: {repo_url} (Branch: {branch or 'Default'})")

        max_retries = 3
        for attempt in range(max_retries):
            try:
                if branch:
                    Repo.clone_from(repo_url, CLONE_DIR, branch=branch)
                else:
                    Repo.clone_from(repo_url, CLONE_DIR)
                print("✅ Repository cloned successfully")
                return True
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"⚠️ Attempt {attempt + 1} failed: {e}. Retrying in 2s...")
                    import time
                    time.sleep(2)
                else:
                   # Attempted all retries, raising only the specific useful error messages or the last one
                    error_msg = str(e).lower()
                    if "authentication failed" in error_msg or "permission denied" in error_msg:
                        print("🔒 ERROR: This repository appears to be PRIVATE.")
                        raise Exception("Private repository access denied. Please check URL or credentials.")
                    elif "not found" in error_msg:
                        print("❌ ERROR: Repository not found.")
                        raise Exception("Repository not found.")
                    else:
                         print(f"❌ ERROR: Unable to clone repository after {max_retries} attempts: {e}")
                         raise Exception(f"Failed to clone repository: {str(e)}")
