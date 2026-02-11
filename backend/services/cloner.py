import os
import shutil
import requests
import zipfile
import io
import tempfile

# -----------------------------
# CONFIG
# -----------------------------
# Use designated temp directory for serverless compatibility (Vercel allows write only in /tmp)
CLONE_DIR = os.path.join(tempfile.gettempdir(), "vulnexa_cloned_repo")

class ClonerService:
    @staticmethod
    def clone_repo(repo_url: str, branch: str = None) -> bool:
        # Clean up previous clone
        if os.path.exists(CLONE_DIR):
            try:
                def on_rm_error(func, path, exc_info):
                    os.chmod(path, 0o777)
                    func(path)
                shutil.rmtree(CLONE_DIR, onerror=on_rm_error)
            except Exception as e:
                print(f"⚠️ Warning: Could not fully clean up {CLONE_DIR}: {e}")

        print(f"📥 Downloading repository: {repo_url} (Branch: {branch or 'Default'})")

        # Construct ZIP URL
        # Normal: https://github.com/user/repo
        # Zip: https://github.com/user/repo/archive/refs/heads/branch.zip
        # Default: https://github.com/user/repo/archive/HEAD.zip
        
        repo_url = repo_url.rstrip("/")
        if branch:
            zip_url = f"{repo_url}/archive/refs/heads/{branch}.zip"
        else:
            zip_url = f"{repo_url}/archive/HEAD.zip"

        try:
            print(f"⬇️ Fetching ZIP from: {zip_url}")
            response = requests.get(zip_url, stream=True)
            
            if response.status_code == 404:
                # Try master/main if default HEAD failed (unlikely for github)
                 raise Exception("Branch or repository not found (404).")
            elif response.status_code != 200:
                raise Exception(f"Failed to download repository. Status: {response.status_code}")

            # Extract ZIP
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                # Extract to a temp dir first because GitHub zips have a top-level folder
                with tempfile.TemporaryDirectory() as temp_extract_dir:
                    z.extractall(temp_extract_dir)
                    
                    # Find the top-level directory (e.g. repo-main)
                    extracted_folders = os.listdir(temp_extract_dir)
                    if not extracted_folders:
                         raise Exception("Downloaded ZIP archive is empty.")
                    
                    source_dir = os.path.join(temp_extract_dir, extracted_folders[0])
                    
                    # Move to CLONE_DIR
                    shutil.copytree(source_dir, CLONE_DIR)

            print("✅ Repository downloaded & extracted successfully")
            return True

        except Exception as e:
            print(f"❌ ERROR: Download failed: {e}")
            raise Exception(f"Failed to download repository: {str(e)}")
