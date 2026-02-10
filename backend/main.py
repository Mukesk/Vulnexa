from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
import os
import shutil
from datetime import datetime

from backend.services.cloner import ClonerService
from backend.services.scanner import ScannerService
from backend.services.ai_agent import AIAgentService

app = FastAPI(title="Vulnexa API", description="Backend for Vulnexa Security Scanner")

# CORS Middleware
origins = [
    "http://localhost:5173",  # Vite dev server
    "http://127.0.0.1:5173",
    "http://localhost:4173",  # Vite preview
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ScanRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = None

class Occurrence(BaseModel):
    filename: str
    line: Optional[int]
    severity: str

class VulnerabilityCategory(BaseModel):
    category: str
    count: int
    occurrences: List[Occurrence]

class ScanResponse(BaseModel):
    repository: str
    scanTime: str
    vulnerabilities: List[VulnerabilityCategory]
    summary: dict
    ai_prompt: Optional[str] = None

# Helpers
def cleanup():
    import tempfile
    clone_dir = os.path.join(tempfile.gettempdir(), "vulnexa_cloned_repo")
    if os.path.exists(clone_dir):
        try:
            shutil.rmtree(clone_dir)
        except Exception:
            pass

def parse_github_url(url: str):
    """
    Parses a GitHub URL to extract the base repository URL and the branch name if present.
    Example: https://github.com/user/repo/tree/branch -> (https://github.com/user/repo, branch)
    """
    if "/tree/" in url:
        parts = url.split("/tree/")
        base_url = parts[0]
        branch_name = parts[1].split("/")[0]  # Take only the first part after tree/ as branch for now, or the whole rest?
        # A branch can contain slashes, but usually 'tree' is followed by the branch name.
        # If the URL is .../tree/feature/branch-name, parts[1] is feature/branch-name.
        # So we should take the rest.
        branch_name = parts[1]
        
        # Remove trailing slash if present
        if branch_name.endswith("/"):
            branch_name = branch_name[:-1]
            
        return base_url, branch_name
    return url, None

@app.get("/")
def read_root():
    return {"status": "Vulnexa API is running"}

@app.post("/api/scan", response_model=ScanResponse)
def scan_repository(request: ScanRequest):
    repo_url = request.repo_url.strip()
    branch = request.branch

    # Fix common URL typos
    if repo_url.startswith("ttps://"):
        repo_url = "https://" + repo_url[7:]
    elif repo_url.startswith("http://"):
        repo_url = "https://" + repo_url[7:]

    # Try to parse branch from URL if not provided
    if not branch:
        repo_url, extracted_branch = parse_github_url(repo_url)
        if extracted_branch:
            branch = extracted_branch
            
    print(f"🚀 Received scan request for: {repo_url} (Branch: {branch})")
    
    try:
        # 1. Clone
        ClonerService.clone_repo(repo_url, branch)
        
        # 2. Scan
        findings = ScannerService.scan_codebase()
        
        # 3. Generate AI Prompts (Optional but useful)
        ai_data = AIAgentService.generate_prompts(findings)
        master_prompt = ai_data.get("master_prompt") if ai_data else None
        
        # 4. Calculate Summary Stats
        total_vulns = sum(cat['count'] for cat in findings)
        
        # Simple risk score calculation (matching frontend logic roughly)
        severity_weights = {"Critical": 5, "High": 3, "Medium": 2, "Low": 1}
        weighted_sum = 0
        total_items = 0
        
        for cat in findings:
            for occ in cat['occurrences']:
                weighted_sum += severity_weights.get(occ['severity'], 1)
                total_items += 1
                
        risk_score = 0
        if total_items > 0:
            # Normalized to 0-100
             risk_score = min(100, round((weighted_sum / (total_items * 5)) * 100))
        
        risk_label = "Low Risk"
        if risk_score >= 75: risk_label = "Critical Risk"
        elif risk_score >= 50: risk_label = "High Risk"
        elif risk_score >= 25: risk_label = "Moderate Risk"

        highest_risk_area = "None"
        if findings:
            # Find category with highest weighted score
            best_cat = None
            max_cat_score = -1
            for cat in findings:
                cat_score = sum(severity_weights.get(o['severity'], 1) for o in cat['occurrences'])
                if cat_score > max_cat_score:
                    max_cat_score = cat_score
                    best_cat = cat['category']
            highest_risk_area = best_cat

        response = {
            "repository": request.repo_url,
            "scanTime": datetime.utcnow().isoformat(),
            "vulnerabilities": findings,
            "summary": {
                "totalVulns": total_vulns,
                "riskScore": risk_score,
                "riskLevel": risk_label,
                "highestRiskArea": highest_risk_area
            },
            "ai_prompt": master_prompt
        }
        
        return response

    except Exception as e:
        error_msg = str(e).lower()
        print(f"❌ Error during scan: {error_msg}")
        
        status_code = 500
        detail = "Internal Server Error"

        if "repository not found" in error_msg:
            status_code = 404
            detail = "Repository not found. Please check the URL."
        elif "private repository" in error_msg or "authentication failed" in error_msg:
            status_code = 403
            detail = "Repository is private or requires authentication."
        elif "failed to clone" in error_msg:
             status_code = 400
             detail = f"Failed to clone repository: {str(e)}"
        else:
             detail = str(e)

        raise HTTPException(status_code=status_code, detail=detail)
    
    # We don't auto-cleanup here to allow debugging, potentially invoke cleanup via background task if needed
    # cleanup() 

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
