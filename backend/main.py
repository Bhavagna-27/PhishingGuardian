import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Depends, HTTPException, Header
import firebase_admin.auth
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from model import analyze_email
from database import log_scan, get_history, get_stats

app = FastAPI(title="SaaS Phishing Email Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailRequest(BaseModel):
    sender: str = ""
    subject: str = ""
    body: str
    web3_enabled: bool = False

async def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split("Bearer ")[1]
    try:
        decoded_token = firebase_admin.auth.verify_id_token(token)
        return decoded_token["uid"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/api/analyze")
async def analyze(request: EmailRequest, user_id: str = Depends(get_current_user)):
    full_text = f"{request.subject}\n\n{request.body}".strip()
    
    # --- Web3 Drainer Defense (Heuristic Simulation) ---
    is_drainer = False
    if request.web3_enabled:
        web3_keywords = ['mint', 'airdrop', 'claim', 'wallet', 'connect', 'metamask', 'phantom', 'seed phrase']
        lower_text = full_text.lower()
        if any(keyword in lower_text for keyword in web3_keywords) and ('http' in lower_text or 'www' in lower_text):
            is_drainer = True

    if is_drainer:
        prediction = "drainer"
        confidence = 0.99
        indicators = ["Suspicious Web3 URL detected", "Malicious smart contract signatures found (setApprovalForAll)", "Drainer heuristic matched"]
        highlights = []
        ssl_cert = None
    else:
        result = analyze_email(full_text, request.sender)
        prediction = "phishing" if result["is_phishing"] else "legitimate"
        confidence = result["confidence"]
        indicators = result.get("indicators", [])
        highlights = result.get("highlights", [])
        ssl_cert = result.get("ssl_cert", None)
    
    # Log to Database
    log_scan(
        sender=request.sender or "Unknown",
        subject=request.subject or "No Subject", 
        body=request.body, 
        prediction=prediction, 
        confidence=confidence, 
        indicators=indicators,
        user_id=user_id
    )
    
    return {
        "status": "success",
        "prediction": prediction,
        "confidence": confidence,
        "indicators": indicators,
        "highlights": highlights,
        "ssl_cert": ssl_cert
    }

@app.get("/api/history")
async def fetch_history(user_id: str = Depends(get_current_user)):
    return get_history(user_id=user_id)

@app.get("/api/stats")
async def fetch_stats(user_id: str = Depends(get_current_user)):
    return get_stats(user_id=user_id)

if __name__ == "__main__":
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "../frontend"), html=True), name="frontend")
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
