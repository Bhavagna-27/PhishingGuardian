import os
import sys
import json
from datetime import datetime

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

# Global variables for db
db = None

KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firebase-key.json")

def init_db():
    global db
    if not os.path.exists(KEY_PATH):
        print("\n" + "="*60)
        print("FIREBASE SETUP REQUIRED")
        print(f"Missing Service Account Key: {KEY_PATH}")
        print("Please place your 'firebase-key.json' in the backend folder and restart the server.")
        print("="*60 + "\n")
        sys.exit(1)
        
    try:
        if not firebase_admin._apps:
            cred = credentials.Certificate(KEY_PATH)
            firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("[SUCCESS] Successfully connected to Firebase Firestore!")
    except Exception as e:
        print(f"[ERROR] Failed to initialize Firebase: {e}")
        sys.exit(1)

def log_scan(sender, subject, body, prediction, confidence, indicators, user_id):
    if db is None: return
    preview = body[:100] + "..." if len(body) > 100 else body
    
    # Store scans in a subcollection under the specific user's document
    doc_ref = db.collection('users').document(user_id).collection('scans').document()
    doc_ref.set({
        'timestamp': datetime.now().isoformat(),
        'sender': sender,
        'subject': subject,
        'preview': preview,
        'prediction': prediction,
        'confidence': confidence,
        'indicators': indicators 
    })

def get_history(user_id, limit=50):
    if db is None: return []
    # Retrieve scans only from this user's subcollection
    docs = db.collection('users').document(user_id).collection('scans').stream()
    
    result = []
    for doc in docs:
        d = doc.to_dict()
        d['id'] = doc.id
        result.append(d)
    
    result.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return result[:limit]

def get_stats(user_id):
    if db is None: 
        return {"total_scans": 0, "threats_blocked": 0, "safe_emails": 0}
        
    try:
        scans_ref = db.collection('users').document(user_id).collection('scans')
        total = sum(1 for _ in scans_ref.stream())
        threats = sum(1 for _ in scans_ref.where('prediction', '==', 'phishing').stream())
        
        return {
            "total_scans": total,
            "threats_blocked": threats,
            "safe_emails": total - threats
        }
    except Exception as e:
        print("Stats error:", e)
        return {"total_scans": 0, "threats_blocked": 0, "safe_emails": 0}

init_db()
