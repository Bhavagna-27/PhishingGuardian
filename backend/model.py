import re
import requests
import socket
import ssl
from urllib.parse import urlparse
import google.generativeai as genai
import json

# Initialize Gemini with the user's API Key
genai.configure(api_key="YOUR_GEMINI_API_KEY")

# We use gemini-2.5-flash for speed in the scanner, but it's highly capable.
try:
    llm_model = genai.GenerativeModel('gemini-2.5-flash')
except Exception as e:
    print(f"Error initializing Gemini: {e}")
    llm_model = None

def active_domain_scan(url):
    threats = []
    ssl_data = None
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, timeout=3, allow_redirects=True, headers=headers)
        if len(response.history) > 0:
            final_url = response.url
            orig_domain = urlparse(url).netloc.replace('www.', '')
            final_domain = urlparse(final_url).netloc.replace('www.', '')
            if orig_domain != final_domain:
                threats.append(f"Active Forensics: URL aggressively redirects to hidden destination -> {final_url}")
            
        if response.status_code >= 400:
            threats.append(f"Active Forensics: Live Domain returned HTTP error {response.status_code}")
    except requests.exceptions.Timeout:
        threats.append(f"Active Forensics: Live Domain is unreachable (Timeout)")
    except requests.exceptions.RequestException:
        threats.append(f"Active Forensics: Live Domain connection failed (Likely taken offline or blocked)")
        
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0]
        if not domain:
            domain = url.split('://')[-1].split('/')[0]
            
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                der_cert = ssock.getpeercert(binary_form=True)
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                
                def get_field(cert_dict, field_name):
                    for x in cert_dict:
                        if x[0][0] == field_name:
                            return x[0][1]
                    return "Unknown"
                
                ssl_data = {
                    "issuer": get_field(cert.get('issuer', []), 'organizationName'),
                    "subject": get_field(cert.get('subject', []), 'commonName'),
                    "expires": cert.get('notAfter', 'Unknown'),
                    "pem": pem_cert
                }
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
        threats.append(f"Active Forensics: CRITICAL - Invalid or self-signed SSL Certificate!")
    except Exception as e:
        print(f"General SSL parsing error: {e}")
        
    return threats, ssl_data

def analyze_urls(text):
    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
    url_threats = []
    highlight_urls = []
    ssl_cert_data = None
    
    for url in urls:
        highlight_urls.append(url)
        # ACTIVE DOMAIN FORENSICS
        active_threats, ssl_data = active_domain_scan(url)
        url_threats.extend(active_threats)
        if ssl_data and not ssl_cert_data:
            ssl_cert_data = ssl_data # Grab the first valid one
            
    return url_threats, highlight_urls, ssl_cert_data

def extract_json_from_llm(response_text):
    try:
        # Sometimes the LLM wraps JSON in markdown blocks
        if "```json" in response_text:
            json_str = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            json_str = response_text.split("```")[1].split("```")[0].strip()
        else:
            json_str = response_text.strip()
        return json.loads(json_str)
    except Exception as e:
        print(f"Failed to parse LLM JSON: {e}")
        return None

class PhishingDetector:
    def __init__(self):
        pass

    def predict(self, text: str, sender: str = ""):
        if not text.strip():
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "indicators": ["Empty email content"],
                "highlights": []
            }

        url_threats, url_highlights, ssl_cert_data = analyze_urls(text)
        
        if not llm_model:
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "indicators": ["System Error: LLM Initialization Failed."],
                "highlights": [],
                "ssl_cert": ssl_cert_data
            }

        prompt = f"""
You are an elite Senior Cybersecurity Forensic Analyst. 
Analyze the following email/message payload for phishing, social engineering, or Web3 drainer attempts.

Payload Context:
Sender Address (if provided): {sender}
Message Body:
\"\"\"
{text}
\"\"\"

Your task is to determine the probability that this is a malicious attack.
Return your analysis strictly in valid JSON format matching this exact schema:
{{
  "is_phishing": true or false,
  "confidence": a float between 0.0 and 1.0 representing threat probability,
  "indicators": ["list", "of", "strings", "explaining", "the", "psychological", "manipulation", "or", "threat", "vectors"],
  "highlights": ["list", "of", "exact", "words", "or", "short", "phrases", "from", "the", "text", "that", "are", "suspicious"]
}}

Rules:
- Be highly accurate. Do not flag generic marketing newsletters or legitimate meeting invites.
- DO flag urgency, forced action, suspicious login requests, crypto airdrops, and credential harvesting.
- The 'highlights' must exactly match text found in the payload so they can be highlighted on the frontend.
- Do NOT output any markdown around the JSON, just output the raw JSON object.
"""

        try:
            response = llm_model.generate_content(prompt)
            result = extract_json_from_llm(response.text)
            
            if not result:
                raise ValueError("Could not parse LLM JSON")
                
            phishing_prob = result.get('confidence', 0.0)
            indicators = result.get('indicators', [])
            highlights = result.get('highlights', [])
            
        except Exception as e:
            print(f"LLM Error: {e}")
            phishing_prob = 0.5
            indicators = ["Error: Could not reach Neural Network. Falling back to default."]
            highlights = []

        # Combine LLM intelligence with Active Domain Forensics
        all_indicators = indicators + url_threats
        all_highlights = highlights + url_highlights

        # If Active Forensics found a CRITICAL SSL issue or aggressive redirect, massively boost the threat score
        if len(url_threats) > 0:
            phishing_prob = min(0.99, phishing_prob + 0.40)
            
        is_phishing = phishing_prob > 0.50
        
        # Deduplicate highlights
        all_highlights = list(set(all_highlights))

        return {
            "is_phishing": is_phishing,
            "confidence": round(phishing_prob, 4),
            "indicators": all_indicators if all_indicators else ["Clean: No explicit threat vectors identified by LLM."],
            "highlights": all_highlights,
            "ssl_cert": ssl_cert_data
        }

detector = PhishingDetector()

def analyze_email(text: str, sender: str = ""):
    return detector.predict(text, sender)
