PhishingGuardian
PhishingGuardian is an enterprise-grade Cybersecurity Threat Intelligence Dashboard designed to detect, analyze, and neutralize advanced phishing attacks, Zero-Day threats, and Web3 crypto drainers.

Unlike standard static keyword scanners, PhishingGuardian is powered by a live neural network and active domain forensics to hunt down threats in real-time.

Live Demo
Try it here: https://vikas-97a5f.web.app/

Core Technologies & Features
Google Gemini 1.5 Pro Neural Network: The core engine relies on an LLM to perform deep semantic analysis of the payload. It understands context, urgency, and manipulation tactics rather than just looking at hardcoded keywords.
Active Domain Forensics: The backend physically reaches out to suspicious URLs, follows hidden redirects, and analyzes server headers to identify masked malicious domains.
Cryptographic SSL Extraction: Automatically intercepts the physical SSL connection to extract the cryptographic certificate (Subject, Issuer, Expiry), allowing users to download the raw .pem file to verify domain authenticity.
Web3 Drainer Defense: Includes an experimental heuristic engine that flags malicious smart contract signatures (like setApprovalForAll) commonly used in wallet draining scams.
Zero-Dependency Vanilla Frontend: Built with pure HTML5, CSS3, and ES6 JavaScript to maximize loading speed and minimize external package vulnerabilities. Hosted instantly on Firebase.
How to run locally (For Judges)
If you want to run the python backend API on your local machine:

Clone the repository.
Place your firebase-key.json and a Gemini API key inside the backend folder.
Install dependencies: pip install -r requirements.txt
Run the engine: python backend/main.py
