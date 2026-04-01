"""
Backend API untuk Browser Extension & Desktop App
Standalone Flask server untuk deteksi URL phishing otomatis
"""

import os
import sys
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PHISING_DIR = os.path.normpath(os.path.join(BASE_DIR, '..', '..', 'Phising'))
print("-" * 50)
print("🔍 CEK INTEGRASI FILE:")
print(f"📁 Folder Phising: {'✅ Ditemukan' if os.path.exists(PHISING_DIR) else '❌ TIDAK DITEMUKAN'}")

files = ["model_v2.pkl", "feature_cols_v2.pkl", "threshold_v2.pkl", "feature_extractor.py"]
for f in files:
    exists = os.path.exists(os.path.join(PHISING_DIR, f))
    print(f"📄 File {f}: {'✅ Ada' if exists else '❌ Hilang'}")
print("-" * 50)
# -------------------------------------
sys.path.insert(0, PHISING_DIR)

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from feature_extractor import extract_features, get_url_risk_factors, get_url_safe_reasons
import urllib.parse

app = Flask(__name__)
# CORS(app)  # Enable cross-origin requests untuk browser extension
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Load model V3 dengan smart whitelist
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PHISING_DIR = os.path.join(BASE_DIR, '..', '..', 'Phising')

# Try to load V3 model dengan smart whitelist
try:
    model = joblib.load(os.path.join(PHISING_DIR, "model_v3.pkl"))
    feature_cols = joblib.load(os.path.join(PHISING_DIR, "feature_cols_v3.pkl"))
    threshold = joblib.load(os.path.join(PHISING_DIR, "threshold_v3.pkl"))
    
    # Try smart whitelist first, fallback to regular whitelist
    try:
        KNOWN_SAFE_DOMAINS = joblib.load(os.path.join(PHISING_DIR, "smart_whitelist.pkl"))
        print("✅ Model V3 + Smart Whitelist LOADED")
    except FileNotFoundError:
        KNOWN_SAFE_DOMAINS = joblib.load(os.path.join(PHISING_DIR, "whitelist_domains.pkl"))
        print("✅ Model V3 + Regular Whitelist LOADED")
        
except FileNotFoundError:
    print("⚠️  Model V3 tidak ditemukan, menggunakan V2...")
    model = joblib.load(os.path.join(PHISING_DIR, "model_v2.pkl"))
    feature_cols = joblib.load(os.path.join(PHISING_DIR, "feature_cols_v2.pkl"))
    threshold = joblib.load(os.path.join(PHISING_DIR, "threshold_v2.pkl"))
    KNOWN_SAFE_DOMAINS = {
        "google.com", "youtube.com", "facebook.com", "wikipedia.org", "twitter.com",
        "instagram.com", "linkedin.com", "github.com", "stackoverflow.com", "reddit.com",
        "amazon.com", "microsoft.com", "apple.com", "netflix.com", "spotify.com",
        "tokopedia.com", "shopee.co.id", "bukalapak.com", "gojek.com", "grab.com",
        "bca.co.id", "mandiri.co.id", "bni.co.id", "bri.co.id", "kemenkeu.go.id",
    }
    print("✅ Model V2 + Basic Whitelist LOADED (Fallback)")

def is_known_safe(hostname: str) -> bool:
    """
    Check if domain is in known safe list.
    Handles both exact matches (google.com) and subdomains (mail.google.com)
    """
    if not hostname:
        return False
    
    hostname = hostname.lower()
    
    # Check exact match
    if hostname in KNOWN_SAFE_DOMAINS:
        return True
    
    # Check if subdomain of known safe domain (e.g., www.google.com → google.com)
    parts = hostname.split(".")
    
    # Check base domains with up to 3 parts (e.g., .co.id)
    for n in range(2, min(len(parts) + 1, 5)):
        domain = ".".join(parts[-n:])
        if domain in KNOWN_SAFE_DOMAINS:
            return True
    
    return False

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "online", "service": "Phishing Detection API"})

@app.route('/api/check-url', methods=['POST'])
def check_url():
    """
    Check single URL for phishing dengan priority logic
    Request: {"url": "https://example.com"}
    Response: {
        "url": "https://example.com",
        "is_phishing": false,
        "confidence": 95.5,
        "risk_level": "LOW",
        "reasons": ["✅ URL terlihat aman..."]
    }
    """
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        
        if not url:
            return jsonify({"error": "URL tidak boleh kosong"}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = "http://" + url
        
        # Extract hostname
        hostname = ""
        try:
            hostname = urllib.parse.urlparse(url).hostname or ""
        except:
            pass
        
        # STEP 1: Check whitelist FIRST (highest priority)
        # ++++++++++++++++++++++++++++++++++++++++++
        if is_known_safe(hostname):
            # Jika dari domain terpercaya, langsung return SAFE meski ada indikator phishing di URL
            reasons = [
                f"✅ Domain {hostname} adalah domain terpercaya",
                "✅ Website ini adalah layanan resmi yang aman",
                "✅ Whitelist protection: Perlindungan berkode untuk domain verifikasi"
            ]
            
            return jsonify({
                "url": url,
                "is_phishing": False,
                "confidence": 99.0,
                "phish_prob": 1.0,
                "safe_prob": 99.0,
                "risk_level": "SAFE ✅",
                "reasons": reasons,
                "status": "safe",
                "protection_type": "whitelist",
                "message": f"Domain {hostname} telah diverifikasi sebagai AMAN"
            })
        
        # STEP 2: Extract features dan jalankan model
        # ++++++++++++++++++++++++++++++++++++++++++
        features = extract_features(url)
        X = pd.DataFrame([{col: features.get(col, 0) for col in feature_cols}])
        
        # Get prediction
        proba = model.predict_proba(X)[0]
        phish_prob = float(proba[1])
        safe_prob = float(proba[0])

        prediction = 1 if phish_prob > threshold else 0
        is_phishing = prediction == 1
        
        confidence = round(max(phish_prob, safe_prob) * 100, 2)
        
        # Get risk factors or safe reasons
        if is_phishing:
            reasons = get_url_risk_factors(url)
            risk_level = "CRITICAL" if confidence >= 90 else "HIGH" if confidence >= 75 else "MEDIUM"
        else:
            reasons = get_url_safe_reasons(url)
            risk_level = "LOW"
        
        return jsonify({
            "url": url,
            "is_phishing": is_phishing,
            "confidence": confidence,
            "model_confidence_explained": f"Model yakin {confidence}% bahwa URL ini {'⚠️  PHISHING' if is_phishing else '✅ AMAN'}",
            "phish_prob": round(phish_prob * 100, 2),
            "safe_prob": round(safe_prob * 100, 2),
            "risk_level": risk_level,
            "reasons": reasons,
            "status": "phishing" if is_phishing else "safe",
            "protection_type": "ml_model"
        })
    
    except Exception as e:
        import traceback
        return jsonify({
            "error": f"Error analyzing URL: {str(e)}",
            "traceback": traceback.format_exc()
        }), 500

@app.route('/api/batch-check', methods=['POST'])
def batch_check():
    """
    Check multiple URLs at once (max 20)
    Request: {"urls": ["url1", "url2", ...]}
    """
    try:
        data = request.get_json(silent=True) or {}
        urls = data.get("urls", [])
        
        if not isinstance(urls, list):
            return jsonify({"error": "URLs harus berupa list"}), 400
        
        if len(urls) > 20:
            return jsonify({"error": "Maksimum 20 URLs per request"}), 400
        
        results = []
        for url in urls:
            url = url.strip()
            if not url:
                continue

            if not url.startswith(('http://', 'https://')):
                url = "http://" + url

            try:
                features = extract_features(url)
                X = pd.DataFrame([{col: features.get(col, 0) for col in feature_cols}])

                proba = model.predict_proba(X)[0]
                phish_prob = float(proba[1])
                safe_prob = float(proba[0])

                prediction = 1 if phish_prob > threshold else 0
                is_phishing = prediction == 1

                confidence = round(max(phish_prob, safe_prob) * 100, 2)

                results.append({
                    "url": url,
                    "is_phishing": is_phishing,
                    "confidence": confidence,
                    "status": "phishing" if is_phishing else "safe"
                })

            except Exception as e:
                results.append({
                    "url": url,
                    "error": str(e),
                    "is_phishing": None
                })
        
        return jsonify({"results": results, "total": len(results)})
    
    except Exception as e:
        return jsonify({"error": f"Batch check error: {str(e)}"}), 500

if __name__ == '__main__':
    print("🛡️  Phishing Detection API - Starting...")
    print("🌐 API running on http://localhost:5001")
    app.run(debug=False, host='localhost', port=5001)