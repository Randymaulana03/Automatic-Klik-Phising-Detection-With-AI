"""
Backend API untuk Browser Extension & Desktop App
Standalone Flask server untuk deteksi URL phishing otomatis
"""
import os
import sys
import logging
import urllib.parse
import joblib
import pandas as pd
 
from flask import Flask, request, jsonify, g
from flask_cors import CORS
 
# Flask-Limiter opsional — jika tidak terinstall, rate limit dinonaktifkan
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _LIMITER_AVAILABLE = True
except ImportError:
    _LIMITER_AVAILABLE = False
 
# =============================================================================
# LOGGING
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)
 
# =============================================================================
# PATH SETUP — semua file model di folder yang sama dengan api.py
# =============================================================================
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR  = os.environ.get("MODEL_DIR", BASE_DIR)   # override via env var jika perlu
 
sys.path.insert(0, MODEL_DIR)
 
from feature_extractor import extract_features, get_url_risk_factors, get_url_safe_reasons
 
# =============================================================================
# LOAD MODEL
# =============================================================================
def _load(filename: str):
    path = os.path.join(MODEL_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"File model tidak ditemukan: {path}")
    return joblib.load(path)
 
logger.info("Memuat model...")
model        = _load("model.pkl")
feature_cols = _load("feature_cols.pkl")

# Threshold: bisa dari file opsional, fallback ke 0.5
_threshold_path = os.path.join(MODEL_DIR, "threshold.pkl")
THRESHOLD = joblib.load(_threshold_path) if os.path.exists(_threshold_path) else 0.5
logger.info(f"Model siap. Threshold: {THRESHOLD}, Fitur: {len(feature_cols)}")

# =============================================================================
# FLASK APP
# =============================================================================
app = Flask(__name__)

# CORS: set ALLOWED_ORIGINS="https://myextension.com,https://myapp.com" di env
_raw_origins = os.environ.get("ALLOWED_ORIGINS", "*")
_origins = [o.strip() for o in _raw_origins.split(",")] if _raw_origins != "*" else "*"
CORS(app, resources={r"/api/*": {"origins": _origins}})

# Rate limiting (jika tersedia)
if _LIMITER_AVAILABLE:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "60 per hour"],
        storage_uri="memory://",
    )
    _single_limit  = "30 per minute"
    _batch_limit   = "10 per minute"
else:
    logger.warning("flask-limiter tidak terinstall — rate limiting dinonaktifkan.")
    limiter = None

# =============================================================================
# SAFE DOMAIN ALLOWLIST
# =============================================================================
KNOWN_SAFE_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "github.com",
    "stackoverflow.com", "reddit.com", "amazon.com", "microsoft.com",
    "apple.com", "netflix.com", "spotify.com",
    "tokopedia.com", "shopee.co.id", "bukalapak.com",
    "gojek.com", "grab.com",
    "bca.co.id", "mandiri.co.id", "bni.co.id", "bri.co.id",
    "kemenkeu.go.id",
}

def _is_known_safe(hostname: str) -> bool:
    """Cek apakah hostname atau parent domain-nya ada di allowlist."""
    parts = hostname.lower().split(".")
    for n in range(2, min(len(parts) + 1, 4)):
        if ".".join(parts[-n:]) in KNOWN_SAFE_DOMAINS:
            return True
    return False

# =============================================================================
# INPUT VALIDATION
# =============================================================================
_MAX_URL_LEN = 2048

def _validate_url(raw: str) -> tuple[str, str | None]:
    """
    Validasi dan normalisasi URL.
    Kembalikan (url_bersih, pesan_error).
    """
    url = raw.strip()
    if not url:
        return "", "URL tidak boleh kosong"
    if len(url) > _MAX_URL_LEN:
        return "", f"URL terlalu panjang (maks {_MAX_URL_LEN} karakter)"

    # Tambahkan scheme jika tidak ada
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            return "", "URL tidak valid: hostname tidak ditemukan"
        # Hostname hanya boleh karakter valid
        if not all(c.isalnum() or c in "-._~:@!$&'()*+,;=[]%" for c in parsed.netloc):
            return "", "URL mengandung karakter tidak valid di hostname"
    except Exception:
        return "", "URL tidak dapat di-parse"

    return url, None

# =============================================================================
# CORE DETECTION
# =============================================================================
def analyze_url(url: str) -> dict:
    """Jalankan deteksi phishing pada satu URL."""
    features = extract_features(url)
    X = pd.DataFrame([{col: features.get(col, 0) for col in feature_cols}])

    proba      = model.predict_proba(X)[0]
    phish_prob = float(proba[1])
    safe_prob  = float(proba[0])
    is_phishing = phish_prob > THRESHOLD

    # Risk level
    if phish_prob >= 0.90:
        risk_level = "CRITICAL"
    elif phish_prob >= 0.75:
        risk_level = "HIGH"
    elif phish_prob >= 0.60:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Safe domain override — TRANSPARAN, tidak memodifikasi probabilitas model
    overridden_by_safelist = False
    try:
        hostname = urllib.parse.urlparse(url).hostname or ""
        if _is_known_safe(hostname) and phish_prob < 0.65:
            # Domain dikenal aman dan model tidak sangat yakin = override ke safe
            # Probabilitas model TIDAK diubah agar tetap jujur
            is_phishing = False
            risk_level  = "LOW"
            overridden_by_safelist = True
    except Exception:
        logger.exception(f"Error saat cek safe domain untuk: {url}")

    confidence = round(max(phish_prob, safe_prob) * 100, 2)
    reasons    = get_url_risk_factors(url) if is_phishing else get_url_safe_reasons(url)

    result = {
        "url":                    url,
        "is_phishing":            is_phishing,
        "status":                 "phishing" if is_phishing else "safe",
        "risk_level":             risk_level,
        "confidence":             confidence,
        "phish_prob":             round(phish_prob * 100, 2),
        "safe_prob":              round(safe_prob  * 100, 2),
        "overridden_by_safelist": overridden_by_safelist,
        "reasons":                reasons,
    }
    return result

# =============================================================================
# REQUEST LOGGING
# =============================================================================
@app.before_request
def _log_request():
    logger.info(f"→ {request.method} {request.path} from {request.remote_addr}")

@app.after_request
def _log_response(response):
    logger.info(f"← {response.status_code} {request.path}")
    return response

# =============================================================================
# ROUTES
# =============================================================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":    "online",
        "service":   "Phishing Detection API",
        "threshold": THRESHOLD,
        "features":  len(feature_cols),
        "model":     type(model).__name__,
    })


@app.route("/api/check-url", methods=["POST"])
def check_url():
    # Rate limit per-endpoint jika tersedia
    if limiter:
        limiter.limit(_single_limit)(lambda: None)()

    try:
        data = request.get_json(silent=True) or {}
        url, err = _validate_url(data.get("url") or "")
        if err:
            return jsonify({"error": err}), 400

        result = analyze_url(url)
        return jsonify(result)

    except Exception:
        logger.exception(f"Error saat memproses check-url")
        return jsonify({"error": "Terjadi kesalahan internal"}), 500


@app.route("/api/batch-check", methods=["POST"])
def batch_check():
    if limiter:
        limiter.limit(_batch_limit)(lambda: None)()

    try:
        data = request.get_json(silent=True) or {}
        urls = data.get("urls", [])

        if not isinstance(urls, list):
            return jsonify({"error": "urls harus berupa list"}), 400
        if len(urls) > 20:
            return jsonify({"error": "Maksimum 20 URL per request"}), 400

        results = []
        for raw_url in urls:
            if not isinstance(raw_url, str):
                results.append({"url": str(raw_url), "error": "URL harus berupa string"})
                continue

            url, err = _validate_url(raw_url)
            if err:
                results.append({"url": raw_url.strip(), "error": err})
                continue

            try:
                results.append(analyze_url(url))
            except Exception:
                logger.exception(f"Error saat memproses URL dalam batch: {url}")
                results.append({"url": url, "error": "Gagal memproses URL ini", "is_phishing": None})

        phishing_count = sum(1 for r in results if r.get("is_phishing") is True)
        return jsonify({
            "results":        results,
            "total":          len(results),
            "phishing_count": phishing_count,
            "safe_count":     len(results) - phishing_count,
        })

    except Exception:
        logger.exception("Error saat memproses batch-check")
        return jsonify({"error": "Terjadi kesalahan internal"}), 500


# =============================================================================
# ENTRYPOINT
# =============================================================================
if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5001))
    logger.info(f"🛡️  Phishing Detection API berjalan di http://{host}:{port}")
    app.run(debug=False, host=host, port=port)
