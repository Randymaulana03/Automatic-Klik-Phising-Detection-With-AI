# 🛡️ Automatic Phishing Detection System

Sistem otomatis untuk mendeteksi phishing URLs saat Anda mengklik link. **Tidak perlu copy-paste URL lagi!**<br>
untuk technical report bisa di akses di folder **docs -> TECHNICAL_REPORT.MD**

## ✨ Fitur Utama

### 🎯 3 Komponen Terintegrasi

1. **Browser Extension** (Auto-detection)
   - Deteksi otomatis setiap klik link
   - Popup warning jika phishing
   - Options: "Lanjut" atau "Balik"
   - Tidak ada popup jika URL aman ✅

2. **Backend API** (Flask)
   - REST API di port 5001
   - Menggunakan ML model yang sudah dilatih
   - Response cepat (<500ms)
   - Dukungan batch check

---

## 🚀 Instalasi Cepat

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Start Backend API
```bash
python backend_api/api.py
```
✅ Server siap di http://localhost:5001

### Step 3: Load Browser Extension

**Chrome:**
```
1. Buka chrome://extensions/
2. Aktifkan "Developer mode" (top right)
3. Klik "Load unpacked"
4. Pilih folder: browser_extension/
```

**Firefox:**
```
1. Buka about:debugging#/runtime/this-firefox
2. Klik "Load Temporary Add-on"
3. Pilih file: manifest.json
```

---

## 📖 Cara Kerja

### Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                  User Clicks Link                            │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│         Content Script Intercept (content.js)               │
│         - Detect link click                                 │
│         - Extract URL                                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│         Send to Backend API (background.js)                 │
│         POST http://localhost:5001/api/check-url            │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│       ML Model Decision (API: api.py)                        │
│       - Extract 71 features                                 │
│       - Random Forest prediction                            │
│       - Get risk factors                                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
            ┌──────────┴──────────┐
            │                     │
            ▼                     ▼
       PHISHING               SAFE
            │                     │
            ▼                     ▼
    Popup Warning        Direct Navigate
    - Title: 🚨           (No popup)
    - Reasons             Navigate to URL
    - Buttons:            Seamless UX
      Lanjut/Balik
```

---

## 🎨 Visual Examples

### Safe URL - No Popup
```
User clicks: https://github.com/user/repo
      ↓
Content Script checks
      ↓
Backend: is_phishing = FALSE
      ↓
✅ Direct navigate (no popup)
```

### Phishing URL - Popup Warning
```
User clicks: https://paypal-verify-secure.tk/login
      ↓
Content Script checks
      ↓
Backend: is_phishing = TRUE (confidence 92%)
      ↓
🚨 POPUP MUNCUL:
┌─────────────────────────────────┐
│ 🚨 Potensi Link Phishing!       │
│                                 │
│ URL terdeteksi berbahaya:       │
│ confidence 92%                  │
│ paypal-verify-secure.tk/login   │
│                                 │
│ Alasan:                         │
│ • Menyamar sebagai paypal       │
│ • TLD mencurigakan: .tk         │
│ • Kata "verify" mencurigakan    │
│                                 │
│ [← Balik] [Lanjut >]            │
└─────────────────────────────────┘
```

---

## 📁 Struktur Folder

```
Automatic Klik Phising Detection With AI/
│
├── backend_api/
│   └── api.py              # 🔧 Flask REST API
│       ├── /health
│       ├── /api/check-url  (POST)
│       └── /api/batch-check (POST)
│
├── browser_extension/
│   ├── manifest.json       # 📋 Chrome/Firefox config
│   ├── background.js       # 🔌 Service worker
│   ├── content.js          # 🎯 Link interceptor
│   ├── popup.html          # 🖼️ Control panel
│   └── popup.js            # ⚙️ Popup logic

```

---

## ⚙️ Configuration

### Backend API Settings
Edit `backend_api/api.py`:

```python
# Change API port
app.run(debug=False, host='localhost', port=5001)

# Add to whitelist (skip check)
KNOWN_SAFE_DOMAINS = {
    "google.com",
    "custom-domain.com"  # Add your domain
}
```

### Browser Extension Settings
Edit `browser_extension/background.js`:

```javascript
const API_URL = 'http://localhost:5001/api/check-url';
// Change if API on different machine/port
```

Edit `browser_extension/popup.html`:
```html
<!-- Customize warning message -->
```

---

## 🔌 API Endpoints

### 1. Health Check
```
GET /health
Response: {"status": "online", "service": "Phishing Detection API"}
```

### 2. Check Single URL
```
POST /api/check-url
Content-Type: application/json

Request:
{
  "url": "https://example.com"
}

Response:
{
  "url": "https://example.com",
  "is_phishing": false,
  "confidence": 95.5,
  "phish_prob": 4.5,
  "safe_prob": 95.5,
  "risk_level": "LOW",
  "status": "safe",
  "reasons": [
    "✅ URL terlihat aman",
    "✅ Menggunakan HTTPS",
    "✅ Tidak mengandung karakter mencurigakan"
  ]
}
```

### 3. Batch Check (Max 20 URLs)
```
POST /api/batch-check
Content-Type: application/json

Request:
{
  "urls": [
    "https://github.com",
    "https://phishing-site.tk/login"
  ]
}

Response:
{
  "results": [
    {"url": "https://github.com", "is_phishing": false, "confidence": 95.5, "status": "safe"},
    {"url": "https://phishing-site.tk/login", "is_phishing": true, "confidence": 89.2, "status": "phishing"}
  ],
  "total": 2
}
```

---

## 🎯 Usage Examples

### Example 1: Google Link (Safe)
```
Web Page: Click on "Visit Google"
Link: https://www.google.com

Process:
1. Extension intercept click
2. Send to API: {url: "https://www.google.com"}
3. Backend check: is_phishing = FALSE
4. Response: navigate (no popup)
5. Result: Go to google.com directly ✅
```

### Example 2: Malicious PayPal Link
```
Web Page: Click on "Verify Account"
Link: http://paypal-secure-verify.tk/login?user=account

Process:
1. Extension intercept click
2. Send to API: {url: "http://paypal-secure-verify.tk/login?user=account"}
3. Backend check features:
   - TLD .tk (suspicious)
   - Subdomain "paypal-secure" (brand spoofing)
   - Kata "verify" (phishing keyword)
   - is_phishing = TRUE (confidence 92%)
4. Response: Show warning popup
5. User clicks "Balik" → go back safely ✅
```

---

## 🛠️ Troubleshooting

### Extension tidak bekerja

**Problem:** Extension tidak mendeteksi link
```
Solution:
1. ✅ Pastikan Backend API running:
   python backend_api/api.py
2. ✅ Check port 5001 available:
   netstat -ano | findstr 5001
3. ✅ Reload extension: F5 or reload button
4. ✅ Check console: F12 → Console tab
```

### "Connection refused" Error
```
Solution:
1. Backend belum di-start
2. Port 5001 sudah terpakai
3. Firewall block localhost

Fix:
- python backend_api/api.py
- atau: python backend_api/api.py --port 5002
```

### Popup tidak muncul
```
Solution:
1. ✅ Check is_phishing value dari API
2. ✅ Pastikan confidence > threshold
3. ✅ Check content.js di F12 Console

Debug:
- Add breakpoint di content.js
- Check API response
```

---

## 📊 Statistics & Monitoring
### View in Extension
- Popup icon menunjukkan extension ON/OFF
- Click untuk open control panel

---

## 🔐 Security & Privacy

### ✅ Safe
- ✓ Hanya local API (http://localhost:5001)
- ✓ Model ML jalan lokal
- ✓ No data sent ke external server
- ✓ Browsing data private
- ✓ Open source code

### ⚠️ Limitations
- ⚠ Model accuracy ~91% (bukan 100%)
- ⚠ URL analysis saja (tidak check page content)
- ⚠ False positives possible
- ⚠ Butuh user judgment untuk URL samar

---

## 🧪 Testing

### Manual Test
```
1. Start Backend: python backend_api/api.py
2. Load Extension
3. Go to test website
4. Click link → see result
```

### Curl Test
```bash
# Safe URL
curl -X POST http://localhost:5001/api/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'

# Phishing URL
curl -X POST http://localhost:5001/api/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypal-secure.tk/login"}'
```

---

## 📝 Notes

- Extension bekerja di semua website
- Popup hanya muncul jika phishing terdeteksi
- Safe URLs tidak ada popup (seamless UX)
- System memory ~50-150 MB

---

## 🤝 Contributing

Issues/suggestions? Check:
1. Console F12 untuk error
2. Backend log output
3. Extension manifest.json

---

**Status:** ✅ Production Ready
**Last Updated:** March 2026
**Support:** Open Source
