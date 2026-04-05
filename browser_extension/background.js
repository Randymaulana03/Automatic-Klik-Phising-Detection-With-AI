const API_URL = 'http://localhost:5001/api/check-url';
let isEnabled = true;
let urlCache = new Map();

// 1. Sinkronisasi Awal & Health Check
chrome.storage.local.get('phishing_detector_enabled', (result) => {
    isEnabled = result.phishing_detector_enabled !== false;
    checkServerHealth(); // Cek kesehatan server saat startup
});

// 2. Pantau perubahan toggle dari Popup
chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && changes.phishing_detector_enabled) {
        isEnabled = changes.phishing_detector_enabled.newValue;
        checkServerHealth(); // Re-check status saat toggle diubah
    }
});

// 3. Pesan dari Content Script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getStatus') {
        sendResponse({ enabled: isEnabled });
        return false;
    }

    if (request.action === 'checkURL') {
        if (!isEnabled) {
            sendResponse({ is_phishing: false });
            return false;
        }
        checkPhishingURL(request.url)
            .then(result => sendResponse(result))
            .catch(error => sendResponse({ error: error.message }));
        return true; 
    }
});

// 4. Fungsi Utama Fetch dengan Cache
async function checkPhishingURL(url) {
    if (urlCache.has(url)) {
        console.log("⚡ Cache Hit:", url);
        return urlCache.get(url);
    }

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) throw new Error(`API error: ${response.status}`);
        const data = await response.json();
        
        const result = {
            success: true,
            is_phishing: data.is_phishing,
            confidence: data.confidence,
            risk_level: data.risk_level,
            reasons: data.reasons,
            status: data.status
        };

        urlCache.set(url, result); // Simpan ke cache
        if (urlCache.size > 100) urlCache.delete(urlCache.keys().next().value); // Limit cache
        
        updateLocalStats(data.is_phishing);
        return result;
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// 5. Statistik Dashboard
function updateLocalStats(isPhishing) {
    chrome.storage.local.get('phishing_stats', (result) => {
        let stats = result.phishing_stats || { checked: 0, phishing: 0, safe: 0 };
        stats.checked++;
        if (isPhishing) stats.phishing++; else stats.safe++;
        chrome.storage.local.set({ 'phishing_stats': stats });
    });
}

// 6. Health Check & Badge Logic (Digabung agar tidak bentrok)
async function checkServerHealth() {
    if (!isEnabled) {
        updateBadgeUI("OFF", "#f44336"); // Merah jika dimatikan user
        return;
    }

    try {
        const response = await fetch('http://localhost:5001/health');
        const data = await response.json();
        if (data.status === "online") {
            updateBadgeUI("ON", "#4caf50"); // Hijau jika server OK
        } else {
            updateBadgeUI("ERR", "#ff9800"); // Oranye jika server respon tapi aneh
        }
    } catch (error) {
        updateBadgeUI("X", "#f44336"); // Merah/X jika server Flask mati
    }
}

function updateBadgeUI(text, color) {
    chrome.action.setBadgeText({ text: text });
    chrome.action.setBadgeBackgroundColor({ color: color });
}

// Alarms & Listeners
// Alarms & Listeners
chrome.alarms.create("healthCheck", { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "healthCheck") checkServerHealth();
});

chrome.runtime.onStartup.addListener(checkServerHealth);
chrome.tabs.onActivated.addListener(checkServerHealth);