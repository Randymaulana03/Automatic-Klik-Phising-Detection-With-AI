/**
 * Content Script
 * Injected ke setiap halaman web
 * Intercept semua link click
 */

let isDetectorEnabled = true;

// Cek status saat pertama kali load
chrome.storage.local.get('phishing_detector_enabled', (result) => {
  isDetectorEnabled = result.phishing_detector_enabled !== false;
});

// Pantau perubahan status secara real-time (tanpa refresh halaman)
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && changes.phishing_detector_enabled) {
    isDetectorEnabled = changes.phishing_detector_enabled.newValue;
  }
});

/**
 * Intercept click pada semua link (<a> tags)
 */
document.addEventListener('click', function(event) {
  
  if (!isDetectorEnabled) return;
  
  const link = event.target.closest('a');
  if (!link) return;
  
  const url = link.href;
  if (url.includes('javascript:void(0)') || url.startsWith('#')) return;
  
  // Skip internal anchors, javascript:, mailto:, etc
  if (!url || !url.startsWith('http')) return;
  
  // Prevent default dan cek URL
  event.preventDefault();
  event.stopPropagation();
  
  checkAndNavigate(url);
}, true); // Use capture phase to intercept before other handlers

/**
 * Cek URL dan tampil popup jika phishing
 */
function checkAndNavigate(url) {
  console.log('🔍 Checking URL:', url);
  
  chrome.runtime.sendMessage(
    { action: 'checkURL', url: url },
    (response) => {
      if (response?.error) {
        console.error('Check error:', response.error);
        // If API fails, allow navigation
        window.location.href = url;
        return;
      }
      
      if (response?.is_phishing) {
        // URL is PHISHING - show warning popup
        showPhishingWarning(url, response.reasons, response.confidence);
      } else {
        // URL is SAFE - navigate directly (silent, no popup)
        window.location.href = url;
      }
    }
  );
}

/**
 * Tampil popup warning untuk phishing URL
 */
function showPhishingWarning(url, reasons, confidence) {
  // Buat popup overlay
  const overlay = document.createElement('div');
  overlay.id = 'phishing-detector-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0, 0, 0, 0.8);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2147483647; /* Nilai maksimal yang didukung browser */
    font-family: Arial, sans-serif;
    backdrop-filter: blur(4px); /* Efek blur pada background website */
`;
  
  // Buat popup content
  const popup = document.createElement('div');
  popup.style.cssText = `
    background: white;
    border-radius: 12px;
    padding: 32px;
    max-width: 500px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    animation: slideIn 0.3s ease;
  `;
  
  // Buat content
  let reasonsHTML = '';
  if (reasons && reasons.length > 0) {
    reasonsHTML = '<div style="margin: 20px 0;"><strong>Alasan:</strong><ul style="margin: 10px 0; padding-left: 20px;">';
    reasons.forEach(reason => {
      reasonsHTML += `<li style="margin: 8px 0; color: #555; font-size: 14px;">${escapeHtml(reason)}</li>`;
    });
    reasonsHTML += '</ul></div>';
  }
  
  popup.innerHTML = `
    <div style="text-align: center;">
      <div style="font-size: 48px; margin-bottom: 16px;">🚨</div>
      <h2 style="color: #d32f2f; margin: 0 0 10px 0; font-size: 24px;">Potensi Link Phishing!</h2>
      <p style="color: #666; margin: 0 0 16px 0; font-size: 14px;">
        Model AI mendeteksi link ini berpotensi berbahaya dengan confidence ${confidence}%
      </p>
      
      <div style="background: #ffe0e0; border-left: 4px solid #d32f2f; padding: 12px; border-radius: 4px; text-align: left; margin-bottom: 20px;">
        <div style="font-family: monospace; font-size: 12px; color: #666; word-break: break-all;">
          ${escapeHtml(url)}
        </div>
      </div>
      
      ${reasonsHTML}
      
      <div style="display: flex; gap: 12px; justify-content: center; margin-top: 24px;">
        <button id="phishing-back-btn" style="
          padding: 10px 24px;
          background: #4caf50;
          color: white;
          border: none;
          border-radius: 6px;
          cursor: pointer;
          font-weight: bold;
          font-size: 14px;
        ">← Balik (Aman)</button>
        
        <button id="phishing-continue-btn" style="
          padding: 10px 24px;
          background: #d32f2f;
          color: white;
          border: none;
          border-radius: 6px;
          cursor: pointer;
          font-weight: bold;
          font-size: 14px;
        ">Lanjut (Risiko)</button>
      </div>
      
      <p style="font-size: 12px; color: #999; margin-top: 16px;">
        🛡️ Phishing Klik Detector AI
      </p>
    </div>
  `;
  
  overlay.appendChild(popup);
  document.body.appendChild(overlay);
  
  // Add animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes slideIn {
      from {
        opacity: 0;
        transform: scale(0.9);
      }
      to {
        opacity: 1;
        transform: scale(1);
      }
    }
  `;
  document.head.appendChild(style);
  
  // Event listeners
  document.getElementById('phishing-back-btn').addEventListener('click', () => {
    overlay.remove();
    if (window.history.length > 1) {
      history.back();
    } else {
      window.close(); // Tutup tab jika tidak ada history (kasus New Tab)
    }
  });
  
  document.getElementById('phishing-continue-btn').addEventListener('click', () => {
    overlay.remove();
    window.location.href = url;
  });
  
  // Close on ESC
  document.addEventListener('keydown', (e) => {
    const overlay = document.getElementById('phishing-detector-overlay');
    if (e.key === 'Escape' && overlay) {
      overlay.remove();
      if (window.history.length > 1) {
        history.back();
      } else {
        window.close();
      }
    }
  });
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

console.log('✅ Phishing Detector Content Script Loaded');
