/**
 * Popup Script - Control panel
 */

const toggleSwitch = document.getElementById('toggleSwitch');
const statusText = document.getElementById('statusText');
const statusIndicator = document.getElementById('statusIndicator');
const statStatus = document.getElementById('stat-status');

// Load saved state
chrome.storage.local.get('phishing_detector_enabled', (result) => {
  const enabled = result.phishing_detector_enabled !== false;
  toggleSwitch.checked = enabled;
  updateStatus(enabled);
});

// Toggle handler
toggleSwitch.addEventListener('change', () => {
  const enabled = toggleSwitch.checked;
  chrome.storage.local.set({ 'phishing_detector_enabled': enabled });
  updateStatus(enabled);
});

function updateStatus(enabled) {
  if (enabled) {
    statusText.textContent = 'Aktif';
    statusIndicator.textContent = '● Online';
    statusIndicator.className = 'status active';
    statStatus.textContent = '✓ Aktif';
  } else {
    statusText.textContent = 'Nonaktif';
    statusIndicator.textContent = '● Offline';
    statusIndicator.className = 'status inactive';
    statStatus.textContent = '✗ Nonaktif';
  }
}

// Reset stats is Maintenance
// document.getElementById('resetStats').addEventListener('click', () => {
//   chrome.storage.local.set({
//     'phishing_stats': { checked: 0, phishing: 0, safe: 0 }
//   });
//   alert('Stats direset!');
// });


// Open dashboard is Maintenance
// document.getElementById('openDashboard').addEventListener('click', () => {
//   chrome.tabs.create({ url: 'dashboard.html' });
// });
