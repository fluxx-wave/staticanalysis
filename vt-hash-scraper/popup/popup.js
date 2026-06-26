document.addEventListener('DOMContentLoaded', () => {
  // ── DOM References ──
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const cacheCount = document.getElementById('cacheCount');
  const currentPage = document.getElementById('currentPage');
  const sheetsEndpointStatus = document.getElementById('sheetsEndpointStatus');
  const sheetsUrlInput = document.getElementById('sheetsUrl');
  const sheetsStatus = document.getElementById('sheetsStatus');
  const autoPushToggle = document.getElementById('autoPush');
  const mainView = document.getElementById('mainView');
  const settingsView = document.getElementById('settingsView');
  const settingsToggle = document.getElementById('settingsToggle');
  const settingsBack = document.getElementById('settingsBack');
  const pushToSheetsBtn = document.getElementById('pushToSheets');
  const forceHeadersBtn = document.getElementById('forceHeadersBtn');

  let isSettingsOpen = false;

  // ── Settings Toggle (gear icon) ──
  function openSettings() {
    isSettingsOpen = true;
    mainView.classList.add('hidden');
    settingsView.classList.remove('hidden');
    settingsToggle.classList.add('active');
  }

  function closeSettings() {
    isSettingsOpen = false;
    settingsView.classList.add('hidden');
    mainView.classList.remove('hidden');
    settingsToggle.classList.remove('active');
  }

  settingsToggle.addEventListener('click', () => {
    if (isSettingsOpen) closeSettings();
    else openSettings();
  });

  settingsBack.addEventListener('click', closeSettings);

  // ── Check Current Tab ──
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (tab?.url?.includes('virustotal.com')) {
      statusDot.classList.add('active');
      const hashMatch = tab.url.match(/\/gui\/file\/([a-fA-F0-9]{32,64})/);
      if (hashMatch) {
        statusText.textContent = 'Active — Scraping hash';
        currentPage.textContent = hashMatch[1].substring(0, 16) + '...';
      } else {
        statusText.textContent = 'Active — On VirusTotal';
        currentPage.textContent = 'No hash detected';
      }
    } else {
      statusDot.classList.add('inactive');
      statusText.textContent = 'Inactive — Not on VirusTotal';
      currentPage.textContent = 'Navigate to virustotal.com';
    }
  });

  // ── Count Cached Results ──
  chrome.storage.local.get(null, (items) => {
    const vtKeys = Object.keys(items).filter(k =>
      k.startsWith('vt_') && k !== 'vt_sheets_url' && k !== 'vt_auto_push'
    );
    cacheCount.textContent = vtKeys.length;
  });

  // ── Load Saved Settings ──
  chrome.storage.local.get(['vt_sheets_url', 'vt_auto_push'], (r) => {
    if (r.vt_sheets_url) {
      sheetsUrlInput.value = r.vt_sheets_url;
      sheetsEndpointStatus.textContent = 'Configured ✓';
      sheetsEndpointStatus.className = 'info-value configured';
      sheetsStatus.innerHTML = '<span style="color:#10B981">✓ Endpoint configured</span>';
      pushToSheetsBtn.disabled = false;
      if (forceHeadersBtn) forceHeadersBtn.disabled = false;
    } else {
      sheetsEndpointStatus.textContent = 'Not configured';
      sheetsEndpointStatus.className = 'info-value not-configured';
      pushToSheetsBtn.disabled = true;
      if (forceHeadersBtn) forceHeadersBtn.disabled = true;
    }
    autoPushToggle.checked = !!r.vt_auto_push;
  });

  // ── Live URL Validation ──
  sheetsUrlInput.addEventListener('input', () => {
    const url = sheetsUrlInput.value.trim();
    sheetsUrlInput.classList.remove('valid', 'invalid');
    sheetsStatus.innerHTML = '';
    if (!url) return;
    if (url.startsWith('https://script.google.com/')) {
      sheetsUrlInput.classList.add('valid');
    } else {
      sheetsUrlInput.classList.add('invalid');
      sheetsStatus.innerHTML = '<span style="color:#EF4444">⚠ Must be a Google Apps Script URL</span>';
      sheetsStatus.className = 'settings-status error';
    }
  });

  // ── Save Settings ──
  document.getElementById('saveSettings').addEventListener('click', () => {
    const url = sheetsUrlInput.value.trim();
    const autoPush = autoPushToggle.checked;

    if (url && !url.startsWith('https://script.google.com/')) {
      sheetsStatus.innerHTML = '✗ Invalid URL — must start with https://script.google.com/';
      sheetsStatus.className = 'settings-status error';
      showToast('Invalid endpoint URL', 'error');
      return;
    }

    const settings = { vt_auto_push: autoPush };

    if (url) {
      settings.vt_sheets_url = url;
    } else {
      chrome.storage.local.remove('vt_sheets_url');
    }

    chrome.storage.local.set(settings, () => {
      sheetsStatus.innerHTML = '✓ Settings saved successfully!';
      sheetsStatus.className = 'settings-status success';
      showToast('Settings saved!', 'success');

      // Update main view status
      if (url) {
        sheetsEndpointStatus.textContent = 'Configured ✓';
        sheetsEndpointStatus.className = 'info-value configured';
        pushToSheetsBtn.disabled = false;
        if (forceHeadersBtn) forceHeadersBtn.disabled = false;
      } else {
        sheetsEndpointStatus.textContent = 'Not configured';
        sheetsEndpointStatus.className = 'info-value not-configured';
        pushToSheetsBtn.disabled = true;
        if (forceHeadersBtn) forceHeadersBtn.disabled = true;
      }

      // Auto-close settings after saving
      setTimeout(closeSettings, 800);
    });
  });

  // ── Test Endpoint ──
  document.getElementById('testEndpoint').addEventListener('click', () => {
    const url = sheetsUrlInput.value.trim();
    if (!url) {
      sheetsStatus.innerHTML = '⚠ Enter a URL first';
      sheetsStatus.className = 'settings-status error';
      return;
    }
    if (!url.startsWith('https://script.google.com/')) {
      sheetsStatus.innerHTML = '✗ Invalid Google Apps Script URL';
      sheetsStatus.className = 'settings-status error';
      return;
    }

    sheetsStatus.innerHTML = '⏳ Testing endpoint...';
    sheetsStatus.className = 'settings-status info';

    const testPayload = {
      test: true,
      timestamp: new Date().toISOString(),
      source: 'VT Hash Scraper — Connection Test'
    };

    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: JSON.stringify(testPayload),
      mode: 'no-cors'
    }).then(() => {
      sheetsStatus.innerHTML = '✓ Request sent! Check your Google Sheet to confirm.';
      sheetsStatus.className = 'settings-status success';
      showToast('Test request sent!', 'success');
    }).catch(err => {
      sheetsStatus.innerHTML = '✗ Failed: ' + err.message;
      sheetsStatus.className = 'settings-status error';
      showToast('Test failed', 'error');
    });
  });

  // ── Push to Sheets (Main View) ──
  pushToSheetsBtn.addEventListener('click', () => {
    chrome.storage.local.get('vt_sheets_url', (r) => {
      const url = r.vt_sheets_url;
      if (!url) {
        showToast('Configure endpoint in Settings first', 'error');
        return;
      }

      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (!tab?.url?.includes('virustotal.com/gui/file/')) {
          showToast('Navigate to a VT file page first', 'error');
          return;
        }

        const hashMatch = tab.url.match(/\/gui\/file\/([a-fA-F0-9]{32,64})/);
        if (!hashMatch) {
          showToast('No hash found on current page', 'error');
          return;
        }

        const hash = hashMatch[1];
        pushToSheetsBtn.disabled = true;
        pushToSheetsBtn.innerHTML = '⏳ Pushing...';

        chrome.storage.local.get(`vt_${hash}`, (result) => {
          const cached = result[`vt_${hash}`];
          if (!cached?.data) {
            showToast('No scraped data found. Open the panel first.', 'error');
            resetPushBtn();
            return;
          }

          const payload = {
            ...cached.data,
            sourceUrl: tab.url,
            pushedAt: new Date().toISOString()
          };

          fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: JSON.stringify(payload),
            mode: 'no-cors'
          }).then(() => {
            pushToSheetsBtn.innerHTML = '✓ Pushed!';
            pushToSheetsBtn.classList.add('success');
            showToast('Data pushed to Google Sheets!', 'success');
            setTimeout(resetPushBtn, 2500);
          }).catch(err => {
            pushToSheetsBtn.innerHTML = '✗ Failed';
            pushToSheetsBtn.classList.add('error');
            showToast('Push failed: ' + err.message, 'error');
            setTimeout(resetPushBtn, 2500);
          });
        });
      });
    });
  });

  function resetPushBtn() {
    pushToSheetsBtn.disabled = false;
    pushToSheetsBtn.classList.remove('success', 'error');
    pushToSheetsBtn.innerHTML = `<svg viewBox="0 0 24 24" class="btn-icon"><path d="M19 11H7.83l4.88-4.88c.39-.39.39-1.03 0-1.42a.996.996 0 00-1.41 0l-6.59 6.59a.996.996 0 000 1.41l6.59 6.59a.996.996 0 101.41-1.41L7.83 13H19c.55 0 1-.45 1-1s-.45-1-1-1z" transform="rotate(180 12 12)"/></svg> Push to Sheets`;
    chrome.storage.local.get('vt_sheets_url', (r) => {
      pushToSheetsBtn.disabled = !r.vt_sheets_url;
    });
  }

  // ── Force Add Headers ──
  if (forceHeadersBtn) {
    forceHeadersBtn.addEventListener('click', () => {
      chrome.storage.local.get('vt_sheets_url', (r) => {
        const url = r.vt_sheets_url;
        if (!url) {
          showToast('Configure endpoint in Settings first', 'error');
          return;
        }

        forceHeadersBtn.disabled = true;
        forceHeadersBtn.textContent = '⏳ Adding...';

        const payload = { action: 'forceHeaders' };

        fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: JSON.stringify(payload),
          mode: 'no-cors'
        }).then(() => {
          forceHeadersBtn.textContent = '✓ Headers Added';
          showToast('Headers injected into Sheet!', 'success');
          setTimeout(() => {
            forceHeadersBtn.disabled = false;
            forceHeadersBtn.textContent = 'Add Headers';
          }, 2500);
        }).catch(err => {
          forceHeadersBtn.textContent = '✗ Failed';
          showToast('Request failed: ' + err.message, 'error');
          setTimeout(() => {
            forceHeadersBtn.disabled = false;
            forceHeadersBtn.textContent = 'Add Headers';
          }, 2500);
        });
      });
    });
  }

  // ── Clear Cache ──
  document.getElementById('clearCache').addEventListener('click', () => {
    chrome.storage.local.get(null, (items) => {
      const vtKeys = Object.keys(items).filter(k =>
        k.startsWith('vt_') && k !== 'vt_sheets_url' && k !== 'vt_auto_push'
      );
      chrome.storage.local.remove(vtKeys, () => {
        cacheCount.textContent = '0';
        showToast('Cache cleared!', 'success');
      });
    });
  });

  // ── Open VirusTotal ──
  document.getElementById('openVT').addEventListener('click', () => {
    chrome.tabs.create({ url: 'https://www.virustotal.com' });
  });

  // ── Toast Notification ──
  function showToast(message, type = '') {
    document.querySelectorAll('.popup-toast').forEach(t => t.remove());
    const toast = document.createElement('div');
    toast.className = `popup-toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2500);
  }
});
