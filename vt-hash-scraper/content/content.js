/**
 * VT Hash Scraper — Content Script
 * Injects into VirusTotal pages, intercepts data, and renders a side panel.
 */
(function () {
  'use strict';
  if (window.__vtScraperLoaded) return;
  window.__vtScraperLoaded = true;

  let scrapedData = null;
  let panelOpen = false;
  let settingsOpen = false;
  let hashQueueOpen = false;
  let hashList = [];
  let currentFilter = 'all';
  let searchQuery = '';
  const pushedHashes = new Set(); // Track hashes already pushed to Sheets this session

  // ── Inject page-level interceptor ──
  const s = document.createElement('script');
  s.src = chrome.runtime.getURL('content/injector.js');
  (document.head || document.documentElement).appendChild(s);
  s.onload = () => s.remove();

  // ── Listen for intercepted data ──
  window.addEventListener('message', (e) => {
    if (e.data?.source !== 'vt-hash-scraper') return;
    if (e.data.type === 'VT_FETCH_INTERCEPTED' && e.data.data?.data?.attributes) {
      scrapedData = e.data.data;
      updateFAB();
      if (panelOpen && !settingsOpen && !hashQueueOpen) renderPanel();
      saveToChromeStorage(scrapedData);
      // Auto-mark hash as crawled in the queue
      const scrapedHash = scrapedData?.data?.id || getHashFromURL();
      if (scrapedHash) markHashCrawled(scrapedHash);
      // Auto-push to Google Sheets in background
      autoPushToSheets();
    }
  });

  // ── Also scrape DOM as fallback ──
  function scrapeFromDOM() {
    const data = { detection: {}, meta: {}, names: [], tags: [] };
    try {
      // Try to find detection stats from the page
      const allText = document.body.innerText;
      const match = allText.match(/(\d+)\s*\/\s*(\d+)\s*security vendors/i);
      if (match) {
        data.detection.malicious = parseInt(match[1]);
        data.detection.total = parseInt(match[2]);
      }
      // Traverse shadow DOMs for detection rows
      queryShadowAll(document, 'vt-ui-file-card, vt-ui-detections-widget, .detection').forEach(el => {
        const text = el.textContent || el.innerText || '';
        if (text) data.rawText = (data.rawText || '') + text + '\n';
      });
    } catch (e) { /* ignore */ }
    return data;
  }

  function queryShadowAll(root, selector) {
    const results = [];
    try {
      root.querySelectorAll(selector).forEach(el => results.push(el));
      root.querySelectorAll('*').forEach(el => {
        if (el.shadowRoot) {
          queryShadowAll(el.shadowRoot, selector).forEach(r => results.push(r));
        }
      });
    } catch (e) { /* ignore */ }
    return results;
  }

  function saveToChromeStorage(data) {
    try {
      const hash = getHashFromURL();
      if (hash && data) {
        chrome.storage.local.set({ [`vt_${hash}`]: { data, ts: Date.now() } });
      }
    } catch (e) { /* ignore */ }
  }

  function getHashFromURL() {
    const m = window.location.pathname.match(/\/gui\/file\/([a-fA-F0-9]{32,64})/);
    return m ? m[1] : null;
  }

  // ── Create FAB ──
  function createFAB() {
    if (document.getElementById('vt-scraper-fab')) return;
    const fab = document.createElement('button');
    fab.id = 'vt-scraper-fab';
    fab.title = 'VT Hash Scraper';
    fab.innerHTML = `<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>`;
    fab.onclick = togglePanel;
    document.body.appendChild(fab);
  }

  function updateFAB() {
    const fab = document.getElementById('vt-scraper-fab');
    if (!fab) return;
    const attrs = scrapedData?.data?.attributes;
    if (attrs) {
      const stats = attrs.last_analysis_stats || {};
      const mal = stats.malicious || 0;
      fab.classList.add('vts-has-data');
      if (mal > 0) {
        fab.classList.add('vts-malicious');
        let badge = fab.querySelector('.vts-badge');
        if (!badge) { badge = document.createElement('span'); badge.className = 'vts-badge'; fab.appendChild(badge); }
        badge.textContent = mal;
      }
    }
  }

  // ── Panel Toggle ──
  function togglePanel() {
    panelOpen = !panelOpen;
    let panel = document.getElementById('vt-scraper-panel');
    if (!panel) { panel = createPanel(); }
    if (panelOpen) {
      panel.classList.add('vts-open');
      if (scrapedData) renderPanel();
      else renderEmpty();
    } else {
      panel.classList.remove('vts-open');
    }
  }

  function createPanel() {
    const panel = document.createElement('div');
    panel.id = 'vt-scraper-panel';
    panel.innerHTML = `
      <div class="vts-header">
        <div class="vts-header-icon"><svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg></div>
        <div><div class="vts-header-title">VT Hash Scraper</div><div class="vts-header-sub">Real-time data extraction</div></div>
        <div class="vts-header-actions">
          <button class="vts-header-btn" id="vts-hashqueue" title="Hash Queue"><svg viewBox="0 0 24 24"><path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/></svg></button>
          <button class="vts-header-btn" id="vts-settings" title="Settings"><svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 00-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1115.6 12 3.61 3.61 0 0112 15.6z"/></svg></button>
          <button class="vts-header-btn" id="vts-refresh" title="Re-scrape"><svg viewBox="0 0 24 24"><path d="M17.65 6.35A7.96 7.96 0 0012 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0112 18c-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg></button>
          <button class="vts-header-btn" id="vts-close" title="Close"><svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg></button>
        </div>
      </div>
      <div class="vts-body" id="vts-body"></div>
      <div class="vts-settings-body" id="vts-settings-body" style="display:none"></div>
      <div class="vts-queue-body" id="vts-queue-body" style="display:none"></div>
      <div class="vts-footer">
        <span>VT Hash Scraper v1.0</span>
        <div style="display:flex;gap:6px">
          <button class="vts-export-btn" id="vts-headers" title="Force add headers to Google Sheet">Add Headers</button>
          <button class="vts-export-btn" id="vts-sheets" title="Send to Google Sheets">📊 Sheets</button>
          <button class="vts-export-btn" id="vts-export">Export JSON</button>
        </div>
      </div>`;
    document.body.appendChild(panel);
    panel.querySelector('#vts-close').onclick = togglePanel;
    panel.querySelector('#vts-settings').onclick = toggleSettings;
    panel.querySelector('#vts-hashqueue').onclick = toggleHashQueue;
    panel.querySelector('#vts-refresh').onclick = () => { scrapedData = null; renderLoading(); location.reload(); };
    panel.querySelector('#vts-export').onclick = exportJSON;
    panel.querySelector('#vts-sheets').onclick = sendToSheets;
    panel.querySelector('#vts-headers').onclick = forceHeaders;
    return panel;
  }

  // ── Hide all views helper ──
  function hideAllViews() {
    const body = document.getElementById('vts-body');
    const settingsBody = document.getElementById('vts-settings-body');
    const queueBody = document.getElementById('vts-queue-body');
    if (body) body.style.display = 'none';
    if (settingsBody) settingsBody.style.display = 'none';
    if (queueBody) queueBody.style.display = 'none';
    document.querySelectorAll('.vts-header-btn').forEach(b => b.classList.remove('vts-active'));
    settingsOpen = false;
    hashQueueOpen = false;
  }

  function showMainView() {
    hideAllViews();
    const body = document.getElementById('vts-body');
    if (body) body.style.display = 'block';
  }

  // ── Settings Panel ──
  function toggleSettings() {
    if (settingsOpen) {
      showMainView();
      return;
    }
    hideAllViews();
    settingsOpen = true;
    const settingsBody = document.getElementById('vts-settings-body');
    const settingsBtn = document.getElementById('vts-settings');
    if (settingsBody) settingsBody.style.display = 'flex';
    if (settingsBtn) settingsBtn.classList.add('vts-active');
    renderSettings();
  }

  // ── Hash Queue Panel ──
  function toggleHashQueue() {
    if (hashQueueOpen) {
      showMainView();
      return;
    }
    hideAllViews();
    hashQueueOpen = true;
    const queueBody = document.getElementById('vts-queue-body');
    const queueBtn = document.getElementById('vts-hashqueue');
    if (queueBody) queueBody.style.display = 'flex';
    if (queueBtn) queueBtn.classList.add('vts-active');
    renderHashQueue();
  }

  function renderHashQueue() {
    const queueBody = document.getElementById('vts-queue-body');
    if (!queueBody) return;

    queueBody.innerHTML = `
      <div class="vts-settings-content">
        <div class="vts-settings-title-row">
          <svg viewBox="0 0 24 24" class="vts-settings-icon"><path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/></svg>
          <span>Hash Queue</span>
          <button class="vts-queue-refresh-btn" id="vts-queue-refresh" title="Refresh list">↻</button>
        </div>
        <div class="vts-queue-stats" id="vts-queue-stats"></div>
        <input class="vts-settings-input vts-queue-search" id="vts-queue-search" placeholder="Filter hashes...">
        <div class="vts-queue-list" id="vts-queue-list">
          <div class="vts-empty"><div class="vts-spinner"></div><p>Loading hashes...</p></div>
        </div>
        <button class="vts-settings-back" id="vts-queue-back">← Back to Data</button>
      </div>
    `;

    queueBody.querySelector('#vts-queue-back').onclick = () => showMainView();
    queueBody.querySelector('#vts-queue-refresh').onclick = () => fetchHashList();
    queueBody.querySelector('#vts-queue-search').oninput = (e) => renderHashItems(e.target.value);

    fetchHashList();
  }

  function fetchHashList() {
    chrome.storage.local.get('vt_sheets_url', (r) => {
      const url = r.vt_sheets_url;
      if (!url) {
        const listEl = document.getElementById('vts-queue-list');
        if (listEl) listEl.innerHTML = '<div class="vts-queue-empty">⚠ Set your endpoint URL in Settings first</div>';
        return;
      }

      const listEl = document.getElementById('vts-queue-list');
      if (listEl) listEl.innerHTML = '<div class="vts-empty"><div class="vts-spinner"></div><p>Fetching hashes...</p></div>';

      fetch(url + '?action=getHashes')
        .then(res => res.json())
        .then(data => {
          if (data.status === 'success' && data.hashes) {
            hashList = data.hashes;
            updateQueueStats(data);
            renderHashItems('');
          } else {
            const listEl = document.getElementById('vts-queue-list');
            if (listEl) listEl.innerHTML = '<div class="vts-queue-empty">✗ ' + (data.message || 'Failed to load hashes') + '</div>';
          }
        })
        .catch(err => {
          const listEl = document.getElementById('vts-queue-list');
          if (listEl) listEl.innerHTML = '<div class="vts-queue-empty">✗ Network error: ' + err.message + '</div>';
        });
    });
  }

  function updateQueueStats(data) {
    const statsEl = document.getElementById('vts-queue-stats');
    if (!statsEl) return;
    const total = data.total || 0;
    const crawled = data.crawled || 0;
    const pending = data.pending || 0;
    const pct = total > 0 ? Math.round(crawled / total * 100) : 0;
    statsEl.innerHTML = `
      <div class="vts-queue-progress">
        <div class="vts-queue-progress-bar" style="width:${pct}%"></div>
      </div>
      <div class="vts-queue-stat-row">
        <span class="vts-queue-stat"><span class="vts-stat-dot pending"></span> ${pending} pending</span>
        <span class="vts-queue-stat"><span class="vts-stat-dot crawled"></span> ${crawled} crawled</span>
        <span class="vts-queue-stat">${total} total</span>
      </div>
    `;
  }

  function renderHashItems(filter) {
    const listEl = document.getElementById('vts-queue-list');
    if (!listEl) return;
    const q = (filter || '').toLowerCase();
    const currentHash = getHashFromURL();
    let filtered = hashList;
    if (q) filtered = hashList.filter(h => h.hash.toLowerCase().includes(q));

    if (filtered.length === 0) {
      listEl.innerHTML = '<div class="vts-queue-empty">No hashes found</div>';
      return;
    }

    // Show pending first, then crawled
    filtered.sort((a, b) => {
      if (a.status === 'pending' && b.status !== 'pending') return -1;
      if (a.status !== 'pending' && b.status === 'pending') return 1;
      return 0;
    });

    listEl.innerHTML = filtered.map(h => {
      const isCurrent = currentHash && h.hash.toLowerCase() === currentHash.toLowerCase();
      const statusClass = isCurrent ? 'current' : h.status;
      const statusIcon = isCurrent ? '🔍' : (h.status === 'crawled' ? '✓' : '○');
      const shortHash = h.hash.substring(0, 16) + '...' + h.hash.substring(h.hash.length - 8);
      return `<div class="vts-queue-item ${statusClass}" data-hash="${esc(h.hash)}" data-row="${h.row}">
        <span class="vts-queue-item-status">${statusIcon}</span>
        <span class="vts-queue-item-hash" title="${esc(h.hash)}">${esc(shortHash)}</span>
        <button class="vts-queue-item-go" title="Search this hash">${h.status === 'crawled' ? '↻' : '→'}</button>
      </div>`;
    }).join('');

    // Wire click handlers
    listEl.querySelectorAll('.vts-queue-item-go').forEach(btn => {
      btn.onclick = (e) => {
        e.stopPropagation();
        const item = btn.closest('.vts-queue-item');
        const hash = item.dataset.hash;
        searchHash(hash);
      };
    });
    listEl.querySelectorAll('.vts-queue-item').forEach(item => {
      item.onclick = () => {
        const hash = item.dataset.hash;
        navigator.clipboard.writeText(hash).then(() => showToast('Hash copied!'));
      };
    });
  }

  function searchHash(hash) {
    // Navigate directly to VT file page
    window.location.href = 'https://www.virustotal.com/gui/file/' + hash;
    showToast('Navigating to hash...');
  }

  // ── Auto-mark crawled after scraping ──
  function markHashCrawled(hash) {
    if (!hashList.length) return;
    const match = hashList.find(h => h.hash.toLowerCase() === hash.toLowerCase() && h.status === 'pending');
    if (!match) return;

    chrome.storage.local.get('vt_sheets_url', (r) => {
      const url = r.vt_sheets_url;
      if (!url) return;

      fetch(url + '?action=markCrawled&row=' + match.row)
        .then(res => res.json())
        .then(data => {
          if (data.status === 'success') {
            match.status = 'crawled';
            showToast('✓ Hash marked as crawled in sheet');
            renderHashItems('');
          }
        })
        .catch(() => { /* silently fail */ });
    });
  }

  function renderSettings() {
    const settingsBody = document.getElementById('vts-settings-body');
    if (!settingsBody) return;

    chrome.storage.local.get(['vt_sheets_url', 'vt_auto_push'], (r) => {
      const savedUrl = r.vt_sheets_url || '';
      const hashListUrl = r.vt_sheets_url || ''; // same endpoint, different actions
      const autoPush = !!r.vt_auto_push;

      settingsBody.innerHTML = `
        <div class="vts-settings-content">
          <div class="vts-settings-title-row">
            <svg viewBox="0 0 24 24" class="vts-settings-icon"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 00-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1115.6 12 3.61 3.61 0 0112 15.6z"/></svg>
            <span>Settings</span>
          </div>

          <div class="vts-settings-section">
            <div class="vts-settings-section-header">
              <svg viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V5h14v14z"/><path d="M7 12h2v5H7zm4-3h2v8h-2zm4-3h2v11h-2z"/></svg>
              <span>Google Sheets Endpoint</span>
            </div>
            <p class="vts-settings-desc">Enter your Google Apps Script Web App URL to push scraped data to Google Sheets.</p>
            <label class="vts-settings-label">Web App URL</label>
            <input type="url" id="vts-sheets-url" class="vts-settings-input" placeholder="https://script.google.com/macros/s/..." value="${esc(savedUrl)}">
            <div class="vts-settings-hint">Must be a deployed Apps Script web app URL</div>
            <div class="vts-settings-status" id="vts-settings-status"></div>
          </div>

          <div class="vts-settings-section">
            <div class="vts-settings-section-header">
              <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
              <span>Auto-Push</span>
            </div>
            <p class="vts-settings-desc">Automatically push data to Sheets whenever a new hash is scraped.</p>
            <label class="vts-settings-toggle">
              <input type="checkbox" id="vts-auto-push" ${autoPush ? 'checked' : ''}>
              <span class="vts-toggle-slider"></span>
              <span class="vts-toggle-label">Enable auto-push</span>
            </label>
          </div>

          <div class="vts-settings-actions">
            <button class="vts-settings-btn vts-settings-save" id="vts-save-settings">✓ Save Settings</button>
            <button class="vts-settings-btn vts-settings-test" id="vts-test-endpoint">⚡ Test</button>
          </div>

          <div class="vts-settings-section">
            <div class="vts-settings-section-header">
              <svg viewBox="0 0 24 24"><path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/></svg>
              <span>Hash Queue</span>
            </div>
            <p class="vts-settings-desc">The Hash Queue uses the same endpoint URL above. Make sure your Apps Script has both RESULT_SHEET_URL and HASH_SHEET_URL configured.</p>
          </div>

          <button class="vts-settings-back" id="vts-settings-back">← Back to Data</button>
        </div>
      `;

      // Wire up save
      settingsBody.querySelector('#vts-save-settings').onclick = () => {
        const url = settingsBody.querySelector('#vts-sheets-url').value.trim();
        const auto = settingsBody.querySelector('#vts-auto-push').checked;
        const status = settingsBody.querySelector('#vts-settings-status');

        if (url && !url.startsWith('https://script.google.com/')) {
          status.textContent = '✗ Must be a Google Apps Script URL';
          status.className = 'vts-settings-status vts-status-error';
          return;
        }

        const data = { vt_auto_push: auto };
        if (url) data.vt_sheets_url = url;
        else chrome.storage.local.remove('vt_sheets_url');

        chrome.storage.local.set(data, () => {
          status.textContent = '✓ Settings saved!';
          status.className = 'vts-settings-status vts-status-success';
          showToast('✓ Settings saved!');
          setTimeout(() => { toggleSettings(); }, 800);
        });
      };

      // Wire up test
      settingsBody.querySelector('#vts-test-endpoint').onclick = () => {
        const url = settingsBody.querySelector('#vts-sheets-url').value.trim();
        const status = settingsBody.querySelector('#vts-settings-status');
        if (!url) {
          status.textContent = '⚠ Enter a URL first';
          status.className = 'vts-settings-status vts-status-error';
          return;
        }
        if (!url.startsWith('https://script.google.com/')) {
          status.textContent = '✗ Invalid URL';
          status.className = 'vts-settings-status vts-status-error';
          return;
        }
        status.textContent = '⏳ Testing...';
        status.className = 'vts-settings-status vts-status-info';
        fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: JSON.stringify({ test: true, ts: new Date().toISOString(), source: 'VT Hash Scraper' }),
          mode: 'no-cors'
        }).then(() => {
          status.textContent = '✓ Request sent! Check your Sheet.';
          status.className = 'vts-settings-status vts-status-success';
        }).catch(err => {
          status.textContent = '✗ Failed: ' + err.message;
          status.className = 'vts-settings-status vts-status-error';
        });
      };

      // Wire up back button
      settingsBody.querySelector('#vts-settings-back').onclick = toggleSettings;
    });
  }

  function renderEmpty() {
    const body = document.getElementById('vts-body');
    if (!body) return;
    body.innerHTML = `<div class="vts-empty"><div class="vts-spinner"></div><p>Waiting for VirusTotal data...</p><p style="font-size:11px;margin-top:8px;color:#475569">Navigate to a file hash page to scrape data</p></div>`;
  }

  function renderLoading() {
    const body = document.getElementById('vts-body');
    if (!body) return;
    body.innerHTML = `<div class="vts-loading"><div class="vts-spinner"></div><p>Scraping data...</p></div>`;
  }

  // ── Main Render ──
  function renderPanel() {
    const body = document.getElementById('vts-body');
    if (!body || !scrapedData?.data?.attributes) return;
    const a = scrapedData.data.attributes;
    const stats = a.last_analysis_stats || {};
    const total = Object.values(stats).reduce((s, v) => s + v, 0);
    const mal = stats.malicious || 0;
    const sus = stats.suspicious || 0;
    const harm = stats.harmless || 0;
    const undet = stats.undetected || 0;
    const tout = stats.timeout || 0;
    const pct = total > 0 ? ((mal + sus) / total) * 100 : 0;
    const circumference = 2 * Math.PI * 36;
    const offset = circumference - (pct / 100) * circumference;
    const ringColor = mal > 10 ? '#EF4444' : mal > 0 ? '#F97316' : '#10B981';

    let html = '';

    // Detection Ring
    html += `<div class="vts-detection-ring">
      <svg class="vts-ring-svg" viewBox="0 0 90 90">
        <circle class="vts-ring-bg" cx="45" cy="45" r="36"/>
        <circle class="vts-ring-fill" cx="45" cy="45" r="36" stroke="${ringColor}"
          stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
          transform="rotate(-90 45 45)"/>
        <text class="vts-ring-text" x="45" y="43" text-anchor="middle">${mal + sus}</text>
        <text class="vts-ring-label" x="45" y="55" text-anchor="middle">/ ${total}</text>
      </svg>
      <div class="vts-ring-stats">
        <div class="vts-stat-row"><span class="vts-stat-dot malicious"></span><span class="vts-stat-count">${mal}</span>Malicious</div>
        <div class="vts-stat-row"><span class="vts-stat-dot suspicious"></span><span class="vts-stat-count">${sus}</span>Suspicious</div>
        <div class="vts-stat-row"><span class="vts-stat-dot harmless"></span><span class="vts-stat-count">${harm}</span>Harmless</div>
        <div class="vts-stat-row"><span class="vts-stat-dot undetected"></span><span class="vts-stat-count">${undet}</span>Undetected</div>
        ${tout ? `<div class="vts-stat-row"><span class="vts-stat-dot timeout"></span><span class="vts-stat-count">${tout}</span>Timeout</div>` : ''}
      </div>
    </div>`;

    // Threat Labels
    if (a.popular_threat_classification) {
      const ptc = a.popular_threat_classification;
      html += `<div class="vts-section"><div class="vts-section-header" onclick="this.parentElement.classList.toggle('collapsed')">
        <svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
        <span class="vts-section-title">Threat Classification</span>
        <svg class="vts-section-chevron" viewBox="0 0 24 24"><path d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6z"/></svg>
      </div><div class="vts-section-body">`;
      if (ptc.suggested_threat_label) html += kv('Threat Label', ptc.suggested_threat_label);
      if (ptc.popular_threat_name) html += `<div style="margin-top:8px"><div class="vts-tags">${ptc.popular_threat_name.map(t => `<span class="vts-tag danger">${t.value} (${t.count})</span>`).join('')}</div></div>`;
      if (ptc.popular_threat_category) html += `<div style="margin-top:6px"><div class="vts-tags">${ptc.popular_threat_category.map(t => `<span class="vts-tag">${t.value} (${t.count})</span>`).join('')}</div></div>`;
      html += `</div></div>`;
    }

    // File Metadata
    html += section('File Metadata', '<svg viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zM6 20V4h7v5h5v11H6z"/></svg>',
      kv('SHA-256', a.sha256, true) + kv('SHA-1', a.sha1, true) + kv('MD5', a.md5, true) +
      kv('File Name', a.meaningful_name || a.names?.[0] || '—') +
      kv('File Type', a.type_description || a.magic || '—') +
      kv('File Size', formatBytes(a.size)) +
      kv('Type Tag', a.type_tag || '—') +
      (a.first_submission_date ? kv('First Seen', new Date(a.first_submission_date * 1000).toLocaleString()) : '') +
      (a.last_submission_date ? kv('Last Seen', new Date(a.last_submission_date * 1000).toLocaleString()) : '') +
      (a.last_analysis_date ? kv('Last Analysis', new Date(a.last_analysis_date * 1000).toLocaleString()) : '') +
      (a.times_submitted ? kv('Submissions', a.times_submitted) : '') +
      (a.reputation !== undefined ? kv('Reputation', a.reputation) : '')
    );

    // Tags
    if (a.tags?.length) {
      html += section('Tags', '<svg viewBox="0 0 24 24"><path d="M21.41 11.58l-9-9C12.05 2.22 11.55 2 11 2H4c-1.1 0-2 .9-2 2v7c0 .55.22 1.05.59 1.42l9 9c.36.36.86.58 1.41.58s1.05-.22 1.41-.59l7-7c.37-.36.59-.86.59-1.41s-.23-1.06-.59-1.42zM5.5 7C4.67 7 4 6.33 4 5.5S4.67 4 5.5 4 7 4.67 7 5.5 6.33 7 5.5 7z"/></svg>',
        `<div class="vts-tags">${a.tags.map(t => `<span class="vts-tag">${esc(t)}</span>`).join('')}</div>`);
    }

    // Signature Info
    if (a.signature_info) {
      const si = a.signature_info;
      html += section('Signature Info', '<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>',
        Object.entries(si).map(([k, v]) => kv(k.replace(/_/g, ' '), typeof v === 'object' ? JSON.stringify(v) : v)).join(''));
    }

    // ML Static Analysis Details (Extracted from the Details Tab)
    if (a.pe_info || a.vhash || a.ssdeep || a.tlsh || a.packers || a.trid) {
      let mlContent = '';
      if (a.pe_info?.imphash) mlContent += kv('ImpHash', a.pe_info.imphash, true);
      if (a.vhash) mlContent += kv('VHash', a.vhash, true);
      if (a.ssdeep) mlContent += kv('SSDeep', a.ssdeep, true);
      if (a.tlsh) mlContent += kv('TLSH', a.tlsh, true);
      if (a.pe_info?.machine_type) mlContent += kv('PE Machine Type', a.pe_info.machine_type);
      if (a.pe_info?.entry_point) mlContent += kv('PE Entry Point', a.pe_info.entry_point);
      if (a.pe_info?.sections) mlContent += kv('PE Sections Count', a.pe_info.sections.length);
      if (a.pe_info?.import_list) mlContent += kv('PE Imports Count', a.pe_info.import_list.length);
      if (a.pe_info?.export_list) mlContent += kv('PE Exports Count', a.pe_info.export_list.length);
      
      if (a.packers) {
        const pList = Object.entries(a.packers).map(([k,v]) => `${k}: ${v}`).join(' | ');
        if (pList) mlContent += kv('Packers', pList);
      }
      if (a.trid && a.trid.length) {
        const tList = a.trid.slice(0, 3).map(t => `${t.file_type} (${t.probability}%)`).join(' | ');
        if (tList) mlContent += kv('TrID', tList);
      }
      
      html += section('Static Analysis / Details', '<svg viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V5h14v14z"/></svg>', mlContent);
    }

    // Known Names
    if (a.names?.length) {
      html += section('Known Names', '<svg viewBox="0 0 24 24"><path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/></svg>',
        a.names.slice(0, 20).map(n => `<div style="font-size:12px;font-family:'JetBrains Mono',monospace;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.03);word-break:break-all">${esc(n)}</div>`).join('') +
        (a.names.length > 20 ? `<div style="color:#64748b;font-size:11px;margin-top:6px">...and ${a.names.length - 20} more</div>` : ''));
    }

    // Detection Details Table
    if (a.last_analysis_results) {
      const results = Object.values(a.last_analysis_results);
      html += `<div class="vts-section" id="vts-detections-section">
        <div class="vts-section-header" onclick="this.parentElement.classList.toggle('collapsed')">
          <svg viewBox="0 0 24 24"><path d="M19.35 10.04A7.49 7.49 0 0012 4C9.11 4 6.6 5.64 5.35 8.04A5.994 5.994 0 000 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>
          <span class="vts-section-title">Detection Details (${results.length} engines)</span>
          <svg class="vts-section-chevron" viewBox="0 0 24 24"><path d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6z"/></svg>
        </div>
        <div class="vts-section-body">
          <input class="vts-search" id="vts-det-search" placeholder="Search engines..." oninput="window.__vtsSearch(this.value)">
          <div class="vts-filter-bar" id="vts-filter-bar">
            <button class="vts-filter-btn active" data-f="all">All (${results.length})</button>
            <button class="vts-filter-btn" data-f="malicious">Malicious (${mal})</button>
            <button class="vts-filter-btn" data-f="suspicious">Suspicious (${sus})</button>
            <button class="vts-filter-btn" data-f="undetected">Clean (${undet + harm})</button>
          </div>
          <div id="vts-det-body"></div>
        </div>
      </div>`;
    }

    body.innerHTML = html;
    renderDetections();

    // Wire filter buttons
    document.querySelectorAll('.vts-filter-btn').forEach(btn => {
      btn.onclick = () => {
        document.querySelectorAll('.vts-filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.f;
        renderDetections();
      };
    });

    // Wire search
    window.__vtsSearch = (q) => { searchQuery = q.toLowerCase(); renderDetections(); };

    // Wire copy
    body.querySelectorAll('.vts-copyable').forEach(el => {
      el.onclick = () => {
        navigator.clipboard.writeText(el.textContent).then(() => {
          el.classList.add('vts-copied');
          setTimeout(() => el.classList.remove('vts-copied'), 2000);
        });
      };
    });
  }

  function renderDetections() {
    const el = document.getElementById('vts-det-body');
    if (!el || !scrapedData?.data?.attributes?.last_analysis_results) return;
    let results = Object.values(scrapedData.data.attributes.last_analysis_results);
    if (currentFilter !== 'all') {
      if (currentFilter === 'undetected') results = results.filter(r => r.category === 'undetected' || r.category === 'harmless');
      else results = results.filter(r => r.category === currentFilter);
    }
    if (searchQuery) results = results.filter(r => r.engine_name.toLowerCase().includes(searchQuery) || (r.result || '').toLowerCase().includes(searchQuery));
    results.sort((a, b) => { const order = { malicious: 0, suspicious: 1, undetected: 2, harmless: 3 }; return (order[a.category] ?? 4) - (order[b.category] ?? 4); });

    el.innerHTML = `<table class="vts-det-table"><thead><tr><th>Engine</th><th>Verdict</th><th>Result</th></tr></thead><tbody>${
      results.map(r => `<tr><td class="vts-det-engine">${esc(r.engine_name)}</td><td><span class="vts-det-badge ${r.category}">${r.category}</span></td><td class="vts-det-result ${r.category}">${r.result ? esc(r.result) : '—'}</td></tr>`).join('')
    }</tbody></table>`;
  }

  function exportJSON() {
    if (!scrapedData) { showToast('No data to export'); return; }
    const blob = new Blob([JSON.stringify(scrapedData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vt_${getHashFromURL() || 'data'}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('JSON exported!');
  }

  // ── Auto-push: runs in background whenever new hash data arrives ──
  function autoPushToSheets() {
    if (!scrapedData?.data?.attributes) return;
    const hash = scrapedData.data.attributes.sha256 || scrapedData.data.attributes.md5 || getHashFromURL();
    if (!hash || pushedHashes.has(hash.toLowerCase())) return; // Already pushed this session

    chrome.storage.local.get(['vt_sheets_url', 'vt_auto_push'], (r) => {
      if (!r.vt_auto_push || !r.vt_sheets_url) return;
      pushDataToSheets(r.vt_sheets_url, true);
    });
  }

  // ── Core push function, used by both auto-push and manual button ──
  function pushDataToSheets(url, silent) {
    const hash = scrapedData?.data?.attributes?.sha256 || scrapedData?.data?.attributes?.md5 || getHashFromURL() || '';
    const payload = { ...scrapedData, sourceUrl: window.location.href };

    if (!silent) {
      const sheetsBtn = document.getElementById('vts-sheets');
      if (sheetsBtn) { sheetsBtn.textContent = '⏳ Sending...'; sheetsBtn.disabled = true; }
    }

    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: JSON.stringify(payload),
      mode: 'no-cors'
    }).then(() => {
      pushedHashes.add(hash.toLowerCase());
      const shortHash = hash.substring(0, 12) + '...';
      showToast(`📊 ${shortHash} pushed to Google Sheets`);
      if (!silent) {
        const sheetsBtn = document.getElementById('vts-sheets');
        if (sheetsBtn) { sheetsBtn.textContent = '✓ Sent!'; sheetsBtn.disabled = false; }
        setTimeout(() => { if (sheetsBtn) sheetsBtn.textContent = '📊 Sheets'; }, 3000);
      }
    }).catch(err => {
      if (silent) {
        showToast('⚠ Auto-push failed: ' + err.message);
      } else {
        showToast('✗ Failed to send: ' + err.message);
        const sheetsBtn = document.getElementById('vts-sheets');
        if (sheetsBtn) { sheetsBtn.textContent = '📊 Sheets'; sheetsBtn.disabled = false; }
      }
    });
  }

  // ── Manual send (from button click) ──
  function sendToSheets() {
    if (!scrapedData) { showToast('No data to send'); return; }
    chrome.storage.local.get('vt_sheets_url', (r) => {
      const url = r.vt_sheets_url;
      if (!url) {
        showToast('⚠ Set Google Sheets URL in Settings ⚙️');
        return;
      }
      pushDataToSheets(url, false);
    });
  }

  // ── Manual add headers ──
  function forceHeaders() {
    chrome.storage.local.get('vt_sheets_url', (r) => {
      const url = r.vt_sheets_url;
      if (!url) {
        showToast('⚠ Set Google Sheets URL in Settings ⚙️');
        return;
      }
      
      const btn = document.getElementById('vts-headers');
      if (btn) { btn.textContent = '⏳ Adding...'; btn.disabled = true; }

      fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: JSON.stringify({ action: 'forceHeaders' }),
        mode: 'no-cors'
      }).then(() => {
        showToast('✓ Headers added to Sheet');
        if (btn) { btn.textContent = '✓ Added!'; btn.disabled = false; }
        setTimeout(() => { if (btn) btn.textContent = 'Add Headers'; }, 3000);
      }).catch(err => {
        showToast('✗ Failed to add headers: ' + err.message);
        if (btn) { btn.textContent = 'Add Headers'; btn.disabled = false; }
      });
    });
  }

  function showToast(msg) {
    const t = document.createElement('div');
    t.className = 'vts-toast';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2500);
  }

  // ── Helpers ──
  function section(title, icon, content) {
    return `<div class="vts-section"><div class="vts-section-header" onclick="this.parentElement.classList.toggle('collapsed')">${icon}<span class="vts-section-title">${title}</span><svg class="vts-section-chevron" viewBox="0 0 24 24"><path d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6z"/></svg></div><div class="vts-section-body">${content}</div></div>`;
  }
  function kv(key, val, copyable) {
    if (!val && val !== 0) return '';
    return `<div class="vts-kv"><span class="vts-kv-key">${esc(key)}</span><span class="vts-kv-val${copyable ? ' vts-copyable' : ''}">${esc(String(val))}</span></div>`;
  }
  function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function formatBytes(b) {
    if (!b) return '—';
    const u = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return b.toFixed(i ? 1 : 0) + ' ' + u[i];
  }

  // ── URL change detection (SPA) ──
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      scrapedData = null;
      const hash = getHashFromURL();
      if (hash) {
        chrome.storage.local.get(`vt_${hash}`, (r) => {
          const cached = r[`vt_${hash}`];
          if (cached && Date.now() - cached.ts < 3600000) {
            scrapedData = cached.data;
            updateFAB();
            if (panelOpen) renderPanel();
          }
        });
      }
      updateFAB();
      if (panelOpen) renderEmpty();
    }
  }).observe(document, { subtree: true, childList: true });

  // ── Init ──
  function init() {
    createFAB();
    const hash = getHashFromURL();
    if (hash) {
      chrome.storage.local.get(`vt_${hash}`, (r) => {
        const cached = r[`vt_${hash}`];
        if (cached && Date.now() - cached.ts < 3600000) {
          scrapedData = cached.data;
          updateFAB();
        }
      });
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
