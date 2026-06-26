/**
 * VT Hash Scraper — Background Service Worker
 * Handles storage coordination and badge updates.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log('[VT Hash Scraper] Extension installed.');
});

// Update badge when tab navigates to VT file page
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (tab.url && tab.url.includes('virustotal.com/gui/file/')) {
    chrome.action.setBadgeBackgroundColor({ color: '#6C3AED', tabId });
    chrome.action.setBadgeText({ text: 'ON', tabId });
  } else if (tab.url && tab.url.includes('virustotal.com')) {
    chrome.action.setBadgeText({ text: '', tabId });
  }
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'VT_DATA_SCRAPED') {
    // Store the scraped data
    const hash = msg.hash;
    if (hash) {
      chrome.storage.local.set({
        [`vt_${hash}`]: { data: msg.data, ts: Date.now() }
      });
      // Update badge
      if (sender.tab?.id) {
        const mal = msg.data?.data?.attributes?.last_analysis_stats?.malicious || 0;
        chrome.action.setBadgeText({ text: String(mal), tabId: sender.tab.id });
        chrome.action.setBadgeBackgroundColor({
          color: mal > 0 ? '#EF4444' : '#10B981',
          tabId: sender.tab.id
        });
      }

      // Auto-push to Google Sheets if enabled
      chrome.storage.local.get(['vt_sheets_url', 'vt_auto_push'], (r) => {
        if (r.vt_auto_push && r.vt_sheets_url) {
          const payload = {
            ...msg.data,
            sourceUrl: sender.tab?.url || '',
            pushedAt: new Date().toISOString(),
            autoPush: true
          };
          fetch(r.vt_sheets_url, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: JSON.stringify(payload),
            mode: 'no-cors'
          }).then(() => {
            console.log('[VT Hash Scraper] Auto-pushed to Google Sheets.');
          }).catch(err => {
            console.warn('[VT Hash Scraper] Auto-push failed:', err.message);
          });
        }
      });
    }
    sendResponse({ ok: true });
  }
  return true;
});
