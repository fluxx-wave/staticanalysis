/**
 * VT Hash Scraper — Page-Level Injector
 * 
 * This script runs in the PAGE context (not content script context).
 * It monkey-patches window.fetch and XMLHttpRequest to intercept
 * VirusTotal's own internal API responses, capturing the structured
 * JSON data that VT's frontend fetches.
 * 
 * It also proactively re-fetches data if loaded on a hash detail page.
 */

(function () {
  'use strict';

  const VT_SCRAPER_ID = 'vt-hash-scraper';

  // ── Intercept fetch() ──────────────────────────────────────────────
  const originalFetch = window.fetch;
  window.fetch = async function (...args) {
    const response = await originalFetch.apply(this, args);
    try {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';

      // Capture file report responses
      if (url.includes('/api/v3/files/') || url.includes('/ui/files/')) {
        const clone = response.clone();
        clone.json().then(data => {
          window.postMessage({
            source: VT_SCRAPER_ID,
            type: 'VT_FETCH_INTERCEPTED',
            endpoint: url,
            data: data
          }, '*');
        }).catch(() => { });
      }

      // Capture search/analysis responses
      if (url.includes('/api/v3/search') || url.includes('/ui/search')) {
        const clone = response.clone();
        clone.json().then(data => {
          window.postMessage({
            source: VT_SCRAPER_ID,
            type: 'VT_SEARCH_INTERCEPTED',
            endpoint: url,
            data: data
          }, '*');
        }).catch(() => { });
      }

    } catch (e) { /* silently ignore parse errors */ }
    return response;
  };

  // ── Intercept XMLHttpRequest ───────────────────────────────────────
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this._vtUrl = url;
    return originalXHROpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function (...args) {
    this.addEventListener('load', function () {
      try {
        const url = this._vtUrl || '';
        if (url.includes('/api/v3/files/') || url.includes('/ui/files/')) {
          const data = JSON.parse(this.responseText);
          window.postMessage({
            source: VT_SCRAPER_ID,
            type: 'VT_FETCH_INTERCEPTED',
            endpoint: url,
            data: data
          }, '*');
        }
      } catch (e) { /* silently ignore */ }
    });
    return originalXHRSend.apply(this, args);
  };

  // ── Proactive Re-fetch for already-loaded pages ────────────────────
  // If the user is already on a hash page, the VT API call may have
  // already completed before our interceptor loaded. Re-fetch the data.
  function proactiveFetch() {
    const hashMatch = window.location.pathname.match(/\/gui\/file\/([a-fA-F0-9]{32,64})/);
    if (!hashMatch) return;

    const hash = hashMatch[1];
    const apiUrl = `/ui/files/${hash}`;

    // Small delay to let the content script's listener set up
    setTimeout(() => {
      originalFetch(apiUrl, {
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          'X-Tool': 'vt-ui'
        }
      })
        .then(r => r.json())
        .then(data => {
          if (data?.data?.attributes) {
            window.postMessage({
              source: VT_SCRAPER_ID,
              type: 'VT_FETCH_INTERCEPTED',
              endpoint: apiUrl,
              data: data
            }, '*');
          }
        })
        .catch(() => { /* silently fail */ });
    }, 500);
  }

  // Signal that injector is ready
  window.postMessage({
    source: VT_SCRAPER_ID,
    type: 'VT_INJECTOR_READY'
  }, '*');

  // Trigger proactive fetch
  proactiveFetch();

})();
