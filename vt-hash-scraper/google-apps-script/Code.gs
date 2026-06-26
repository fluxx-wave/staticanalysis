/**
 * VT Hash Scraper — Google Apps Script
 * 
 * SETUP:
 * 1. Set RESULT_SHEET_URL to your results Google Sheet URL
 * 2. Set HASH_SHEET_URL to your MalwareBazaar hash list sheet URL
 * 3. Paste this code in Apps Script
 * 4. Deploy → New deployment → Web app → Execute as Me → Anyone
 * 5. Authorize all permissions
 * 6. Copy the /exec URL into extension settings
 *
 * HASH SHEET FORMAT:
 *   Column A = hash values (sha256, md5, etc.)
 *   Column B = status (auto-filled with "CRAWLED" by the extension)
 *   Column C = crawled timestamp (auto-filled)
 *   Row 1 = headers (skipped)
 */

// ⬇⬇⬇ PASTE YOUR GOOGLE SHEET URLs HERE ⬇⬇⬇
const RESULT_SHEET_URL = ''
const HASH_SHEET_URL = '';

// ─── Helper: Get or Create Spreadsheet ───
function getSpreadsheet() {
  var ss;
  var props = PropertiesService.getScriptProperties();
  
  // 1. Try to get container-bound spreadsheet
  try { ss = SpreadsheetApp.getActiveSpreadsheet(); } catch(e) {}
  
  // 2. Try configured URL
  if (!ss && RESULT_SHEET_URL && RESULT_SHEET_URL !== 'PASTE_YOUR_RESULT_SHEET_URL_HERE') {
    try { ss = SpreadsheetApp.openByUrl(RESULT_SHEET_URL); } catch(e) {}
  }
  
  // 3. Try previously auto-created spreadsheet
  if (!ss) {
    var savedUrl = props.getProperty('AUTO_SHEET_URL');
    if (savedUrl) {
      try { ss = SpreadsheetApp.openByUrl(savedUrl); } catch(e) {}
    }
  }
  
  // 4. Create new if none exists
  if (!ss) {
    ss = SpreadsheetApp.create('VT Hash Scraper Data');
    props.setProperty('AUTO_SHEET_URL', ss.getUrl());
    Logger.log('Created new spreadsheet: ' + ss.getUrl());
  }
  return ss;
}

function getResultSheet() {
  var ss = getSpreadsheet();
  // Use the very first tab of the spreadsheet, whatever it is named.
  // This prevents it from creating a new 'Results' sheet.
  var sheet = ss.getSheets()[0];

  // Explicitly ensure headers are present in Row 1
  if (sheet.getLastRow() === 0 || sheet.getRange('A1').getValue() !== 'Scrape Time (v2)') {
    if (sheet.getLastRow() > 0) {
      sheet.insertRowBefore(1); // Make room for headers if data exists
    }
    var headers = [
      'Scrape Time (v2)', 'SHA-256', 'SHA-1', 'MD5', 'File Name',
      'File Type', 'File Size', 'Malicious', 'Suspicious',
      'Harmless', 'Undetected', 'Total Engines', 'Detection %',
      'Threat Label', 'Threat Names', 'Tags', 'First Seen',
      'Last Seen', 'Last Analysis', 'Reputation', 'Submissions',
      'Signer', 'Top Detections', 'Source URL',
      'Is Malware (Label)', 'ImpHash', 'VHash', 'SSDeep', 'TLSH',
      'PE Machine Type', 'PE Entry Point', 'PE Sections Count', 
      'PE Imports Count', 'PE Exports Count', 'Packers', 'TrID',
      'PE Info (JSON)', 'ExifTool (JSON)', 'Signature Info (JSON)', 
      'Packers (JSON)', 'TrID (JSON)', 'All Attributes (JSON)'
    ];
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    var hr = sheet.getRange(1, 1, 1, headers.length);
    hr.setFontWeight('bold');
    sheet.setFrozenRows(1);
    SpreadsheetApp.flush(); // Force write to sheet so appendRow doesn't overwrite it
  }
  return sheet;
}

function getHashSheet() {
  var ss;
  if (HASH_SHEET_URL && HASH_SHEET_URL !== 'PASTE_YOUR_HASH_LIST_SHEET_URL_HERE') {
    try { ss = SpreadsheetApp.openByUrl(HASH_SHEET_URL); } catch(e) {}
  }
  if (!ss) {
    ss = getSpreadsheet();
  }
  
  var sheet = ss.getSheetByName('Hash Queue');
  if (!sheet) {
    sheet = ss.insertSheet('Hash Queue');
  }

  // Explicitly ensure headers are present in Row 1
  if (sheet.getLastRow() === 0 || sheet.getRange('A1').getValue() !== 'Hash') {
    if (sheet.getLastRow() > 0) {
      sheet.insertRowBefore(1);
    }
    var headers = ['Hash', 'Status', 'Crawled Timestamp'];
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    var hr = sheet.getRange(1, 1, 1, headers.length);
    hr.setFontWeight('bold');
    sheet.setFrozenRows(1);
    SpreadsheetApp.flush(); // Force write to sheet so appendRow doesn't overwrite it
  }
  return sheet;
}

// Helper to prevent 50,000 character limit errors in Google Sheets
function safeStringify(obj) {
  if (!obj) return '';
  try {
    var str = JSON.stringify(obj);
    if (str.length > 49000) {
      return str.substring(0, 49000) + '... [TRUNCATED DUE TO GOOGLE SHEETS LIMIT]';
    }
    return str;
  } catch (e) {
    return '';
  }
}

// ─── GET Endpoint ───
function doGet(e) {
  try {
    var action = (e && e.parameter && e.parameter.action) ? e.parameter.action : '';

    // Return uncrawled hashes
    if (action === 'getHashes') {
      var sheet = getHashSheet();
      var lastRow = sheet.getLastRow();
      if (lastRow <= 1) {
        return jsonResponse({ status: 'success', hashes: [], total: 0, message: 'No hashes in sheet' });
      }

      var dataRange = sheet.getRange(2, 1, lastRow - 1, 3); // A2:C{last} — hash, status, timestamp
      var data = dataRange.getValues();
      var hashes = [];
      var totalCrawled = 0;

      for (var i = 0; i < data.length; i++) {
        var hash = String(data[i][0]).trim();
        var status = String(data[i][1]).trim().toUpperCase();
        if (!hash || hash === 'undefined' || hash === '') continue;

        var isCrawled = (status === 'CRAWLED' || status === 'DONE');
        if (isCrawled) totalCrawled++;

        hashes.push({
          hash: hash,
          row: i + 2, // actual sheet row (1-indexed, skip header)
          status: isCrawled ? 'crawled' : 'pending'
        });
      }

      return jsonResponse({
        status: 'success',
        hashes: hashes,
        total: hashes.length,
        crawled: totalCrawled,
        pending: hashes.length - totalCrawled
      });
    }

    // Mark a hash as crawled
    if (action === 'markCrawled') {
      var row = parseInt(e.parameter.row);
      if (!row || row < 2) {
        return jsonResponse({ status: 'error', message: 'Invalid row number' });
      }
      var sheet = getHashSheet();
      sheet.getRange(row, 2).setValue('CRAWLED');
      sheet.getRange(row, 3).setValue(new Date().toISOString());

      return jsonResponse({ status: 'success', message: 'Row ' + row + ' marked as crawled' });
    }

    // Default
    return jsonResponse({ status: 'ok', message: 'VT Hash Scraper endpoint is active.' });

  } catch (err) {
    return jsonResponse({ status: 'error', message: err.toString() });
  }
}

// ─── POST Endpoint (scrape results) ───
function doPost(e) {
  try {
    var payload = JSON.parse(e.postData.contents);

    // Handle test pings
    if (payload.test === true) {
      return jsonResponse({
        status: 'success',
        message: 'Endpoint is working!'
      });
    }

    // Handle markCrawled via POST too
    if (payload.action === 'markCrawled' && payload.row) {
      var row = parseInt(payload.row);
      if (row < 2) return jsonResponse({ status: 'error', message: 'Invalid row' });
      var hSheet = getHashSheet();
      hSheet.getRange(row, 2).setValue('CRAWLED');
      hSheet.getRange(row, 3).setValue(new Date().toISOString());
      return jsonResponse({ status: 'success', message: 'Marked crawled' });
    }

    // Force add headers via UI button
    if (payload.action === 'forceHeaders') {
      getResultSheet();
      getHashSheet();
      return jsonResponse({ status: 'success', message: 'Headers forced' });
    }

    var sheet = getResultSheet();

    var attr = (payload.data && payload.data.attributes) ? payload.data.attributes : {};
    var stats = attr.last_analysis_stats || {};
    var mal = stats.malicious || 0;
    var sus = stats.suspicious || 0;
    var harm = stats.harmless || 0;
    var undet = stats.undetected || 0;
    var total = mal + sus + harm + undet + (stats.timeout || 0);
    var detRate = total > 0 ? ((mal + sus) / total * 100).toFixed(1) : '0';

    // ML Label
    var isMalware = (mal >= 3) ? 1 : 0;

    // Hashes
    var impHash = attr.pe_info ? attr.pe_info.imphash : '';
    var vhash = attr.vhash || '';
    var ssdeep = attr.ssdeep || '';
    var tlsh = attr.tlsh || '';

    // PE Features
    var peMachineType = attr.pe_info ? attr.pe_info.machine_type : '';
    var peEntryPoint = attr.pe_info ? attr.pe_info.entry_point : '';
    var peSectionsCount = attr.pe_info && attr.pe_info.sections ? attr.pe_info.sections.length : 0;
    var peImportsCount = attr.pe_info && attr.pe_info.import_list ? attr.pe_info.import_list.length : 0;
    var peExportsCount = attr.pe_info && attr.pe_info.export_list ? attr.pe_info.export_list.length : 0;

    // Packers
    var packersObj = attr.packers || {};
    var packersList = [];
    for (var pKey in packersObj) {
      packersList.push(pKey + ': ' + packersObj[pKey]);
    }
    var packers = packersList.join(' | ');

    // TrID
    var tridList = attr.trid || [];
    var tridMatches = [];
    for (var t = 0; t < tridList.length && t < 3; t++) {
      tridMatches.push(tridList[t].file_type + ' (' + tridList[t].probability + '%)');
    }
    var trid = tridMatches.join(' | ');

    // Top malicious detections
    var malEngines = [];
    var results = attr.last_analysis_results || {};
    var rKeys = Object.keys(results);
    for (var i = 0; i < rKeys.length && malEngines.length < 10; i++) {
      var r = results[rKeys[i]];
      if (r.category === 'malicious' && r.result) {
        malEngines.push(r.engine_name + ': ' + r.result);
      }
    }

    // Threat info
    var ptc = attr.popular_threat_classification || {};
    var threatLabel = ptc.suggested_threat_label || '';
    var threatNames = [];
    if (ptc.popular_threat_name) {
      for (var j = 0; j < ptc.popular_threat_name.length; j++) {
        threatNames.push(ptc.popular_threat_name[j].value);
      }
    }

    // Signature
    var sigInfo = attr.signature_info || {};
    var signer = sigInfo.signers || sigInfo.subject || '';
    if (typeof signer !== 'string') signer = JSON.stringify(signer);

    var fileName = attr.meaningful_name || '';
    if (!fileName && attr.names && attr.names.length > 0) fileName = attr.names[0];
    var tags = (attr.tags && attr.tags.length > 0) ? attr.tags.join(', ') : '';

    // Detailed JSON dumps for complete access
    var peInfoJson = safeStringify(attr.pe_info);
    var exifToolJson = safeStringify(attr.exiftool);
    var signatureJson = safeStringify(attr.signature_info);
    var packersJson = safeStringify(attr.packers);
    var tridJson = safeStringify(attr.trid);
    
    // Strip out last_analysis_results from full JSON to save space since we have stats
    var clonedAttr = JSON.parse(JSON.stringify(attr));
    delete clonedAttr.last_analysis_results;
    var allAttrJson = safeStringify(clonedAttr);

    var row = [
      new Date().toISOString(),
      attr.sha256 || '', attr.sha1 || '', attr.md5 || '',
      fileName, attr.type_description || attr.magic || '', attr.size || '',
      mal, sus, harm, undet, total, detRate + '%',
      threatLabel, threatNames.join(', '), tags,
      attr.first_submission_date ? new Date(attr.first_submission_date * 1000).toISOString() : '',
      attr.last_submission_date ? new Date(attr.last_submission_date * 1000).toISOString() : '',
      attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toISOString() : '',
      attr.reputation !== undefined ? attr.reputation : '',
      attr.times_submitted || '', signer,
      malEngines.join(' | '), payload.sourceUrl || '',
      isMalware, impHash, vhash, ssdeep, tlsh,
      peMachineType, peEntryPoint, peSectionsCount,
      peImportsCount, peExportsCount, packers, trid,
      peInfoJson, exifToolJson, signatureJson, packersJson, tridJson, allAttrJson
    ];

    sheet.appendRow(row);

    var lastRow = sheet.getLastRow();

    return jsonResponse({ status: 'success', row: lastRow, hash: attr.sha256 || attr.md5 || '' });

  } catch (err) {
    return jsonResponse({ status: 'error', message: err.toString() });
  }
}

function jsonResponse(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
