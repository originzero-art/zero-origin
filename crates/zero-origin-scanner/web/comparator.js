// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>
//
// comparator.js // Split-Screen Telemetry Controller for scanner.originzero.art
// Security Invariant: Zero innerHTML assignments; 100% safe DOM node creation.

(function () {
  'use strict';

  const themeBtn = document.getElementById('theme-toggle');
  const form = document.getElementById('probe-form');
  const modeCrawler = document.getElementById('mode-crawler');
  const modeHuman = document.getElementById('mode-human');
  const botSelect = document.getElementById('bot-variant');
  const leftSelect = document.getElementById('left-target');
  const rightSelect = document.getElementById('right-target');
  const runBtn = document.getElementById('run-probe-btn');
  const statusEl = document.getElementById('probe-status');
  const refreshWalBtn = document.getElementById('refresh-wal-btn');
  const walSummary = document.getElementById('wal-summary');
  const walTbody = document.getElementById('wal-tbody');

  function initTheme() {
    let saved = 'dark';
    try {
      const v = localStorage.getItem('originzero_scanner_theme');
      if (v === 'light' || v === 'dark') saved = v;
    } catch (_) {}
    document.documentElement.setAttribute('data-theme', saved);
    if (themeBtn) themeBtn.setAttribute('aria-pressed', saved === 'light' ? 'true' : 'false');
  }

  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
      const next = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      themeBtn.setAttribute('aria-pressed', next === 'light' ? 'true' : 'false');
      try { localStorage.setItem('originzero_scanner_theme', next); } catch (_) {}
    });
  }

  function syncModeSelect() {
    if (!botSelect || !modeHuman) return;
    botSelect.disabled = modeHuman.checked;
  }

  if (modeCrawler) modeCrawler.addEventListener('change', syncModeSelect);
  if (modeHuman) modeHuman.addEventListener('change', syncModeSelect);

  function clearChildren(el) {
    while (el && el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function appendKv(dl, key, val) {
    if (!dl) return;
    const dt = document.createElement('dt');
    dt.textContent = key;
    const dd = document.createElement('dd');
    dd.textContent = val;
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  function formatBytes(n) {
    if (typeof n !== 'number' || n <= 0) return '0 octeți';
    if (n >= 1048576) return (n / 1048576).toFixed(2) + ' MiB (' + n.toLocaleString('ro-RO') + ' B)';
    if (n >= 1024) return (n / 1024).toFixed(1) + ' KiB (' + n.toLocaleString('ro-RO') + ' B)';
    return n + ' octeți';
  }

  function renderPane(prefix, leg) {
    const titleEl = document.getElementById(prefix + '-pane-title');
    const verdictEl = document.getElementById(prefix + '-verdict');
    const dnsDl = document.getElementById(prefix + '-dns');
    const tlsDl = document.getElementById(prefix + '-tls');
    const httpDl = document.getElementById(prefix + '-http');
    const payloadDl = document.getElementById(prefix + '-payload');
    const c2paDl = document.getElementById(prefix + '-c2pa');

    if (titleEl) titleEl.textContent = leg.target_id;
    if (verdictEl) {
      verdictEl.textContent = leg.verdict_summary_ro;
    }
    if (prefix === 'right') {
      const rightBadge = document.getElementById('right-pane-badge');
      if (rightBadge) {
        const enforced = Boolean(
          (leg.rights && leg.rights.rights_enforced) ||
          leg.http_status === 403 ||
          leg.http_status === 429
        );
        rightBadge.textContent = enforced ? 'SCUT ZERO-ORIGIN ACTIV' : 'ORIGINE EXTERNĂ (PRE-CUTOVER)';
      }
    }

    clearChildren(dnsDl);
    appendKv(dnsDl, 'Gazdă (FQDN)', leg.dns.hostname + '.');
    appendKv(dnsDl, 'IPv4 (A)', (leg.dns.ipv4_records && leg.dns.ipv4_records.length) ? leg.dns.ipv4_records.join(', ') : 'Nerezolvat / Local');
    appendKv(dnsDl, 'IPv6 (AAAA)', (leg.dns.ipv6_records && leg.dns.ipv6_records.length) ? leg.dns.ipv6_records.join(', ') : 'Niciunul / IPv4');
    appendKv(dnsDl, 'NS Autoritativ', (leg.dns.authoritative_ns || []).slice(0, 3).join(', '));
    appendKv(dnsDl, 'RTT DNS / Total', leg.dns.dns_rtt_ms.toFixed(2) + ' ms / ' + leg.total_rtt_ms.toFixed(2) + ' ms');

    clearChildren(tlsDl);
    appendKv(tlsDl, 'Protocol TLS', leg.tls.tls_version);
    appendKv(tlsDl, 'Suită Cifrare', leg.tls.cipher_suite);
    appendKv(tlsDl, 'ALPN / SNI', leg.tls.alpn + ' / ' + leg.tls.sni_sent);
    appendKv(tlsDl, 'Amprentă JA4', leg.tls.ja4_fingerprint ? leg.tls.ja4_fingerprint : 'ABSENTĂ (Fără inspecție MSG_PEEK la L7)');
    appendKv(tlsDl, 'RTT Handshake', leg.tls.handshake_rtt_ms.toFixed(2) + ' ms');

    clearChildren(httpDl);
    appendKv(httpDl, 'Status HTTP', String(leg.http_status));
    appendKv(httpDl, 'TDM-Reservation', leg.rights.tdm_reservation ? leg.rights.tdm_reservation + ' (Activ UE Art. 4)' : 'LIPSĂ (0 protecție)');
    appendKv(httpDl, 'X-Robots-Tag', leg.rights.x_robots_tag || 'LIPSĂ');
    appendKv(httpDl, 'Content-Usage', leg.rights.content_usage || 'LIPSĂ');
    appendKv(httpDl, 'RFC 8288 Link', leg.rights.rfc8288_license_link || 'LIPSĂ');

    clearChildren(payloadDl);
    appendKv(payloadDl, 'Status Pagină / Activ', leg.payload.page_http_status + ' / ' + leg.payload.asset_http_status);
    appendKv(payloadDl, 'Imagine Expusă', formatBytes(leg.payload.image_bytes_leaked));
    appendKv(payloadDl, 'HTML Transferat', formatBytes(leg.payload.page_bytes));
    appendKv(payloadDl, 'Verdict Bandă', leg.payload.bandwidth_verdict);

    clearChildren(c2paDl);
    appendKv(c2paDl, 'Stare C2PA', leg.provenance.status);
    appendKv(c2paDl, 'Algoritm Semnare', leg.provenance.algorithm || 'Niciunul');
    appendKv(c2paDl, 'Autor Atestat', leg.provenance.creator_name || 'Niciunul');
    appendKv(c2paDl, 'Digest SHA-256', leg.provenance.content_sha256 ? leg.provenance.content_sha256.slice(0, 24) + '...' : 'N/A');
    appendKv(c2paDl, 'Diagnostic', leg.provenance.detail);
  }

  function renderWalFeed(feed) {
    if (!walSummary || !walTbody) return;
    clearChildren(walTbody);

    if (!feed || !feed.available) {
      walSummary.textContent = 'Jurnalul SQLite WAL nu conține încă evenimente de blocare sau nu a fost inițializat pe disc.';
      const tr = document.createElement('tr');
      const th = document.createElement('th');
      th.scope = 'row';
      th.textContent = '-';
      const td = document.createElement('td');
      td.colSpan = 5;
      td.textContent = 'Niciun eveniment înregistrat momentan. Rulează o sondă cu profil Crawler Automat pentru a genera o respingere 403 în timp real.';
      tr.appendChild(th);
      tr.appendChild(td);
      walTbody.appendChild(tr);
      return;
    }

    walSummary.textContent =
      'Mod jurnal: ' + feed.wal_mode.toUpperCase() +
      ' | Total Blocate (403): ' + feed.total_blocked_403 +
      ' | Limitate (429): ' + feed.total_rate_limited_429 +
      ' | Smuggling Respins (400): ' + feed.total_rejected_400;

    const events = feed.recent_events || [];
    if (events.length === 0) {
      const tr = document.createElement('tr');
      const th = document.createElement('th');
      th.scope = 'row';
      th.textContent = '#0';
      const td = document.createElement('td');
      td.colSpan = 5;
      td.textContent = 'Baza WAL este activă (0 blocări înregistrate).';
      tr.appendChild(th);
      tr.appendChild(td);
      walTbody.appendChild(tr);
      return;
    }

    events.forEach(function (ev) {
      const tr = document.createElement('tr');
      const th = document.createElement('th');
      th.scope = 'row';
      th.textContent = '#' + ev.id;
      tr.appendChild(th);

      const cols = [
        ev.timestamp_utc,
        ev.action,
        ev.rule_id,
        ev.client_prefix,
        (ev.ja4_hash ? ev.ja4_hash + ' ' : '[fără-TLS] ') + ev.method + ' ' + ev.path_prefix
      ];
      cols.forEach(function (c) {
        const td = document.createElement('td');
        td.textContent = c;
        tr.appendChild(td);
      });
      walTbody.appendChild(tr);
    });
  }

  async function executeProbe() {
    if (!runBtn || !statusEl) return;
    const profileVal = (modeHuman && modeHuman.checked) ? 'human' : (botSelect ? botSelect.value : 'gptbot');
    const leftVal = leftSelect ? leftSelect.value : 'unsafe.originzero.art';
    const rightVal = rightSelect ? rightSelect.value : 'originzero.art';

    runBtn.disabled = true;
    statusEl.textContent = 'Se execută sonda simultană pe fir (' + leftVal + ' vs. ' + rightVal + ') cu profilul [' + profileVal + ']...';

    try {
      const resp = await fetch('/api/v1/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          left_target: leftVal,
          right_target: rightVal,
          profile: profileVal
        })
      });
      const data = await resp.json();
      if (!resp.ok) {
        statusEl.textContent = 'Eroare sondă (' + resp.status + '): ' + (data.message || data.error || 'Solicitare respinsă.');
        runBtn.disabled = false;
        return;
      }

      renderPane('left', data.left);
      renderPane('right', data.right);
      renderWalFeed(data.audit_feed);
      statusEl.textContent = 'Sondă finalizată la ' + data.timestamp_utc + ' pentru profilul: ' + data.profile.label_ro;
    } catch (err) {
      statusEl.textContent = 'Eroare de rețea la interogarea backend-ului local: ' + String(err);
    } finally {
      runBtn.disabled = false;
    }
  }

  async function refreshAuditOnly() {
    try {
      const resp = await fetch('/api/v1/audit-feed');
      if (resp.ok) {
        const feed = await resp.json();
        renderWalFeed(feed);
      }
    } catch (_) {}
  }

  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      executeProbe();
    });
  }

  if (refreshWalBtn) {
    refreshWalBtn.addEventListener('click', function () {
      refreshAuditOnly();
    });
  }

  initTheme();
  syncModeSelect();
  executeProbe();
})();
