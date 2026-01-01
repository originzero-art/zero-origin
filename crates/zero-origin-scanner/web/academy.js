// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>
//
// academy.js // Interactive Simulators for scanner.originzero.art/cum-functioneaza-internetul
// Audited by QA_CCIE_REVIEWER: Unsigned 32-bit shifts (>>> 0), RFC 3021 /31 support, zero innerHTML.

(function () {
  'use strict';

  // 1. Theme Switcher
  const themeBtn = document.getElementById('theme-toggle');
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

  function clearChildren(el) {
    while (el && el.firstChild) el.removeChild(el.firstChild);
  }

  function appendKv(dl, k, v) {
    if (!dl) return;
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.textContent = v;
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  // 2. Interactive DNS Step Visualizer
  const DNS_STEPS = {
    '0': 'Vedere completă: Stub Resolver-ul cere recursivitate [RD=1] -> Resolverul Recursiv parcurge iterativ [RD=0] Zona Rădăcină (.), registrul .art. și serverele autoritative ns1..ns4.example.net. [AA=1], separând traficul web suveran (A/AAAA) de serverul dedicat SMTP 198.51.100.25 (MX).',
    '1': 'Pasul 1 [Stub -> Recursive]: Aplicația apelează getaddrinfo("originzero.art"). Sistemul de operare trimite o datagramă UDP către 1.1.1.1:53 cu Header Flags: QR=0 (Query), RD=1 (Recursion Desired), QNAME="originzero.art.", QTYPE=A/AAAA. Dacă răspunsul este deja în cache cu TTL > 0, rezoluția se încheie în < 2 ms.',
    '2': 'Pasul 2 [Recursive -> Root Zone (.)]: La cache miss, resolverul recursiv întreabă cu RD=0 una dintre cele 13 identități Root (a..m.root-servers.net., rutate global prin BGP Anycast): "Unde găsesc originzero.art.?". Rădăcina nu știe IP-ul final, dar returnează o delegare (referral) cu înregistrările NS pentru zona .art. și hash-ul DS DNSSEC al registrului .art.',
    '3': 'Pasul 3 [Recursive -> TLD (.art.)]: Resolverul întreabă serverele TLD .art. (tot cu RD=0). Registrul .art. răspunde cu secțiunea AUTHORITY conținând delegarea NS către ns1.example.net. .. ns4.example.net., plus înregistrarea DS dacă DNSSEC este activ pe domeniu.',
    '4': 'Pasul 4 [Recursive -> Authoritative (ns1.example.net.)]: Resolverul interoghează direct ns1.example.net. Serverul DNS autoritativ deține fișierul de zonă și răspunde cu Header Flags: QR=1, AA=1 (Authoritative Answer), RA=0 (fără recursivitate), RCODE=0 (NOERROR), secțiunea ANSWER: originzero.art. 300 IN A 203.0.113.10.',
    '5': 'Pasul 5 [Izolarea Serviciilor prin QTYPE]: Când un browser deschide https://originzero.art, cere tipurile A și AAAA (ajungând pe nodul web suveran). Când un server de e-mail trimite un mesaj la contact@originzero.art, cere tipul MX, primind mail.originzero.art. -> 198.51.100.25 (nod SMTP dedicat), protejat de înregistrările TXT (SPF, DKIM, DMARC). Cele două fluxuri sunt complet independente!'
  };

  const stepBtns = document.querySelectorAll('[data-dns-step]');
  const dnsDetailEl = document.getElementById('dns-step-detail');
  const svgGroups = {
    '1': ['dns-node-stub', 'dns-node-rec'],
    '2': ['dns-node-rec', 'dns-node-root'],
    '3': ['dns-node-rec', 'dns-node-tld'],
    '4': ['dns-node-rec', 'dns-node-auth'],
    '5': ['dns-node-auth', 'dns-node-targets']
  };

  function setDnsStep(stepKey) {
    stepBtns.forEach(function (b) {
      b.setAttribute('aria-pressed', b.getAttribute('data-dns-step') === stepKey ? 'true' : 'false');
    });
    if (dnsDetailEl) {
      dnsDetailEl.textContent = DNS_STEPS[stepKey] || DNS_STEPS['0'];
    }
    const allIds = ['dns-node-stub', 'dns-node-rec', 'dns-node-root', 'dns-node-tld', 'dns-node-auth', 'dns-node-targets'];
    const activeSet = svgGroups[stepKey] || allIds;
    allIds.forEach(function (id) {
      const g = document.getElementById(id);
      if (g) {
        g.classList.toggle('node-dimmed', activeSet.indexOf(id) === -1);
      }
    });
  }

  stepBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      setDnsStep(btn.getAttribute('data-dns-step') || '0');
    });
  });

  // 3. Unsigned 32-Bit IPv4 CIDR Calculator & Overlap Detector
  function parseCidr(raw) {
    const trimmed = (raw || '').trim();
    const parts = trimmed.split('/');
    if (parts.length !== 2) return null;
    if (!/^(0|[1-9]\d*)$/.test(parts[1])) return null;
    const prefix = Number(parts[1]);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;

    const octets = parts[0].split('.');
    if (octets.length !== 4) return null;

    let ipU32 = 0;
    for (let i = 0; i < 4; i++) {
      if (!/^(0|[1-9]\d*)$/.test(octets[i])) return null;
      const n = Number(octets[i]);
      if (n < 0 || n > 255) return null;
      ipU32 = ((ipU32 << 8) | n) >>> 0;
    }

    const maskU32 = prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - prefix)) >>> 0);
    const wildcardU32 = (~maskU32) >>> 0;
    const netU32 = (ipU32 & maskU32) >>> 0;
    const bcastU32 = (netU32 | wildcardU32) >>> 0;
    const totalAddresses = Math.pow(2, 32 - prefix);

    let firstUsable = netU32;
    let lastUsable = bcastU32;
    let usableCount = 1;
    let note = 'Rută gazdă unică (/32 Host Route)';

    if (prefix === 31) {
      usableCount = 2;
      note = 'Legătură punct-la-punct fără broadcast (RFC 3021)';
    } else if (prefix <= 30) {
      firstUsable = (netU32 + 1) >>> 0;
      lastUsable = (bcastU32 - 1) >>> 0;
      usableCount = totalAddresses - 2;
      note = 'Subrețea standard (exclude Network ID și Broadcast)';
    }

    return {
      ipU32: ipU32,
      prefix: prefix,
      maskU32: maskU32,
      wildcardU32: wildcardU32,
      netU32: netU32,
      bcastU32: bcastU32,
      firstUsable: firstUsable,
      lastUsable: lastUsable,
      totalAddresses: totalAddresses,
      usableCount: usableCount,
      note: note
    };
  }

  function u32ToIp(n) {
    const u = n >>> 0;
    return [
      (u >>> 24) & 0xFF,
      (u >>> 16) & 0xFF,
      (u >>> 8) & 0xFF,
      u & 0xFF
    ].join('.');
  }

  function classifyRfcScope(ipU32) {
    const u = ipU32 >>> 0;
    const o1 = (u >>> 24) & 0xFF;
    const o2 = (u >>> 16) & 0xFF;
    const o3 = (u >>> 8) & 0xFF;
    if (u === 0xFFFFFFFF) return 'Limited Broadcast (255.255.255.255/32, RFC 919)';
    if (o1 === 0) return 'Rețeaua Curentă / Sursă Nespecificată (0.0.0.0/8, RFC 1122)';
    if (o1 === 127) return 'Loopback Local (127.0.0.0/8, RFC 1122)';
    if (o1 === 10) return 'Spațiu Privat Clasa A (10.0.0.0/8, RFC 1918)';
    if (o1 === 100 && o2 >= 64 && o2 <= 127) return 'Carrier-Grade NAT Shared Space (100.64.0.0/10, RFC 6598)';
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return 'Spațiu Privat (172.16.0.0/12, RFC 1918)';
    if (o1 === 192 && o2 === 168) return 'Spațiu Privat (192.168.0.0/16, RFC 1918)';
    if (o1 === 169 && o2 === 254) return 'Link-Local APIPA / Cloud Metadata (169.254.0.0/16, RFC 3927)';
    if (o1 === 198 && (o2 === 18 || o2 === 19)) return 'Teste de Performanță Rețea (198.18.0.0/15, RFC 2544)';
    if ((o1 === 192 && o2 === 0 && o3 === 2) || (o1 === 198 && o2 === 51 && o3 === 100) || (o1 === 203 && o2 === 0 && o3 === 113)) {
      return 'Documentație și Exemple Tehnice (TEST-NET, RFC 5737)';
    }
    if (o1 >= 224 && o1 <= 239) return 'Multicast IPv4 (224.0.0.0/4, RFC 5771)';
    if (o1 >= 240) return 'Spațiu Rezervat Clasa E (240.0.0.0/4, RFC 1112)';
    return 'Unicast Global Rutabil Public';
  }

  function renderBitGrid(container, ipU32, prefix) {
    if (!container) return;
    clearChildren(container);
    for (let oct = 0; oct < 4; oct++) {
      const box = document.createElement('div');
      box.className = 'octet-box';
      const octVal = (ipU32 >>> (24 - oct * 8)) & 0xFF;
      const lbl = document.createElement('div');
      lbl.className = 'octet-label';
      lbl.textContent = 'Octet ' + (oct + 1) + ' (' + octVal + ')';
      box.appendChild(lbl);

      const bitsWrap = document.createElement('div');
      bitsWrap.className = 'octet-bits';
      for (let b = 0; b < 8; b++) {
        const globalBitIndex = oct * 8 + b;
        const bitVal = (octVal >>> (7 - b)) & 1;
        const cell = document.createElement('span');
        const isNet = globalBitIndex < prefix;
        cell.className = 'bit-cell ' + (isNet ? 'net-bit' : 'host-bit');
        cell.title = 'Bit #' + (globalBitIndex + 1) + ': ' + (isNet ? 'Prefix Rețea' : 'Spațiu Gazdă');
        cell.textContent = String(bitVal);
        bitsWrap.appendChild(cell);
      }
      box.appendChild(bitsWrap);
      container.appendChild(box);
    }
  }

  const cidrForm = document.getElementById('cidr-form');
  const cidrInputA = document.getElementById('cidr-input-a');
  const cidrInputB = document.getElementById('cidr-input-b');
  const cidrError = document.getElementById('cidr-error');
  const cidrBitGrid = document.getElementById('cidr-bit-grid');
  const cidrDlA = document.getElementById('cidr-dl-a');
  const cidrDlOverlap = document.getElementById('cidr-dl-overlap');

  function updateCidrSimulator() {
    const a = parseCidr(cidrInputA ? cidrInputA.value : '');
    const b = parseCidr(cidrInputB ? cidrInputB.value : '');

    if (!a) {
      if (cidrInputA) cidrInputA.setAttribute('aria-invalid', 'true');
      if (cidrError) cidrError.textContent = 'Format invalid pentru Subrețeaua A. Folosește notația IPv4/prefix (ex. 198.51.100.42/24, prefix între 0 și 32).';
      return;
    }
    if (cidrInputA) cidrInputA.removeAttribute('aria-invalid');

    renderBitGrid(cidrBitGrid, a.ipU32, a.prefix);
    clearChildren(cidrDlA);
    appendKv(cidrDlA, 'Adresă Rețea', u32ToIp(a.netU32) + '/' + a.prefix);
    appendKv(cidrDlA, 'Mască Zecimală', u32ToIp(a.maskU32) + ' (Wildcard: ' + u32ToIp(a.wildcardU32) + ')');
    appendKv(cidrDlA, 'Broadcast', a.prefix >= 31 ? 'N/A (' + a.note + ')' : u32ToIp(a.bcastU32));
    appendKv(cidrDlA, 'Interval Utilizabil', u32ToIp(a.firstUsable) + ' -> ' + u32ToIp(a.lastUsable));
    appendKv(cidrDlA, 'Gazde Utilizabile', a.usableCount.toLocaleString('ro-RO') + ' (din ' + a.totalAddresses.toLocaleString('ro-RO') + ' adrese)');
    appendKv(cidrDlA, 'Domeniu RFC', classifyRfcScope(a.ipU32));
    appendKv(cidrDlA, 'Anonimizare /24', u32ToIp((a.ipU32 & 0xFFFFFF00) >>> 0) + '/24 (mod zero-origin WAL)');

    clearChildren(cidrDlOverlap);
    if (!b) {
      if (cidrInputB) cidrInputB.setAttribute('aria-invalid', 'true');
      appendKv(cidrDlOverlap, 'Stare B', 'Introdu o a doua subrețea validă (ex. 198.51.100.128/25) pentru testul de suprapunere.');
      if (cidrError) {
        cidrError.textContent = 'Subrețeaua A a fost calculată, dar Subrețeaua B are un format invalid.';
      }
      return;
    }
    if (cidrInputB) cidrInputB.removeAttribute('aria-invalid');

    const minPrefix = Math.min(a.prefix, b.prefix);
    const minMask = minPrefix === 0 ? 0 : ((0xFFFFFFFF << (32 - minPrefix)) >>> 0);
    const overlaps = ((a.netU32 & minMask) >>> 0) === ((b.netU32 & minMask) >>> 0);

    appendKv(cidrDlOverlap, 'Subrețea B', u32ToIp(b.netU32) + '/' + b.prefix + ' (' + u32ToIp(b.netU32) + ' .. ' + u32ToIp(b.bcastU32) + ')');
    appendKv(cidrDlOverlap, 'Coliziune / Overlap', overlaps ? 'DA [EROARE DE ARHITECTURĂ: Subrețelele se suprapun!]' : 'NU [Izolare curată pe biți]');
    if (overlaps) {
      const winner = a.prefix === b.prefix
        ? 'Ambele au același prefix /' + a.prefix + ' (rută duplicată ambiguă în FIB!).'
        : (a.prefix > b.prefix
          ? 'Subrețeaua A (/' + a.prefix + ') este mai specifică și va captura pachetele prin Longest Prefix Match!'
          : 'Subrețeaua B (/' + b.prefix + ') este mai specifică și va captura pachetele prin Longest Prefix Match!');
      appendKv(cidrDlOverlap, 'Efect în Rutare', winner);
    } else {
      appendKv(cidrDlOverlap, 'Efect în Rutare', 'Cele două blocuri sunt disjuncte și pot coexista sigur în tabela FIB.');
    }

    if (cidrError) {
      cidrError.textContent = 'Calcul binar finalizat fără erori pentru ' + u32ToIp(a.ipU32) + '/' + a.prefix + '.';
    }
  }

  if (cidrForm) {
    cidrForm.addEventListener('submit', function (e) {
      e.preventDefault();
      updateCidrSimulator();
    });
  }
  if (cidrInputA) cidrInputA.addEventListener('input', function () { cidrInputA.removeAttribute('aria-invalid'); });
  if (cidrInputB) cidrInputB.addEventListener('input', function () { cidrInputB.removeAttribute('aria-invalid'); });

  // 4. Browser-Safe Network CLI Simulator
  const cliOutput = document.getElementById('cli-output');
  const cliForm = document.getElementById('cli-form');
  const cliInput = document.getElementById('cli-input');

  function resolveCliCommand(rawCmd) {
    const cmd = (rawCmd || '').trim().replace(/\s+/g, ' ');
    const lower = cmd.toLowerCase();

    if (lower === 'clear') return '__CLEAR__';
    if (lower === 'help') {
      return [
        'Comenzi disponibile în simulatorul determinist:',
        '  dig +trace originzero.art              -> Urmărește delegarea de la (.) la ns1..ns4.example.net.',
        '  dig A originzero.art / dig AAAA ...    -> Interoghează înregistrările IPv4 și IPv6 ale originii web',
        '  dig MX originzero.art                  -> Verifică rutarea e-mailului către nodul SMTP (198.51.100.25)',
        '  dig TXT originzero.art                 -> Inspectează politicile SPF / DMARC',
        '  dig nonexistent.originzero.art         -> Demonstrează RCODE: NXDOMAIN și SOA negative TTL',
        '  dig broken-dnssec.originzero.art [+cd] -> Diagnostic CCIE pentru SERVFAIL cauzat de DNSSEC',
        '  ip route / ip route get 203.0.113.10   -> Demonstrează Longest Prefix Match în kernelul Linux',
        '  ping originzero.art / traceroute -n    -> Verifică RTT-ul ICMP și salturile L3 BGP',
        '  curl -I https://originzero.art         -> Antete suverane TDM Art. 4 + JA4 pe fir',
        '  curl -I -A GPTBot https://originzero.art       -> 403 Forbidden (tăiat de zero-origin)',
        '  curl -I -A GPTBot https://unsafe.originzero.art -> 200 OK (țintă de control neprotejată)',
        '  clear                                  -> Curăță fereastra terminalului'
      ].join('\n');
    }

    if (lower === 'dig +trace originzero.art') {
      return [
        '; <<>> DiG 9.18-originZero-Sim <<>> +trace originzero.art',
        ';; global options: +cmd',
        '.                       518400  IN  NS  a.root-servers.net.',
        '.                       518400  IN  NS  b.root-servers.net.',
        ';; Received 525 bytes from 1.1.1.1#53(1.1.1.1) in 2 ms',
        '',
        'art.                    172800  IN  NS  a.nic.art.',
        'art.                    172800  IN  NS  b.nic.art.',
        'art.                    86400   IN  DS  49812 8 2 9F3A...B14E',
        ';; Received 612 bytes from 198.41.0.4#53(a.root-servers.net) in 9 ms',
        '',
        'originzero.art.         3600    IN  NS  ns1.example.net.',
        'originzero.art.         3600    IN  NS  ns2.example.net.',
        'originzero.art.         3600    IN  NS  ns3.example.net.',
        'originzero.art.         3600    IN  NS  ns4.example.net.',
        ';; Received 204 bytes from 192.0.2.90#53(a.nic.art) in 14 ms',
        '',
        'originzero.art.         300     IN  A   203.0.113.10',
        ';; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 1',
        ';; Received 164 bytes from 192.0.2.53#53(ns1.example.net) in 8 ms'
      ].join('\n');
    }

    if (lower === 'dig mx originzero.art' || lower === 'dig originzero.art mx') {
      return [
        '; <<>> DiG 9.18 <<>> MX originzero.art',
        ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41092',
        ';; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2',
        '',
        ';; ANSWER SECTION:',
        'originzero.art.         3600    IN  MX  10 mail.originzero.art.',
        '',
        ';; ADDITIONAL SECTION:',
        'mail.originzero.art.    3600    IN  A   198.51.100.25',
        ';; [OBSERVAȚIE] Traficul SMTP merge către nodul dedicat de mail (198.51.100.25), complet decuplat de originea web!'
      ].join('\n');
    }

    if (lower === 'dig txt _dmarc.originzero.art' || lower === 'dig _dmarc.originzero.art txt') {
      return [
        '; <<>> DiG 9.18 <<>> TXT _dmarc.originzero.art',
        ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18422',
        ';; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0',
        ';; ANSWER SECTION:',
        '_dmarc.originzero.art.  3600    IN  TXT "v=DMARC1; p=quarantine; rua=mailto:contact@originzero.art"'
      ].join('\n');
    }

    if (lower === 'dig txt originzero.art' || lower === 'dig originzero.art txt') {
      return [
        '; <<>> DiG 9.18 <<>> TXT originzero.art',
        ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18421',
        ';; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0',
        ';; ANSWER SECTION:',
        'originzero.art.         3600    IN  TXT "v=spf1 +a +mx +ip4:198.51.100.25 ~all"',
        ';; [SFAT] Pentru politica DMARC (nod distinct conform RFC 1034 §3.6), rulează: dig TXT _dmarc.originzero.art'
      ].join('\n');
    }

    if (lower === 'dig aaaa originzero.art' || lower === 'dig originzero.art aaaa') {
      return [
        '; <<>> DiG 9.18 <<>> AAAA originzero.art',
        ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29505',
        ';; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0',
        ';; ANSWER SECTION:',
        'originzero.art.         300     IN  AAAA 2001:db8:100::1'
      ].join('\n');
    }

    if (lower === 'dig a originzero.art' || lower === 'dig originzero.art') {
      return [
        '; <<>> DiG 9.18 <<>> A originzero.art',
        ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29504',
        ';; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0',
        ';; ANSWER SECTION:',
        'originzero.art.         300     IN  A    203.0.113.10',
        ';; [TTL = 300s] Valoare redusă intenționat pentru cutover rapid fără cache rezidual.'
      ].join('\n');
    }

    if (lower.indexOf('nonexistent.originzero.art') !== -1) {
      return [
        '; <<>> DiG 9.18 <<>> nonexistent.originzero.art',
        ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 50912',
        ';; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1',
        '',
        ';; AUTHORITY SECTION:',
        'originzero.art.         1800    IN  SOA ns1.example.net. hostmaster.example.net. 2026111901 10800 1800 604800 1800',
        ';; [RFC 2308] RCODE=3 (NXDOMAIN): Ultimul număr din SOA (1800s) dictează durata de negative caching!'
      ].join('\n');
    }

    if (lower.indexOf('broken-dnssec.originzero.art') !== -1) {
      if (lower.indexOf('+cd') !== -1) {
        return [
          '; <<>> DiG 9.18 <<>> broken-dnssec.originzero.art +cd',
          ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61209',
          ';; flags: qr rd ra cd; QUERY: 1, ANSWER: 1',
          '',
          ';; ANSWER SECTION:',
          'broken-dnssec.originzero.art. 300 IN A 203.0.113.10',
          ';; [DIAGNOSTIC CONFIRMAT] Cu flag-ul +cd (Checking Disabled) răspunsul este NOERROR! Cauza lui SERVFAIL este 100% o semnătură RRSIG/DS DNSSEC invalidă.'
        ].join('\n');
      }
      return [
        '; <<>> DiG 9.18 <<>> broken-dnssec.originzero.art',
        ';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 61208',
        ';; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0',
        ';; [EROARE RCODE=2 SERVFAIL] Resolverul recursiv a respins răspunsul. Încearcă acum cu flag-ul +cd!'
      ].join('\n');
    }

    if (lower === 'ip route' || lower.indexOf('ip route get') === 0) {
      return [
        'Tabela FIB locală:',
        '  default via 172.31.1.1 dev eth0 proto static metric 100',
        '  203.0.113.0/24 via 172.31.1.1 dev eth0 metric 50',
        '  203.0.113.0/25 via 10.0.0.1 dev wg0 metric 500',
        '  127.0.0.0/8 dev lo scope host',
        '',
        'Rezultat ip route get 203.0.113.10:',
        '  203.0.113.10 via 10.0.0.1 dev wg0 src 10.0.0.2 uid 1000',
        '  [LONGEST PREFIX MATCH] Ruta /25 (wg0) a învins /24 și /0 chiar dacă avea metrică mai mare (500 vs 50)!'
      ].join('\n');
    }

    if (lower.indexOf('ping') === 0) {
      return [
        'PING originzero.art (203.0.113.10) 56(84) bytes of data.',
        '64 bytes from 203.0.113.10: icmp_seq=1 ttl=57 time=18.4 ms',
        '64 bytes from 203.0.113.10: icmp_seq=2 ttl=57 time=18.2 ms',
        '--- originzero.art ping statistics ---',
        '2 packets transmitted, 2 received, 0% packet loss, rtt avg = 18.3 ms (mesajele ICMP esențiale sunt permise controlat pentru PMTUD)'
      ].join('\n');
    }

    if (lower.indexOf('traceroute') === 0) {
      return [
        'traceroute to originzero.art (203.0.113.10), 30 hops max, 60 byte packets',
        ' 1  192.168.1.1      0.81 ms  (Gateway LAN RFC 1918 + NAPT)',
        ' 2  192.0.2.1        6.40 ms  (ISP Transit Edge AS64496)',
        ' 3  198.51.100.14   14.12 ms  (Regional IXP Peering AS64497)',
        ' 4  198.51.100.1    17.95 ms  (European Core Router AS64500)',
        ' 5  203.0.113.10    18.31 ms  (Sovereign Edge Node -> :443 L4 SNI -> zero-origin)'
      ].join('\n');
    }

    if (lower.indexOf('curl -i') === 0) {
      const isBot = lower.indexOf('gptbot') !== -1 || lower.indexOf('ccbot') !== -1;
      const isUnsafe = lower.indexOf('unsafe.originzero.art') !== -1;

      if (isUnsafe) {
        return [
          'HTTP/2 200',
          'server: origin-http',
          'content-type: text/html; charset=utf-8',
          'x-origin-control-role: unshielded-baseline',
          'x-content-type-options: nosniff',
          '',
          ';; [EXPUS] unsafe.originzero.art NU are scut zero-origin: GPTBot primește 200 OK, lipsește TDM-Reservation: 1 și poate descărca 1.84 MB nesemnați C2PA!'
        ].join('\n');
      }
      if (isBot) {
        return [
          'HTTP/2 403',
          'x-zero-origin-ja4: t13d1516h2_8daaf6152771_e5627efa2ab1',
          'tdm-reservation: 1',
          'tdm-policy: https://originzero.art/license/tdm-reservation',
          'content-usage: train-ai=n, search=y',
          'link: <https://originzero.art/license/tdm-reservation>; rel="license"',
          'x-robots-tag: noai, noimageai',
          '',
          '403 Forbidden: Automated harvesting blocked by zero-origin Edge Shield (RULE-UA-BOT:gptbot).',
          ';; [BLOCAT LA L7] 0 octeți de imagine transferați + eveniment scris zero-PII în zero-origin-audit.db!'
        ].join('\n');
      }
      return [
        'HTTP/2 200',
        'x-zero-origin-ja4: t13d1516h2_8daaf6152771_b0da82dd1658',
        'x-zero-origin-sni: originzero.art',
        'tdm-reservation: 1',
        'tdm-policy: https://originzero.art/license/tdm-reservation',
        'content-usage: train-ai=n, search=y',
        'link: <https://originzero.art/license/tdm-reservation>; rel="license"',
        'x-robots-tag: noai, noimageai',
        'strict-transport-security: max-age=63072000; includeSubDomains; preload',
        '',
        ';; [ACCES UMAN SUVERAN] Vizitator legitim permis cu antete UE 2019/790 Art. 4 și active semnate C2PA Ed25519.'
      ].join('\n');
    }

    return 'Comandă nerecunoscută în simulator: "' + cmd + '". Tastează "help" pentru lista completă de instrumente (dig, ip route, ping, traceroute, curl).';
  }

  function runCli(cmdStr) {
    if (!cliOutput) return;
    const out = resolveCliCommand(cmdStr);
    if (out === '__CLEAR__') {
      cliOutput.textContent = '';
      return;
    }
    const prefix = cliOutput.textContent ? cliOutput.textContent + '\n\n' : '';
    cliOutput.textContent = prefix + 'neteng@zero-origin:~$ ' + cmdStr + '\n' + out;
    cliOutput.scrollTop = cliOutput.scrollHeight;
  }

  document.querySelectorAll('.cli-preset').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const c = btn.getAttribute('data-cmd') || 'help';
      if (cliInput) cliInput.value = c;
      runCli(c);
    });
  });

  if (cliForm) {
    cliForm.addEventListener('submit', function (e) {
      e.preventDefault();
      runCli(cliInput ? cliInput.value : 'help');
    });
  }

  // 5. Production Incident Solvers
  const INCIDENT_EXPLANATIONS = {
    '1': {
      right: 'CORECT! În fișierele de zonă standard RFC 1035 (format BIND), orice nume care nu se termină cu punct (.) este tratat ca relativ la $ORIGIN, devenind scanner.originzero.art.originzero.art. Remediere: scrie fie doar eticheta relativă "scanner", fie FQDN-ul complet cu punct final "scanner.originzero.art.".',
      wrong: 'INCORECT. Un firewall pe portul 443 nu poate produce niciodată un răspuns DNS RCODE=3 (NXDOMAIN) pe portul UDP 53.'
    },
    '2': {
      right: 'CORECT! Faptul că interogarea cu +cd (Checking Disabled) funcționează demonstrează matematic că datele DNS ajung la 1.1.1.1, dar validarea lanțului criptografic DS -> DNSKEY -> RRSIG eșuează. Remediere: actualizează sau elimină înregistrarea DS veche la registrarul domeniului .art.',
      wrong: 'INCORECT. DNS-ul este complet independent de starea procesului HTTP al originii web de pe interfața de loopback.'
    },
    '3': {
      right: 'CORECT! Resolverele recursive respectă cu strictețe numărul de secunde TTL primit anterior și nu reinteroghează serverul autoritativ până la expirarea contorului. De aceea scădem TTL-ul la 300s cu cel puțin 24h înainte de orice migrare.',
      wrong: 'INCORECT. O coliziune de porturi pe serverul nou nu ar direcționa pachetele clienților către IP-ul vechiului furnizor.'
    },
    '4': {
      right: 'CORECT! Masca /23 (255.255.254.0) pe 10.20.0.0 acoperă atât 10.20.0.x cât și 10.20.1.x. Când adaugi 10.20.1.0/24 pe wg0, kernelul aplică Longest Prefix Match (/24 > /23) și trimite tot traficul pentru 10.20.1.50 în tunelul greșit!',
      wrong: 'INCORECT. Problema este pur IPv4 și provine din suprapunerea binară a măștii /23 cu /24.'
    },
    '5': {
      right: 'CORECT! Pachetele mici SYN (60 octeți) încap în MTU 1492, dar ServerHello + lanțul de certificate TLS ating 1500 octeți cu bitul DF=1 (Don\'t Fragment). Când ICMP Tip 3 Cod 4 / ICMPv6 Packet Too Big este blocat, serverul nu află niciodată că trebuie să reducă MSS/segmentul, producând un PMTUD blackhole clasic!',
      wrong: 'INCORECT. Metadatele C2PA se află în fișierele media la Layer-7, mult după finalizarea handshake-ului TLS.'
    }
  };

  document.querySelectorAll('.incident-solve').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const id = btn.getAttribute('data-inc');
      const choice = btn.getAttribute('data-choice');
      const box = document.getElementById('inc-feedback-' + id);
      if (!box || !INCIDENT_EXPLANATIONS[id]) return;
      box.hidden = false;
      box.textContent = INCIDENT_EXPLANATIONS[id][choice];
    });
  });

  // 6. 8-Question CCIE Final Verification Quiz
  const QUIZ_QUESTIONS = [
    {
      q: '1. Câte adrese de gazdă utilizabile oferă subrețeaua IPv4 172.16.20.0/23 conform RFC 4632?',
      opts: [
        '254 gazde utilizabile',
        '510 gazde utilizabile (2^(32-23) - 2 = 512 - 2)',
        '512 gazde utilizabile',
        '1022 gazde utilizabile'
      ],
      ans: 1,
      exp: 'Pentru /23 rămân 32 - 23 = 9 biți de gazdă: 2^9 = 512 adrese totale (172.16.20.0 .. 172.16.21.255), din care scădem Network ID (172.16.20.0) și Broadcast (172.16.21.255), rezultând 510 gazde.'
    },
    {
      q: '2. De ce este interzisă configurarea unei înregistrări CNAME direct pe rădăcina (apexul) domeniului originzero.art. conform RFC 2181 §10.1?',
      opts: [
        'Deoarece CNAME funcționează doar pe IPv6',
        'Deoarece o înregistrare CNAME nu are voie să coexiste pe același nod cu alte tipuri de înregistrări obligatorii la apex precum SOA, NS și MX',
        'Deoarece protocolul DNS clasic nu suportă pachete UDP mai mari de 64 octeți',
        'Deoarece CNAME blochează automat portul 443'
      ],
      ans: 1,
      exp: 'Conform RFC 1034 și RFC 2181 §10.1, un alias CNAME redirecționează toate tipurile de interogări ale acelui nume, intrând în conflict direct cu înregistrările SOA, NS și MX de la apex.'
    },
    {
      q: '3. În tabela de rutare a kernelului există trei rute care acoperă destinația 198.51.100.77: 0.0.0.0/0 (metric 10), 198.51.100.0/24 (metric 50) și 198.51.100.64/26 (metric 900). Ce rută alege kernelul?',
      opts: [
        '0.0.0.0/0 deoarece are metrica cea mai mică (10)',
        '198.51.100.0/24 deoarece este o clasă C tradițională',
        '198.51.100.64/26 deoarece Longest Prefix Match (/26 > /24 > /0) are prioritate absolută înaintea metricii',
        'Pachetul este trimis pe toate cele trei interfețe simultan'
      ],
      ans: 2,
      exp: '198.51.100.64/26 acoperă intervalul .64 .. .127 (deci conține .77) și are cel mai lung prefix (/26). Metrica departajează doar rutele cu exact aceeași lungime de prefix!'
    },
    {
      q: '4. Ce se întâmplă cu poșta electronică (contact@originzero.art) atunci când modificăm înregistrările A și AAAA ale lui originzero.art pentru a muta site-ul web pe un nod nou?',
      opts: [
        'E-mailurile se opresc dacă nu instalăm un server Postfix pe nodul web',
        'Continuă să funcționeze neîntrerupt spre serverul dedicat SMTP (198.51.100.25), atât timp cât înregistrarea MX (mail.originzero.art.) și +ip4:198.51.100.25 din SPF rămân neschimbate',
        'Toate mesajele vechi sunt șterse de resolverul recursiv',
        'MX este suprascris automat de înregistrarea AAAA'
      ],
      ans: 1,
      exp: 'Serverele SMTP rezolvă destinația prin înregistrarea MX (nu prin A-ul rădăcinii web), iar prezența explicită a lui +ip4:198.51.100.25 în TXT SPF menține autorizarea expeditorului.'
    },
    {
      q: '5. Cum reușește un router TCP L4 SNI pe portul :443 să trimită conexiunea pentru originzero.art către zero-origin și cea pentru unsafe.originzero.art către listener-ul de control fără a distruge amprenta TLS JA4?',
      opts: [
        'Decriptează certificatul cu cheia privată și recriptează conexiunea spre backend',
        'Citește la Layer-4 extensia SNI necriptată din TLS ClientHello (RFC 6066) și adaugă antetul binar PROXY protocol v2 fără a modifica niciun octet din înregistrarea TLS',
        'Citește antetul HTTP Host după decriptarea HTTP/2',
        'Folosește un tunel FTP pe portul 21'
      ],
      ans: 1,
      exp: 'Extensia Server Name Indication (RFC 6066) se află în clar în mesajul ClientHello. Routerul TCP L4 inspectează SNI-ul fără terminare TLS, iar zero-origin extrage JA4 prin MSG_PEEK pe octeții originali.'
    },
    {
      q: '6. Care este cauza demonstrată atunci când dig @1.1.1.1 domeniu.art returnează SERVFAIL, dar dig @1.1.1.1 domeniu.art +cd returnează NOERROR și adresa IP corectă?',
      opts: [
        'Cablu submarin secționat către toate serverele rădăcină',
        'Eșec de validare criptografică DNSSEC (de exemplu înregistrare DS greșită în zona părinte sau RRSIG expirat)',
        'Lipsa unei adrese IPv4 private RFC 1918 pe laptopul clientului',
        'Depășirea limitei de 120 cereri/minut în HTTP'
      ],
      ans: 1,
      exp: 'Flag-ul CD (Checking Disabled, RFC 4035) îi cere resolverului recursiv să sară peste validarea semnăturilor DNSSEC. Dacă răspunsul devine NOERROR, transportul DNS funcționează, iar eroarea este strict în lanțul DNSSEC.'
    },
    {
      q: '7. De ce este standardizat prefixul unei subrețele locale IPv6 la /64 conform RFC 4862?',
      opts: [
        'Deoarece adresele IPv6 au doar 64 de biți în total',
        'Deoarece primii 64 de biți identifică rețeaua, iar ultimii 64 de biți sunt necesari pentru generarea Interface Identifier-ului prin SLAAC (Stateless Address Autoconfiguration)',
        'Pentru a păstra compatibilitatea cu broadcast-ul ARP din IPv4',
        'Pentru a ascunde portul TCP 443'
      ],
      ans: 1,
      exp: 'O adresă IPv6 are 128 de biți: arhitectura standard alocă 64 de biți prefixului de rutare și 64 de biți identificatorului de interfață folosit de SLAAC (RFC 4862).'
    },
    {
      q: '8. Cum previne arhitectura scanner.originzero.art vulnerabilitățile de tip Server-Side Request Forgery (SSRF)?',
      opts: [
        'Acceptă orice URL de la utilizator, dar ascunde erorile în interfața CSS',
        'Backend-ul refuză URL-uri sau IP-uri arbitrare, acceptând exclusiv un enum static de 5 identificatori predefiniți pe server, fără urmărirea redirectărilor HTTP 3xx',
        'Se bazează doar pe atributul HTML required din formular',
        'Permite accesul la 169.254.169.254 doar în zilele lucrătoare'
      ],
      ans: 1,
      exp: 'Validarea în browser este doar pentru UX. Securitatea Zero-SSRF este impusă pe server în Rust prin tipul închis AllowedTargetId și dezactivarea completă a redirectărilor.'
    }
  ];

  const quizRoot = document.getElementById('quiz-questions-root');
  const quizForm = document.getElementById('ccie-quiz-form');
  const quizBanner = document.getElementById('quiz-score-banner');

  function renderQuiz() {
    if (!quizRoot) return;
    clearChildren(quizRoot);
    QUIZ_QUESTIONS.forEach(function (item, idx) {
      const card = document.createElement('fieldset');
      card.className = 'quiz-card';
      const legend = document.createElement('legend');
      legend.className = 'quiz-legend';
      legend.textContent = item.q;
      card.appendChild(legend);

      item.opts.forEach(function (optText, optIdx) {
        const wrap = document.createElement('div');
        wrap.className = 'quiz-opt-row';

        const input = document.createElement('input');
        input.type = 'radio';
        input.name = 'q_' + idx;
        input.id = 'q_' + idx + '_' + optIdx;
        input.value = String(optIdx);
        input.className = 'quiz-opt-radio';

        const lbl = document.createElement('label');
        lbl.htmlFor = input.id;
        lbl.textContent = optText;
        lbl.className = 'quiz-opt-label';

        wrap.appendChild(input);
        wrap.appendChild(lbl);
        card.appendChild(wrap);
      });

      const fb = document.createElement('div');
      fb.id = 'quiz-fb-' + idx;
      fb.className = 'quiz-feedback';
      fb.hidden = true;
      card.appendChild(fb);
      quizRoot.appendChild(card);
    });
  }

  if (quizForm) {
    quizForm.addEventListener('submit', function (e) {
      e.preventDefault();
      let correct = 0;
      let answered = 0;

      QUIZ_QUESTIONS.forEach(function (item, idx) {
        const chosen = quizForm.querySelector('input[name="q_' + idx + '"]:checked');
        const fb = document.getElementById('quiz-fb-' + idx);
        if (!fb) return;
        fb.hidden = false;
        if (!chosen) {
          fb.textContent = '[NECOMPLETAT] Selectează o variantă pentru a vedea explicația tehnică.';
          return;
        }
        answered++;
        const val = Number(chosen.value);
        if (val === item.ans) {
          correct++;
          fb.textContent = '[CORECT] ' + item.exp;
        } else {
          fb.textContent = '[GREȘIT] Răspuns corect: "' + item.opts[item.ans] + '". Explicație: ' + item.exp;
        }
      });

      if (quizBanner) {
        quizBanner.textContent =
          'Rezultat Evaluare CCIE: ' + correct + ' / ' + QUIZ_QUESTIONS.length +
          ' răspunsuri corecte (' + answered + ' completate). ' +
          (correct === QUIZ_QUESTIONS.length
            ? 'Excelență tehnică confirmată: gândești 100% în pachete, măști pe biți și protocoale!'
            : 'Revizuiește explicațiile de la întrebările marcate pentru a consolida modelul mental 1%.');
      }
    });
  }

  initTheme();
  setDnsStep('0');
  updateCidrSimulator();
  runCli('dig +trace originzero.art');
  renderQuiz();
})();
