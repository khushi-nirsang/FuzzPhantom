/* ═══════════════════════════════════════════════════════════════════════════
   FuzzPhantom GUI — Dashboard JavaScript
   ═══════════════════════════════════════════════════════════════════════════ */

'use strict';

// ─── State ──────────────────────────────────────────────────────────────────
const state = {
  scanId:        null,
  ws:            null,
  running:       false,
  findings:      [],       // all findings received
  logEntries:    [],       // all log entries
  logFilter:     'ALL',
  sevFilter:     'ALL',
  page:          0,
  pageSize:      50,
  stats: { subdomains:0, crawled_urls:0, parameterized_urls:0,
           api_endpoints:0, js_files:0, findings:0 },
  sevCounts: { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0 },
};

// ─── Chart ──────────────────────────────────────────────────────────────────
let sevChart = null;

function initChart() {
  const ctx = document.getElementById('sev-chart').getContext('2d');
  sevChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low','Info'],
      datasets: [{
        data: [0,0,0,0,0],
        backgroundColor: [
          'rgba(255,34,68,0.85)',
          'rgba(255,106,0,0.85)',
          'rgba(255,214,0,0.85)',
          'rgba(0,212,255,0.85)',
          'rgba(100,116,139,0.85)',
        ],
        borderColor: [
          'rgba(255,34,68,1)',
          'rgba(255,106,0,1)',
          'rgba(255,214,0,1)',
          'rgba(0,212,255,1)',
          'rgba(100,116,139,1)',
        ],
        borderWidth: 2,
        hoverOffset: 6,
      }],
    },
    options: {
      cutout: '68%',
      plugins: { legend: { display: false }, tooltip: {
        backgroundColor: 'rgba(10,12,26,0.95)',
        borderColor: 'rgba(0,212,255,0.3)',
        borderWidth: 1,
        titleColor: '#e2e8f0',
        bodyColor: '#94a3b8',
        callbacks: {
          label: ctx => ` ${ctx.label}: ${ctx.parsed.toLocaleString()}`,
        },
      }},
      animation: { duration: 400 },
    },
  });
}

function updateChart() {
  if (!sevChart) return;
  const { CRITICAL=0, HIGH=0, MEDIUM=0, LOW=0, INFO=0 } = state.sevCounts;
  sevChart.data.datasets[0].data = [CRITICAL, HIGH, MEDIUM, LOW, INFO];
  sevChart.update('none');
  const total = CRITICAL+HIGH+MEDIUM+LOW+INFO;
  document.getElementById('chart-total').textContent = total.toLocaleString();
}

// ─── Stat counter animation ──────────────────────────────────────────────────
const _counterTimers = {};
function animateCounter(elId, target) {
  const el = document.getElementById(elId);
  if (!el) return;
  if (_counterTimers[elId]) cancelAnimationFrame(_counterTimers[elId]);
  const start = parseInt(el.textContent.replace(/,/g,'')) || 0;
  if (start === target) return;
  const dur = Math.min(600, Math.max(200, Math.abs(target - start) * 2));
  const t0 = performance.now();
  function tick(now) {
    const p = Math.min((now - t0) / dur, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(start + (target - start) * ease).toLocaleString();
    if (p < 1) _counterTimers[elId] = requestAnimationFrame(tick);
  }
  _counterTimers[elId] = requestAnimationFrame(tick);
}

function updateStats(stats) {
  Object.assign(state.stats, stats);
  animateCounter('stat-subdomains', stats.subdomains || 0);
  animateCounter('stat-urls',       stats.crawled_urls || 0);
  animateCounter('stat-api',        stats.api_endpoints || 0);
  animateCounter('stat-findings',   stats.findings || 0);
}

function updateSevCounters() {
  animateCounter('stat-critical', state.sevCounts.CRITICAL || 0);
  animateCounter('stat-high',     state.sevCounts.HIGH || 0);
  document.getElementById('findings-count').textContent =
    state.findings.length.toLocaleString();
}

// ─── Status UI ───────────────────────────────────────────────────────────────
function setStatus(status, label) {
  const dot   = document.getElementById('status-dot');
  const lbl   = document.getElementById('status-label');
  dot.className = `status-dot ${status}`;
  lbl.textContent = label;
}

function setStage(stageName) {
  const badge = document.getElementById('stage-badge');
  if (!stageName) { badge.style.display = 'none'; return; }
  badge.style.display = '';
  badge.textContent = stageName.replace(/_/g,' ');
}

// ─── WebSocket ───────────────────────────────────────────────────────────────
function connectWS(scanId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/${scanId}`);
  state.ws = ws;

  ws.onopen = () => console.log('[WS] connected');
  ws.onmessage = e => handleMsg(JSON.parse(e.data));
  ws.onerror   = e => appendLog({type:'log', level:'ERROR', text:'WebSocket error', ts: now(), src:'ws'});
  ws.onclose   = () => {
    if (state.running) {
      setStatus('error', 'Disconnected');
      state.running = false;
      setScanBtn(false);
    }
  };
}

function now() {
  return new Date().toTimeString().slice(0,8);
}

function handleMsg(msg) {
  switch (msg.type) {
    case 'log':
      appendLog(msg);
      break;
    case 'finding':
      addFinding(msg.finding);
      break;
    case 'stats':
      updateStats(msg.stats);
      updateChart();
      break;
    case 'stage':
      setStage(msg.stage);
      appendLog({type:'log', level:'INFO', text:`>> ${msg.text}`, ts: now(), src:'stage'});
      break;
    case 'complete':
      onScanComplete(msg);
      break;
    case 'error':
      appendLog({type:'log', level:'ERROR', text: msg.text, ts: now(), src:'error'});
      onScanEnd('error', 'Error');
      break;
    case 'stopped':
      appendLog({type:'log', level:'WARNING', text: msg.text || 'Stopped', ts: now(), src:'scan'});
      onScanEnd('stopped', 'Stopped');
      break;
    case 'ping':
      break; // keepalive, ignore
    default:
      break;
  }
}

function onScanComplete(msg) {
  appendLog({type:'log', level:'INFO', text: msg.text || 'Scan complete.', ts: now(), src:'scan'});
  if (msg.summary) updateStats(msg.summary);
  updateChart();
  updateFindingsTable();
  onScanEnd('done', 'Complete');
  setStage(null);
  loadReports();

  // Auto-switch to findings if any
  if (state.findings.length > 0) {
    setTimeout(() => switchTab('findings', document.querySelector('[data-tab="findings"]')), 800);
  }
}

function onScanEnd(statusClass, label) {
  state.running = false;
  setStatus(statusClass, label);
  setScanBtn(false);
  setStage(null);
  document.getElementById('btn-clear').style.display = '';
}

// ─── Scan control ────────────────────────────────────────────────────────────
async function handleScanButton() {
  if (state.running) {
    await stopScan();
  } else {
    await startScan();
  }
}

async function startScan() {
  const domain = document.getElementById('input-domain').value.trim();
  if (!domain) {
    document.getElementById('input-domain').focus();
    document.getElementById('input-domain').style.borderColor = 'var(--danger)';
    setTimeout(() => document.getElementById('input-domain').style.borderColor = '', 1500);
    return;
  }

  // Clear previous results
  state.findings = [];
  state.logEntries = [];
  state.sevCounts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  state.page = 0;
  document.getElementById('log-panel').innerHTML = '';
  document.getElementById('log-count').textContent = '0';
  document.getElementById('top-findings-list').innerHTML = '<div class="empty-state">Scan in progress...</div>';
  updateFindingsTable();
  [0,0,0,0,0,0].forEach((_,i) => {
    const ids = ['stat-subdomains','stat-urls','stat-api','stat-findings','stat-critical','stat-high'];
    document.getElementById(ids[i]).textContent = '0';
  });
  updateChart();

  const formats = [];
  if (document.getElementById('fmt-json').checked) formats.push('json');
  if (document.getElementById('fmt-h1').checked)   formats.push('hackerone');
  if (document.getElementById('fmt-bc').checked)   formats.push('bugcrowd');
  if (document.getElementById('fmt-ig').checked)   formats.push('intigriti');

  const config = {
    domain,
    run_subdomains:    document.getElementById('mod-subdomains').checked,
    run_crawl:         document.getElementById('mod-crawl').checked,
    run_fuzz:          document.getElementById('mod-fuzz').checked,
    run_api:           document.getElementById('mod-api').checked,
    run_smart_wordlist:document.getElementById('mod-wordlist').checked,
    output_formats:    formats.length ? formats : ['json'],
    crawl_depth:  parseInt(document.getElementById('opt-depth').value)   || 3,
    rate_limit:   parseInt(document.getElementById('opt-rate').value)    || 50,
    threads:      parseInt(document.getElementById('opt-threads').value) || 20,
    timeout:      parseInt(document.getElementById('opt-timeout').value) || 10,
    proxy:        document.getElementById('opt-proxy').value.trim(),
  };

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(config),
    });
    if (!res.ok) {
      const err = await res.json();
      alert(`Error: ${err.detail || 'Failed to start scan'}`);
      return;
    }
    const data = await res.json();
    state.scanId  = data.scan_id;
    state.running = true;

    // Update UI
    setStatus('running', 'Scanning');
    setScanBtn(true);
    const chip = document.getElementById('target-chip');
    chip.textContent = domain;
    chip.style.display = '';
    document.getElementById('btn-clear').style.display = 'none';

    switchTab('log', document.querySelector('[data-tab="log"]'));
    connectWS(data.scan_id);

  } catch (err) {
    alert(`Failed to connect to server: ${err.message}`);
  }
}

async function stopScan() {
  try {
    await fetch('/api/scan/stop', { method: 'POST' });
  } catch {}
  state.running = false;
  setScanBtn(false);
  setStatus('stopped', 'Stopped');
}

function setScanBtn(running) {
  const btn   = document.getElementById('btn-scan');
  const label = document.getElementById('btn-scan-label');
  const icon  = document.querySelector('.btn-scan-icon');
  if (running) {
    btn.classList.add('scanning');
    label.textContent = 'Stop Scan';
    icon.textContent  = '&#9632;';
    icon.innerHTML    = '&#9632;';
  } else {
    btn.classList.remove('scanning');
    label.textContent = 'Start Scan';
    icon.innerHTML    = '&#9654;';
  }
}

function clearResults() {
  state.findings = [];
  state.logEntries = [];
  state.sevCounts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  state.page = 0;
  document.getElementById('log-panel').innerHTML = '';
  document.getElementById('log-count').textContent = '0';
  document.getElementById('findings-count').textContent = '0';
  document.getElementById('top-findings-list').innerHTML = '<div class="empty-state">No findings yet. Start a scan.</div>';
  document.getElementById('target-chip').style.display = 'none';
  document.getElementById('btn-clear').style.display = 'none';
  setStatus('idle', 'Ready');
  setStage(null);
  ['stat-subdomains','stat-urls','stat-api','stat-findings','stat-critical','stat-high']
    .forEach(id => document.getElementById(id).textContent = '0');
  updateChart();
  updateFindingsTable();
}

// ─── Log panel ───────────────────────────────────────────────────────────────
function appendLog(entry) {
  state.logEntries.push(entry);
  const count = state.logEntries.length;
  document.getElementById('log-count').textContent = count.toLocaleString();

  if (state.logFilter !== 'ALL' && entry.level !== state.logFilter) return;

  const panel = document.getElementById('log-panel');
  const row = document.createElement('div');
  row.className = `log-entry level-${entry.level || 'INFO'}`;
  row.dataset.level = entry.level || 'INFO';
  row.innerHTML = `
    <span class="log-ts">${entry.ts || ''}</span>
    <span class="log-src">${(entry.src || '').slice(0,10)}</span>
    <span class="log-lvl ${entry.level || 'INFO'}">${(entry.level || 'INFO').slice(0,4)}</span>
    <span class="log-text">${escHtml(entry.text || '')}</span>
  `;
  panel.appendChild(row);

  // Auto-scroll to bottom
  panel.scrollTop = panel.scrollHeight;
}

function filterLog(level, btn) {
  state.logFilter = level;
  document.querySelectorAll('.log-filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  // Re-render log
  const panel = document.getElementById('log-panel');
  panel.innerHTML = '';
  state.logEntries.forEach(e => {
    if (level === 'ALL' || e.level === level) {
      const row = document.createElement('div');
      row.className = `log-entry level-${e.level || 'INFO'}`;
      row.innerHTML = `
        <span class="log-ts">${e.ts||''}</span>
        <span class="log-src">${(e.src||'').slice(0,10)}</span>
        <span class="log-lvl ${e.level||'INFO'}">${(e.level||'INFO').slice(0,4)}</span>
        <span class="log-text">${escHtml(e.text||'')}</span>
      `;
      panel.appendChild(row);
    }
  });
  panel.scrollTop = panel.scrollHeight;
}

function clearLog() {
  state.logEntries = [];
  document.getElementById('log-panel').innerHTML = '';
  document.getElementById('log-count').textContent = '0';
}

// ─── Findings ────────────────────────────────────────────────────────────────
function addFinding(f) {
  state.findings.push(f);
  const sev = (f.severity || 'INFO').toUpperCase();
  state.sevCounts[sev] = (state.sevCounts[sev] || 0) + 1;
  updateSevCounters();
  updateChart();

  // Add to top findings if CRITICAL or HIGH
  if (sev === 'CRITICAL' || sev === 'HIGH') addTopFinding(f);

  // Refresh table if on page 0 and filter matches
  if (state.page === 0 && (state.sevFilter === 'ALL' || state.sevFilter === sev)) {
    // Throttle table re-renders (every 20 findings)
    if (state.findings.length % 20 === 0 || state.findings.length < 20) {
      updateFindingsTable();
    }
  }
}

function addTopFinding(f) {
  const list = document.getElementById('top-findings-list');
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  if (list.children.length >= 50) return; // cap at 50 in overview

  const row = document.createElement('div');
  row.className = 'top-finding-row';
  row.innerHTML = `
    <span class="sev-badge badge-${(f.severity||'INFO').toUpperCase()}">${f.severity||'INFO'}</span>
    <div style="min-width:0">
      <div class="url-cell" title="${escHtml(f.url||'')}">${escHtml((f.url||'').slice(0,80))}</div>
      <div style="font-size:10px;color:var(--text-3);margin-top:2px">${escHtml(f.category||'')} ${f.parameter ? '· param: '+f.parameter : ''}</div>
    </div>
  `;
  list.appendChild(row);
}

function filteredFindings() {
  if (state.sevFilter === 'ALL') return state.findings;
  return state.findings.filter(f => (f.severity||'').toUpperCase() === state.sevFilter);
}

function filterFindings(sev, btn) {
  state.sevFilter = sev;
  state.page = 0;
  document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  updateFindingsTable();
}

function updateFindingsTable() {
  const tbody = document.getElementById('findings-tbody');
  const filtered = filteredFindings();
  const total = filtered.length;
  const start = state.page * state.pageSize;
  const slice = filtered.slice(start, start + state.pageSize);

  if (total === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">No findings match the current filter.</td></tr>';
    document.getElementById('pag-bar').style.display = 'none';
    document.getElementById('pag-info').textContent = '';
    return;
  }

  tbody.innerHTML = slice.map(f => {
    const sev = (f.severity || 'INFO').toUpperCase();
    return `<tr>
      <td><span class="sev-badge badge-${sev}">${sev}</span></td>
      <td class="cat-cell">${escHtml(f.category||'')}</td>
      <td class="url-cell" title="${escHtml(f.url||'')}">${escHtml((f.url||'').slice(0,90))}</td>
      <td class="param-cell">${escHtml(f.parameter||'')}</td>
      <td class="detail-cell" title="${escHtml(f.detail||'')}">${escHtml((f.detail||'').slice(0,80))}</td>
    </tr>`;
  }).join('');

  const totalPages = Math.ceil(total / state.pageSize);
  document.getElementById('pag-info').textContent = `${total.toLocaleString()} findings`;
  document.getElementById('pag-page').textContent = `Page ${state.page+1} / ${totalPages}`;
  document.getElementById('pag-bar').style.display = totalPages > 1 ? 'flex' : 'none';
  document.getElementById('pag-prev').disabled = state.page === 0;
  document.getElementById('pag-next').disabled = state.page >= totalPages - 1;
}

function prevPage() { if (state.page > 0) { state.page--; updateFindingsTable(); } }
function nextPage() {
  const total = filteredFindings().length;
  if ((state.page+1) * state.pageSize < total) { state.page++; updateFindingsTable(); }
}

// ─── Reports ─────────────────────────────────────────────────────────────────
async function loadReports() {
  try {
    const res = await fetch('/api/reports');
    const data = await res.json();
    renderReports(data.reports || []);
  } catch (e) {
    console.error('Failed to load reports', e);
  }
}

function renderReports(reports) {
  const list = document.getElementById('reports-list');
  if (!reports.length) {
    list.innerHTML = '<div class="empty-state">No reports yet. Complete a scan first.</div>';
    return;
  }
  list.innerHTML = reports.map(r => `
    <div class="report-item">
      <div class="report-info">
        <span class="report-ext ${r.ext}">${r.ext}</span>
        <div>
          <div class="report-name">${escHtml(r.name)}</div>
          <div class="report-size">${formatBytes(r.size)}</div>
        </div>
      </div>
      <a href="/api/reports/download/${encodeURIComponent(r.name)}" download="${escHtml(r.name)}"
         class="btn-download">Download</a>
    </div>
  `).join('');
}

// ─── Tabs ────────────────────────────────────────────────────────────────────
function switchTab(name, btn) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(`tab-${name}`).classList.add('active');
  if (btn) btn.classList.add('active');
  if (name === 'findings') updateFindingsTable();
  if (name === 'reports')  loadReports();
}

// ─── Advanced panel ──────────────────────────────────────────────────────────
function toggleAdvanced() {
  const panel = document.getElementById('advanced-panel');
  const arrow = document.getElementById('adv-arrow');
  const open  = panel.classList.toggle('open');
  arrow.innerHTML = open ? '&#9650;' : '&#9660;';
}

// ─── Utilities ───────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024*1024) return `${(bytes/1024).toFixed(1)} KB`;
  return `${(bytes/1024/1024).toFixed(1)} MB`;
}

// ─── Init ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initChart();
  loadReports();

  // Enter key on domain input
  document.getElementById('input-domain').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !state.running) startScan();
  });

  // Restore focus styling on domain input
  document.getElementById('input-domain').addEventListener('input', e => {
    e.target.style.borderColor = '';
  });
});
