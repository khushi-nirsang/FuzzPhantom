/* ═══════════════════════════════════════════════════════════════════════════
   FuzzPhantom — Dashboard Application Logic v2.0
   ═══════════════════════════════════════════════════════════════════════════ */

'use strict';

// ── State ────────────────────────────────────────────────────────────────────
const S = {
  ws:           null,
  scanId:       null,
  running:      false,
  subdomains:   [],
  urls:         [],
  directories:  [],   // {url, status, size, elapsed_ms, severity, detail}
  apiEndpoints: [],
  findings:     [],   // all security findings (excludes Directory Found)
  logs:         [],
  currentTab:   'overview',
  logFilter:    'ALL',
  findingsSev:  'ALL',
  dirsFilter:   'ALL',
  findingsPage: 1,
  FIND_PER_PG:  25,
  chart:        null,
  completedStages: new Set(),
  activeStage:  null,
};

const PIPE_STAGES = ['subdomains','crawl','dir_fuzz','fuzz','api','wordlist','reports'];

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initChart();
  loadReports();
  // Restore last target
  const saved = localStorage.getItem('fp_target');
  if (saved) document.getElementById('input-domain').value = saved;
});

// ── Chart ────────────────────────────────────────────────────────────────────
function initChart() {
  const ctx = document.getElementById('sev-chart').getContext('2d');
  S.chart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low','Info'],
      datasets: [{
        data: [0,0,0,0,0],
        backgroundColor: ['#ef4444','#f97316','#f59e0b','#22c55e','#06b6d4'],
        borderColor: '#0c1325', borderWidth: 3, hoverBorderWidth: 3,
      }],
    },
    options: {
      cutout: '72%', responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: {
        callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed}` }
      }},
      animation: { duration: 400 },
    },
  });
}

function updateChart() {
  const sev = countBySeverity(S.findings);
  S.chart.data.datasets[0].data = [
    sev.CRITICAL, sev.HIGH, sev.MEDIUM, sev.LOW, sev.INFO,
  ];
  S.chart.update('active');
  animateNum('chart-total', S.findings.length);
}

// ── Module Toggles ────────────────────────────────────────────────────────────
function onModuleToggle(mod, el) {
  const card = document.getElementById('card-' + mod);
  card.classList.toggle('mod-active', el.checked);
}

function toggleModuleExpand(mod) { /* future: show sub-options */ }

function selectAllModules() {
  ['subdomains','crawl','dir_fuzz','fuzz','api','wordlist'].forEach(m => {
    const cb = document.getElementById('mod-' + m);
    if (cb) { cb.checked = true; onModuleToggle(m, cb); }
  });
}
function clearAllModules() {
  ['subdomains','crawl','dir_fuzz','fuzz','api','wordlist'].forEach(m => {
    const cb = document.getElementById('mod-' + m);
    if (cb) { cb.checked = false; onModuleToggle(m, cb); }
  });
}

// ── Multi-Target ──────────────────────────────────────────────────────────────
function toggleMultiTarget() {
  const panel = document.getElementById('multi-target-panel');
  const btn   = document.getElementById('btn-multi-toggle');
  const open  = panel.style.display !== 'none';
  panel.style.display = open ? 'none' : 'block';
  btn.textContent = open ? '＋ Add multiple targets' : '－ Hide extra targets';
  btn.style.borderColor = open ? 'var(--border)' : 'var(--accent)';
  btn.style.color = open ? 'var(--text-muted)' : 'var(--accent)';
}

// ── Advanced Panel ────────────────────────────────────────────────────────────
function toggleAdvanced() {
  const body  = document.getElementById('adv-body');
  const arrow = document.getElementById('adv-arrow');
  const open  = !body.classList.contains('hidden');
  body.classList.toggle('hidden', open);
  arrow.classList.toggle('open', !open);
}

// ── Format Toggles ────────────────────────────────────────────────────────────
function toggleFmt(id) {
  const cb  = document.getElementById('fmt-' + id);
  const lbl = document.getElementById('fmt-' + id + '-lbl');
  cb.checked = !cb.checked;
  lbl.classList.toggle('checked', cb.checked);
}

function toggleOptionCheckbox(id) {
  const cb = document.getElementById(id);
  const lbl = document.getElementById(id + '-lbl');
  cb.checked = !cb.checked;
  lbl.classList.toggle('checked', cb.checked);
}

// ── Tab Switching ─────────────────────────────────────────────────────────────
function switchTab(name, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
  S.currentTab = name;
  if (name === 'reports') loadReports();
  if (name === 'subdomains') renderSimpleList('subdomains');
  if (name === 'urls') renderSimpleList('urls');
  if (name === 'api') renderSimpleList('api');
  if (name === 'dirs') renderDirs();
  if (name === 'findings') renderFindings();
}

// ── Scan Control ──────────────────────────────────────────────────────────────
async function handleScan() {
  if (S.running) { await stopScan(); return; }
  await startScan();
}

async function startScan() {
  const domain = document.getElementById('input-domain').value.trim();
  if (!domain) { showToast('Enter a target URL or domain first.', 'warning'); return; }

  localStorage.setItem('fp_target', domain);

  const formats = [];
  if (document.getElementById('fmt-json').checked) formats.push('json');
  if (document.getElementById('fmt-jsonl').checked) formats.push('jsonl');
  if (document.getElementById('fmt-csv').checked) formats.push('csv');
  if (document.getElementById('fmt-pdf').checked) formats.push('pdf');
  if (document.getElementById('fmt-h1').checked)   formats.push('hackerone');
  if (document.getElementById('fmt-bc').checked)   formats.push('bugcrowd');
  if (document.getElementById('fmt-ig').checked)   formats.push('intigriti');

  // Collect extra targets from multi-target textarea
  const extraTargets = (document.getElementById('input-targets')?.value || '')
    .split('\n')
    .map(t => t.trim())
    .filter(t => t && t !== domain);

  const cfg = {
    domain,
    targets: extraTargets,
    run_subdomains:    document.getElementById('mod-subdomains').checked,
    run_crawl:         document.getElementById('mod-crawl').checked,
    run_dir_fuzz:      document.getElementById('mod-dir_fuzz').checked,
    run_fuzz:          document.getElementById('mod-fuzz').checked,
    run_api:           document.getElementById('mod-api').checked,
    run_smart_wordlist:document.getElementById('mod-wordlist').checked,
    output_formats:    formats.length ? formats : ['json'],
    crawl_depth:  parseInt(document.getElementById('opt-depth').value)   || 3,
    dir_depth:    parseInt(document.getElementById('opt-dir-depth').value) || 1,
    dir_wordlist: document.getElementById('opt-dir-wordlist').value.trim(),
    dir_extensions: (document.getElementById('opt-dir-exts').value || '')
      .split(',')
      .map(x => x.trim())
      .filter(Boolean),
    rate_limit:   parseInt(document.getElementById('opt-rate').value)    || 50,
    threads:      parseInt(document.getElementById('opt-threads').value) || 20,
    timeout:      parseInt(document.getElementById('opt-timeout').value) || 10,
    delay_ms:     parseInt(document.getElementById('opt-delay').value)   || 0,
    jitter_ms:    parseInt(document.getElementById('opt-jitter').value)  || 0,
    max_hits:     parseInt(document.getElementById('opt-max-hits').value) || 0,
    proxy:        document.getElementById('opt-proxy').value.trim(),
    replay_proxy: document.getElementById('opt-replay-proxy').value.trim(),
    follow_redirects: document.getElementById('opt-follow').checked,
    mutate_wordlist: document.getElementById('opt-mutate').checked,
    mutate_depth: document.getElementById('opt-mutate').checked ? 2 : 1,
    resume: document.getElementById('opt-resume').checked,
    calibration_profile: document.getElementById('opt-calibration-profile').value,
    recursion_status: document.getElementById('opt-rec-status').value.trim(),
    match_status: document.getElementById('opt-match-status').value.trim(),
  };

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(cfg),
    });
    if (!res.ok) {
      const err = await res.json();
      showToast(err.detail || 'Failed to start scan', 'error'); return;
    }
    const data = await res.json();
    S.scanId = data.scan_id;
    onScanStarted(domain);
    connectWS(data.scan_id);
  } catch(e) {
    showToast('Cannot connect to server: ' + e.message, 'error');
  }
}

async function stopScan() {
  try {
    await fetch('/api/scan/stop', { method: 'POST' });
  } catch(_) {}
  onScanStopped();
}

function onScanStarted(domain) {
  S.running = true;
  S.subdomains = []; S.urls = []; S.directories = [];
  S.apiEndpoints = []; S.findings = []; S.logs = [];
  S.completedStages.clear(); S.activeStage = null;

  // Reset all tabs
  resetAllData();

  // UI
  const btn = document.getElementById('btn-scan');
  btn.classList.add('running');
  document.getElementById('btn-scan-label').textContent = '■  Stop Scan';
  document.getElementById('scan-pulse').style.display = 'inline-block';

  const tp = document.getElementById('topbar-target');
  tp.classList.remove('idle');
  document.getElementById('topbar-target-text').textContent = domain;
  document.getElementById('topbar-stage').style.display = 'flex';
  document.getElementById('btn-clear').style.display = 'none';

  resetPipeline();
}

function onScanStopped() {
  S.running = false;
  const btn = document.getElementById('btn-scan');
  btn.classList.remove('running');
  document.getElementById('btn-scan-label').innerHTML = '▶ &nbsp;Start Scan';
  document.getElementById('scan-pulse').style.display = 'none';
  document.getElementById('topbar-stage').style.display = 'none';
  document.getElementById('btn-clear').style.display = 'inline-block';
  if (S.activeStage) markStage(S.activeStage, 'done');
  loadReports();
  showToast('Scan completed!', 'success');
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
function connectWS(scanId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${proto}://${location.host}/ws/${scanId}`;
  S.ws = new WebSocket(url);

  S.ws.onmessage = e => {
    try { handleMsg(JSON.parse(e.data)); }
    catch(_) {}
  };
  S.ws.onclose = () => { if (S.running) onScanStopped(); };
  S.ws.onerror = () => { showToast('WebSocket error', 'error'); };
}

function handleMsg(msg) {
  switch(msg.type) {
    case 'log':          handleLog(msg);          break;
    case 'stats':        handleStats(msg.stats);  break;
    case 'finding':      handleFinding(msg.finding); break;
    case 'subdomain':    handleSubdomain(msg.value); break;
    case 'urls_batch':   (msg.values||[]).forEach(u => handleUrl(u)); break;
    case 'api_endpoint': handleApiEndpoint(msg.value); break;
    case 'stage':        handleStage(msg);        break;
    case 'complete':     handleComplete(msg);     break;
    case 'error':        handleError(msg.text);   break;
    case 'stopped':      onScanStopped();         break;
    case 'ping':         break;
  }
}

// ── Message Handlers ──────────────────────────────────────────────────────────

function handleLog(msg) {
  S.logs.push(msg);
  if (!document.getElementById('log-empty').parentNode) return;
  document.getElementById('log-empty').style.display = 'none';

  const panel = document.getElementById('log-panel');
  if (S.logFilter !== 'ALL' && msg.level !== S.logFilter) return;

  const line = document.createElement('div');
  line.className = 'log-line';
  line.dataset.level = msg.level;
  line.innerHTML = `
    <span class="log-ts">${esc(msg.ts||'')}</span>
    <span class="log-src">${esc(msg.src||'')}</span>
    <span class="log-lvl log-lvl-${(msg.level||'info').toLowerCase()}">${esc(msg.level||'INFO')}</span>
    <span class="log-msg" title="${esc(msg.text||'')}">${esc(msg.text||'')}</span>
  `;
  panel.appendChild(line);

  // Auto-scroll if near bottom
  if (panel.scrollHeight - panel.scrollTop - panel.clientHeight < 120) {
    panel.scrollTop = panel.scrollHeight;
  }

  animateBadge('badge-log', S.logs.length);
}

function handleStats(stats) {
  if (!stats) return;
  animateNum('stat-subdomains', stats.subdomains         || 0);
  animateNum('stat-urls',       stats.crawled_urls       || 0);
  animateNum('stat-params',     stats.parameterized_urls || 0);
  animateNum('stat-api',        stats.api_endpoints      || 0);

  const totalF = stats.findings || 0;
  // Security findings = all findings minus directory findings
  const dirCount = S.directories.length;
  animateNum('stat-findings', Math.max(0, totalF - dirCount));

  const sev = countBySeverity(S.findings);
  animateNum('stat-critical', sev.CRITICAL || 0);
  animateNum('stat-high',     sev.HIGH     || 0);
  animateNum('stat-dirs',     dirCount);
}

function handleSubdomain(value) {
  if (!value || S.subdomains.includes(value)) return;
  S.subdomains.push(value);
  animateNum('stat-subdomains', S.subdomains.length);
  animateBadge('badge-sub', S.subdomains.length);

  if (S.currentTab === 'subdomains') {
    appendDataItem('list-subdomains', value, 'SUB', 'var(--purple)');
  }
  document.getElementById('sub-count').textContent = S.subdomains.length + ' subdomains';
}

function handleUrl(value) {
  if (!value || S.urls.includes(value)) return;
  S.urls.push(value);
  animateBadge('badge-urls', S.urls.length);

  if (S.currentTab === 'urls') {
    appendDataItem('list-urls', value, 'URL', 'var(--cyan)');
  }
  document.getElementById('urls-count').textContent = S.urls.length + ' URLs';
}

function handleApiEndpoint(value) {
  if (!value || S.apiEndpoints.includes(value)) return;
  S.apiEndpoints.push(value);
  animateBadge('badge-api', S.apiEndpoints.length);

  if (S.currentTab === 'api') {
    appendDataItem('list-api', value, 'API', 'var(--green)');
  }
  document.getElementById('api-count').textContent = S.apiEndpoints.length + ' endpoints';
}

function handleFinding(f) {
  if (!f) return;

  if (f.category === 'Directory Found') {
    // Route to directories tab
    const extra = f.extra || {};
    const dir = {
      url:        f.url,
      status:     f.status_code || extra.status || 0,
      size:       f.response_length || 0,
      elapsed_ms: extra.elapsed_ms || 0,
      severity:   f.severity,
      detail:     f.detail || '',
      word:       extra.word || '',
    };
    S.directories.push(dir);
    animateNum('stat-dirs', S.directories.length);
    animateBadge('badge-dirs', S.directories.length);
    document.getElementById('dirs-count').textContent = S.directories.length + ' paths';

    if (S.currentTab === 'dirs') {
      appendDirRow(dir);
    }
  } else {
    // Security finding
    S.findings.push(f);
    updateChart();
    animateBadge('badge-findings', S.findings.length);
    document.getElementById('findings-count-lbl').textContent = S.findings.length + ' findings';

    const sev = countBySeverity(S.findings);
    animateNum('stat-critical', sev.CRITICAL || 0);
    animateNum('stat-high',     sev.HIGH     || 0);
    animateNum('stat-findings', S.findings.length);

    if (S.currentTab === 'findings') {
      renderFindings();
    }
    if (f.severity === 'CRITICAL' || f.severity === 'HIGH') {
      appendTopFinding(f);
    }
  }
}

function handleStage(msg) {
  const name = msg.stage;
  if (S.activeStage && S.activeStage !== name) {
    markStage(S.activeStage, 'done');
    S.completedStages.add(S.activeStage);
  }
  if (msg.text === 'Skipped') {
    markStage(name, 'skipped');
    S.completedStages.add(name);
  } else {
    markStage(name, 'active');
    S.activeStage = name;
    document.getElementById('stage-pill').textContent = name.replace('_',' ').toUpperCase();
  }
}

function handleComplete(msg) {
  onScanStopped();
  // Mark all remaining stages done
  if (S.activeStage) markStage(S.activeStage, 'done');
  markStage('reports', 'done');
  if (msg.reports && msg.reports.length) {
    showToast(`✓ ${msg.reports.length} report(s) generated. Go to Reports tab.`, 'success');
    loadReports();
    // Switch to reports tab briefly
    const reportsBtn = document.querySelector('[data-tab="reports"]');
    if (reportsBtn) switchTab('reports', reportsBtn);
  }
}

function handleError(text) {
  showToast('Error: ' + text, 'error');
  onScanStopped();
}

// ── Pipeline ──────────────────────────────────────────────────────────────────
function resetPipeline() {
  PIPE_STAGES.forEach(s => markStage(s, ''));
}
function markStage(name, cls) {
  const el = document.getElementById('pipe-' + name);
  if (!el) return;
  el.className = 'pipe-node';
  if (cls) el.classList.add(cls);
}

// ── Rendering ─────────────────────────────────────────────────────────────────

function appendDataItem(listId, url, badge, color) {
  const list = document.getElementById(listId);
  // Remove empty state
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  const div = document.createElement('div');
  div.className = 'data-item';
  div.innerHTML = `
    <span class="data-item-badge" style="background:${color}22;color:${color};border:1px solid ${color}44">${badge}</span>
    <span class="data-item-url" title="${esc(url)}">${esc(url)}</span>
    <a href="${esc(url)}" target="_blank" style="color:var(--text-muted);font-size:10px;flex-shrink:0" title="Open">↗</a>
  `;
  list.appendChild(div);
}

function renderSimpleList(type) {
  const map = {
    subdomains: {
      listId: 'list-subdomains',
      values: S.subdomains,
      badge: 'SUB',
      color: 'var(--purple)',
      empty: 'No subdomains found yet.',
      countId: 'sub-count',
      suffix: ' subdomains',
    },
    urls: {
      listId: 'list-urls',
      values: S.urls,
      badge: 'URL',
      color: 'var(--cyan)',
      empty: 'No URLs crawled yet.',
      countId: 'urls-count',
      suffix: ' URLs',
    },
    api: {
      listId: 'list-api',
      values: S.apiEndpoints,
      badge: 'API',
      color: 'var(--green)',
      empty: 'No API endpoints found yet.',
      countId: 'api-count',
      suffix: ' endpoints',
    },
  };
  const cfg = map[type];
  if (!cfg) return;
  const list = document.getElementById(cfg.listId);
  list.innerHTML = '';
  if (!cfg.values.length) {
    list.innerHTML = `<div class="empty-state"><div class="empty-icon">⌁</div><div>${cfg.empty}</div></div>`;
  } else {
    cfg.values.forEach(value => appendDataItem(cfg.listId, value, cfg.badge, cfg.color));
  }
  document.getElementById(cfg.countId).textContent = cfg.values.length + cfg.suffix;
}

function appendDirRow(dir) {
  const tbody = document.getElementById('dirs-tbody');
  const empty = tbody.querySelector('.empty-state');
  if (empty) empty.closest('tr').remove();

  const statusCls = 's' + dir.status;
  const tr = document.createElement('tr');
  tr.dataset.status = dir.status;
  tr.innerHTML = `
    <td><span class="status-chip ${statusCls}">${dir.status}</span></td>
    <td style="color:var(--text-dim)">${fmtSize(dir.size)}</td>
    <td style="color:var(--text-muted);font-family:var(--font-mono)">${dir.elapsed_ms}ms</td>
    <td class="td-url" title="${esc(dir.url)}">
      <a href="${esc(dir.url)}" target="_blank" style="color:var(--text-dim)">${esc(dir.url)}</a>
    </td>
    <td style="color:var(--text-muted);font-size:10px">${esc(dir.detail)}</td>
  `;
  tbody.appendChild(tr);
  applyDirFilter(tr);
}

function applyDirFilter(tr) {
  const s = parseInt(tr.dataset.status);
  const show = S.dirsFilter === 'ALL'
    || (S.dirsFilter === '200' && s >= 200 && s < 300)
    || (S.dirsFilter === '403' && s === 403)
    || (S.dirsFilter === '401' && s === 401)
    || (S.dirsFilter === '301' && s >= 300 && s < 400)
    || (S.dirsFilter === '500' && s >= 500);
  tr.style.display = show ? '' : 'none';
}

function renderDirs() {
  const tbody = document.getElementById('dirs-tbody');
  tbody.innerHTML = '';
  if (!S.directories.length) {
    tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">📂</div><div>No directories found yet.</div></div></td></tr>`;
    return;
  }
  S.directories.forEach(d => appendDirRow(d));
}

function appendTopFinding(f) {
  const list = document.getElementById('top-findings-list');
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  if (list.children.length >= 8) return; // cap at 8

  const div = document.createElement('div');
  div.className = 'finding-preview';
  div.innerHTML = `
    <span class="sev-badge sev-${f.severity.toLowerCase()}">${f.severity}</span>
    <div style="min-width:0">
      <div class="finding-preview-cat">${esc(f.category)}</div>
      <div class="finding-preview-url" title="${esc(f.url)}">${esc(f.url)}</div>
    </div>
  `;
  list.appendChild(div);
}

function renderFindings() {
  const tbody = document.getElementById('findings-tbody');
  const all = S.findings.filter(f =>
    S.findingsSev === 'ALL' || f.severity === S.findingsSev
  );
  const total = all.length;
  const pages = Math.ceil(total / S.FIND_PER_PG);
  S.findingsPage = Math.min(S.findingsPage, pages || 1);
  const slice = all.slice((S.findingsPage-1)*S.FIND_PER_PG, S.findingsPage*S.FIND_PER_PG);

  tbody.innerHTML = '';
  if (!slice.length) {
    tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">🚨</div><div>No findings match the current filter.</div></div></td></tr>`;
    document.getElementById('pag-bar').style.display = 'none';
    return;
  }

  slice.forEach(f => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="sev-badge sev-${f.severity.toLowerCase()}">${f.severity}</span></td>
      <td class="td-cat">${esc(f.category)}</td>
      <td class="td-url" title="${esc(f.url)}">${esc(f.url)}</td>
      <td class="td-param">${esc(f.parameter||'–')}</td>
      <td class="td-detail" title="${esc(f.detail||'')}">${esc(f.detail||'–')}</td>
    `;
    tbody.appendChild(tr);
  });

  const pag = document.getElementById('pag-bar');
  if (pages > 1) {
    pag.style.display = 'flex';
    document.getElementById('pag-info').textContent = `Page ${S.findingsPage} / ${pages}  (${total} total)`;
    document.getElementById('pag-prev').disabled = S.findingsPage <= 1;
    document.getElementById('pag-next').disabled = S.findingsPage >= pages;
  } else {
    pag.style.display = 'none';
  }
}

// ── Filters ───────────────────────────────────────────────────────────────────

function filterLog(level, btn) {
  S.logFilter = level;
  document.querySelectorAll('.log-filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  const panel = document.getElementById('log-panel');
  panel.querySelectorAll('.log-line').forEach(line => {
    line.style.display = (level === 'ALL' || line.dataset.level === level) ? '' : 'none';
  });
}

function filterFindings(sev, btn) {
  S.findingsSev = sev;
  S.findingsPage = 1;
  document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderFindings();
}

function filterDirs(status, btn) {
  S.dirsFilter = status;
  document.querySelectorAll('.dir-filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#dirs-tbody tr').forEach(tr => applyDirFilter(tr));
}

function filterData(type, q) {
  const listId = { subdomains: 'list-subdomains', urls: 'list-urls', api: 'list-api' }[type];
  if (!listId) return;
  const lower = q.toLowerCase();
  document.querySelectorAll('#' + listId + ' .data-item').forEach(item => {
    const url = item.querySelector('.data-item-url');
    item.style.display = (!q || (url && url.textContent.toLowerCase().includes(lower))) ? '' : 'none';
  });
}

function changePage(dir) {
  S.findingsPage += dir;
  renderFindings();
}

// ── Reports ───────────────────────────────────────────────────────────────────

async function loadReports() {
  try {
    const res = await fetch('/api/reports');
    const data = await res.json();
    renderReports(data.reports || []);
  } catch(_) {}
}

function renderReports(reports) {
  const grid = document.getElementById('reports-grid');
  const zipBtn = document.getElementById('btn-zip');

  if (!reports.length) {
    grid.innerHTML = `<div class="empty-state"><div class="empty-icon">📊</div><div>No reports yet. Complete a scan to generate reports.</div></div>`;
    zipBtn.style.display = 'none';
    return;
  }

  zipBtn.style.display = 'flex';
  grid.innerHTML = '';

  reports.forEach(r => {
    const icon = r.ext === 'pdf' ? 'PDF' : r.ext === 'json' ? 'JSON' : r.ext === 'jsonl' ? 'JL' : r.ext === 'csv' ? 'CSV' : 'MD';
    const extClass = r.ext === 'pdf' ? 'ext-pdf' : r.ext === 'json' || r.ext === 'jsonl' ? 'ext-json' : 'ext-md';
    const sizeStr = fmtSize(r.size);
    const div = document.createElement('div');
    div.className = 'report-item';
    div.innerHTML = `
      <div class="report-icon">${icon}</div>
      <div class="report-meta">
        <div class="report-name" title="${esc(r.name)}">${esc(r.name)}</div>
        <div class="report-info">${sizeStr} &nbsp;·&nbsp; ${r.ext.toUpperCase()}</div>
      </div>
      <span class="report-ext-badge ${extClass}">${r.ext.toUpperCase()}</span>
      <a class="btn-dl" href="/api/reports/download/${encodeURIComponent(r.name)}" download>
        ⬇ Download
      </a>
    `;
    grid.appendChild(div);
  });
}

function downloadZip() {
  window.location.href = '/api/reports/zip';
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function clearLog() {
  document.getElementById('log-panel').innerHTML = `
    <div class="empty-state" id="log-empty">
      <div class="empty-icon">📋</div><div>Logs will appear here during a scan.</div>
    </div>`;
  S.logs = [];
  animateBadge('badge-log', 0);
}

function clearAll() {
  S.subdomains=[]; S.urls=[]; S.directories=[];
  S.apiEndpoints=[]; S.findings=[]; S.logs=[];
  resetAllData();
  updateChart();
  document.getElementById('btn-clear').style.display = 'none';
  document.getElementById('topbar-target').classList.add('idle');
  document.getElementById('topbar-target-text').textContent = 'No target';
  resetPipeline();
  ['stat-subdomains','stat-urls','stat-dirs','stat-api','stat-params',
   'stat-findings','stat-critical','stat-high'].forEach(id => animateNum(id,0));
  ['badge-log','badge-sub','badge-urls','badge-dirs','badge-api','badge-findings']
    .forEach(id => animateBadge(id, 0));
}

function resetAllData() {
  // Subdomains list
  document.getElementById('list-subdomains').innerHTML = `<div class="empty-state"><div class="empty-icon">🌐</div><div>Enable Subdomain Discovery and run a scan.</div></div>`;
  document.getElementById('sub-count').textContent = '0 subdomains';
  // URLs list
  document.getElementById('list-urls').innerHTML = `<div class="empty-state"><div class="empty-icon">🕷️</div><div>Enable URL Crawler and run a scan.</div></div>`;
  document.getElementById('urls-count').textContent = '0 URLs';
  // API list
  document.getElementById('list-api').innerHTML = `<div class="empty-state"><div class="empty-icon">🔌</div><div>Enable API Discovery and run a scan.</div></div>`;
  document.getElementById('api-count').textContent = '0 endpoints';
  // Dirs table
  document.getElementById('dirs-tbody').innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">📂</div><div>Enable Directory Fuzzer and run a scan.</div></div></td></tr>`;
  document.getElementById('dirs-count').textContent = '0 paths';
  // Findings table
  document.getElementById('findings-tbody').innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">🚨</div><div>No security findings yet. Run a scan.</div></div></td></tr>`;
  document.getElementById('findings-count-lbl').textContent = '0 findings';
  document.getElementById('pag-bar').style.display = 'none';
  // Top findings
  document.getElementById('top-findings-list').innerHTML = `<div class="empty-state"><div class="empty-icon">🔍</div><div>No findings yet. Configure a target and start a scan.</div></div>`;
  // Log
  clearLog();
  // Chart
  updateChart();
}

async function copyData(type) {
  const data = {
    subdomains:  S.subdomains,
    urls:        S.urls,
    dirs:        S.directories.map(d => d.url),
    api:         S.apiEndpoints,
  }[type] || [];
  try {
    await navigator.clipboard.writeText(data.join('\n'));
    showToast(`${data.length} items copied to clipboard`, 'success');
  } catch(_) {
    showToast('Copy failed — try manually selecting', 'warning');
  }
}

function countBySeverity(findings) {
  return findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});
}

function fmtSize(bytes) {
  if (!bytes || bytes === 0) return '0B';
  if (bytes < 1024) return bytes + 'B';
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + 'KB';
  return (bytes/(1024*1024)).toFixed(2) + 'MB';
}

function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function animateNum(id, val) {
  const el = document.getElementById(id);
  if (!el) return;
  const cur = parseInt(el.textContent) || 0;
  if (cur === val) return;
  el.textContent = val;
  el.classList.remove('updated');
  void el.offsetWidth; // reflow
  el.classList.add('updated');
}

function animateBadge(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ── Toast Notifications ───────────────────────────────────────────────────────
function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type]||'•'}</span><span>${esc(msg)}</span>`;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transition = 'opacity 0.4s'; }, 4000);
  setTimeout(() => toast.remove(), 4500);
}
