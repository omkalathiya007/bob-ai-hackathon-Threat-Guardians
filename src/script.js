/* =========================================================
   ThreatGuard AI v2 — script.js
   Threat Intelligence Correlation & Alert Prioritisation
   PROTOTYPE — ALL DATA IS FICTIONAL — NOT FOR OPERATIONAL USE
   ========================================================= */
'use strict';

/* ── STORAGE KEYS ── */
const KEYS = {
  ALERTS:    'tg2_alerts',
  INCIDENTS: 'tg2_incidents',
  REPORTS:   'tg2_reports',
  SETTINGS:  'tg2_settings',
  DRAFT:     'tg2_draft',
  EXPLOG:    'tg2_explog',
};

/* ── DEFAULTS ── */
const DEFAULT_SETTINGS = { corrTimeWindow: 60, corrMinIndicators: 1 };

/* ── DEMO LOCATION LOOKUP TABLE ── */
const DEMO_LOCATIONS = {
  'Fictional Land':  { lat: 51.5074,  lng: -0.1278,   city: 'Demo City'    },
  'Fictional East':  { lat: 35.6762,  lng: 139.6503,  city: 'Cyber Valley' },
  'Fictional South': { lat: -33.8688, lng: 151.2093,  city: 'Shadow Port'  },
  'Phantom Coast':   { lat: 40.7128,  lng: -74.0060,  city: 'Ghost City'   },
  'Dark Continent':  { lat: -26.2041, lng: 28.0473,   city: 'Signal Hill'  },
  'Frozen Reach':    { lat: 59.9139,  lng: 10.7522,   city: 'Ice Station'  },
  'Desert Pulse':    { lat: 25.2048,  lng: 55.2708,   city: 'Sand Fortress'},
  'Iron Plateau':    { lat: 55.7558,  lng: 37.6173,   city: 'Steel City'   },
  'Neon Delta':      { lat: 22.3193,  lng: 114.1694,  city: 'Neon Bay'     },
  'Coral Reach':     { lat: 1.3521,   lng: 103.8198,  city: 'Reef Station' },
};

/* ── GLOBAL STATE ── */
const State = {
  alerts:          [],
  incidents:       [],
  reports:         [],
  settings:        { ...DEFAULT_SETTINGS },
  filteredAlerts:  [],
  currentPage:     1,
  pageSize:        15,
  pendingImport:   [],
  pendingDeleteId: null,
  currentBluf:     null,
  charts:          {},
  fpFilter:        'all',
  mitreSearch:     '',
  mitreTactic:     '',
  editingAlertId:  null,
};

/* =========================================================
   UTILITIES
   ========================================================= */
const Utils = {
  genId(prefix = 'ALT') {
    const nums = State.alerts.map(a => parseInt((a.alertId || '').replace(/\D/g, '')) || 0);
    return `${prefix}-${(nums.length ? Math.max(...nums) : 1000) + 1}`;
  },
  genIncId() {
    const nums = State.incidents.map(i => parseInt((i.incidentId || '').replace(/\D/g, '')) || 0);
    return `INC-${(nums.length ? Math.max(...nums) : 5000) + 1}`;
  },
  genRptId() {
    const nums = State.reports.map(r => parseInt((r.reportId || '').replace(/\D/g, '')) || 0);
    return `RPT-${(nums.length ? Math.max(...nums) : 9000) + 1}`;
  },
  nowIso()    { return new Date().toISOString().slice(0, 19); },
  fmtDate(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString('en-GB', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }); }
    catch(e) { return iso; }
  },
  fmtDateShort(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' }); }
    catch(e) { return iso; }
  },
  esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  },
  trunc(s, n = 50) { return s && s.length > n ? s.slice(0, n) + '…' : (s || ''); },
  sevCls(sev) { return ({ Critical:'sev-critical', High:'sev-high', Medium:'sev-medium', Low:'sev-low' })[sev] || 'sev-low'; },
  priCls(pri) { return ({ P1:'pri-p1', P2:'pri-p2', P3:'pri-p3', P4:'pri-p4' })[pri] || 'pri-p4'; },
  statusCls(s) {
    return ({ 'New':'status-new','Under Investigation':'status-invest','Confirmed':'status-confirm','False Positive':'status-fp','Closed':'status-closed' })[s] || 'status-new';
  },
  classify(score, status) {
    if (status === 'False Positive') return { label:'Likely Benign',    cls:'cls-benign' };
    if (score >= 75) return { label:'Likely Malicious', cls:'cls-malicious' };
    if (score >= 50) return { label:'Suspicious',       cls:'cls-suspicious' };
    if (score  < 25) return { label:'Likely Benign',    cls:'cls-benign' };
    return { label:'Inconclusive', cls:'cls-inconclusive' };
  },
  riskBarCls(s) { return s >= 80 ? 'risk-80' : s >= 60 ? 'risk-60' : s >= 35 ? 'risk-35' : 'risk-0'; },
  riskBar(score) {
    const c = this.riskBarCls(score);
    return `<div class="risk-bar-wrap"><div class="risk-bar-bg"><div class="risk-bar-fill ${c}" style="width:${score}%"></div></div></div>`;
  },
  clone(o) { return JSON.parse(JSON.stringify(o)); },
  /* Resolve lat/lng for an alert: explicit fields → DEMO_LOCATIONS → null */
  resolveLocation(alert) {
    if (alert.lat != null && alert.lng != null &&
        !isNaN(parseFloat(alert.lat)) && !isNaN(parseFloat(alert.lng))) {
      return { lat: parseFloat(alert.lat), lng: parseFloat(alert.lng),
               city: alert.city || '', country: alert.country || '' };
    }
    if (alert.country && DEMO_LOCATIONS[alert.country]) {
      const loc = DEMO_LOCATIONS[alert.country];
      return { lat: loc.lat, lng: loc.lng,
               city: alert.city || loc.city, country: alert.country };
    }
    return null;
  },
};

/* =========================================================
   LOCAL STORAGE
   ========================================================= */
const Store = {
  load(key, fallback = []) {
    try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; }
    catch(e) { return fallback; }
  },
  save(key, data) {
    try { localStorage.setItem(key, JSON.stringify(data)); return true; }
    catch(e) { Toast.show('Storage error: ' + e.message, 'error'); return false; }
  },
  loadAll() {
    State.alerts    = Store.load(KEYS.ALERTS,    []);
    State.incidents = Store.load(KEYS.INCIDENTS, []);
    State.reports   = Store.load(KEYS.REPORTS,   []);
    State.settings  = { ...DEFAULT_SETTINGS, ...Store.load(KEYS.SETTINGS, {}) };
  },
  saveAll() {
    Store.save(KEYS.ALERTS,    State.alerts);
    Store.save(KEYS.INCIDENTS, State.incidents);
    Store.save(KEYS.REPORTS,   State.reports);
    Store.save(KEYS.SETTINGS,  State.settings);
  },
  info() {
    let t = 0;
    Object.values(KEYS).forEach(k => { t += (localStorage.getItem(k) || '').length; });
    return `Alerts: ${State.alerts.length} | Incidents: ${State.incidents.length} | BLUF Reports: ${State.reports.length} | Storage: ~${(t/1024).toFixed(1)} KB`;
  },
};

/* ── Convenience wrappers (required by spec) ── */
function loadAlerts()  { State.alerts = Store.load(KEYS.ALERTS, []); }
function saveAlerts()  { Store.save(KEYS.ALERTS, State.alerts); }

function updateDashboard() {
  if (Nav.current === 'dashboard') Dashboard.render();
}
function updateAllDepartments() {
  Nav.onEnter(Nav.current);
}

/* =========================================================
   TOAST NOTIFICATIONS
   ========================================================= */
const Toast = {
  show(msg, type = 'info') {
    const titles = { success:'✓ Success', error:'✗ Error', info:'ℹ Info', warn:'⚠ Warning' };
    const c = document.getElementById('toastContainer');
    if (!c) return;
    const d = document.createElement('div');
    d.className = `toast tg-toast t-${type}`;
    d.setAttribute('role','alert');
    d.innerHTML = `
      <div class="toast-header">
        <strong class="me-auto">${titles[type] || 'Notice'}</strong>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
      </div>
      <div class="toast-body">${Utils.esc(msg)}</div>`;
    c.appendChild(d);
    const t = new bootstrap.Toast(d, { delay: type === 'error' ? 6000 : 3500 });
    t.show();
    d.addEventListener('hidden.bs.toast', () => d.remove());
  },
};

/* =========================================================
   RISK SCORING ENGINE
   ========================================================= */
const RiskEngine = {
  SEV:  { Critical:40, High:28, Medium:16, Low:6 },
  ASSET:{ Critical:20, High:14, Medium:8,  Low:3 },
  CAT:  {
    'Exfiltration':10,'Command and Control':9,'Credential Access':8,
    'Privilege Escalation':9,'Lateral Movement':8,'Impact':10,
    'Execution':7,'Persistence':7,'Initial Access':6,
    'Collection':5,'Discovery':3,'Defense Evasion':5,
    'Reconnaissance':3,'Resource Development':2,
  },
  calc(alert, relatedCount = 0) {
    const sev  = this.SEV[alert.severity]          || 6;
    const ast  = this.ASSET[alert.assetCriticality]|| 3;
    const conf = Math.round((parseInt(alert.confidence) || 50) * 0.15);
    const cat  = this.CAT[alert.threatCategory]    || 4;
    const corr = Math.min(relatedCount * 2, 10);
    const total= Math.min(100, sev + ast + conf + cat + corr);
    let priority = total >= 80 ? 'P1' : total >= 60 ? 'P2' : total >= 35 ? 'P3' : 'P4';
    const factors = [
      { label:`Severity (${alert.severity || '?'})`,                   value: sev  },
      { label:`Asset Criticality (${alert.assetCriticality || '?'})`,  value: ast  },
      { label:`Confidence (${alert.confidence || 0}%) × 0.15`,         value: conf },
      { label:`Threat Category (${alert.threatCategory || '?'})`,      value: cat  },
      { label:`Correlated Alerts (×${relatedCount})`,                   value: corr },
    ];
    return { score: total, priority, factors };
  },
  priLabel(p) { return ({ P1:'P1 — Critical', P2:'P2 — High', P3:'P3 — Medium', P4:'P4 — Low' })[p] || p; },
  factorsHtml(factors, score) {
    const rows = factors.map(f =>
      `<div class="factor"><span>${Utils.esc(f.label)}</span><span>+${f.value}</span></div>`
    ).join('');
    return `<div class="score-explain">${rows}
      <div class="factor" style="border-top:1px solid var(--border);margin-top:6px;padding-top:6px;">
        <span><strong>Total Risk Score</strong></span>
        <span style="color:var(--high);font-size:1rem"><strong>${score}</strong> / 100</span>
      </div></div>`;
  },
};

/* =========================================================
   CORRELATION ENGINE
   ========================================================= */
const Correlator = {
  run() {
    const alerts  = State.alerts.filter(a => a.status !== 'False Positive' && a.status !== 'Closed');
    const winMs   = (State.settings.corrTimeWindow || 60) * 60 * 1000;
    const minInd  = State.settings.corrMinIndicators || 1;
    const groups  = [];
    const used    = new Set();

    alerts.forEach((a, i) => {
      if (used.has(a.alertId)) return;
      const grp = [a];
      used.add(a.alertId);
      const tA = new Date(a.timestamp).getTime();

      alerts.forEach((b, j) => {
        if (i === j || used.has(b.alertId)) return;
        if (Math.abs(tA - new Date(b.timestamp).getTime()) > winMs) return;
        let shared = 0;
        if (a.sourceIp         && b.sourceIp         && a.sourceIp         === b.sourceIp)         shared++;
        if (a.destinationIp    && b.destinationIp    && a.destinationIp    === b.destinationIp)    shared++;
        if (a.domain           && b.domain           && a.domain           === b.domain)           shared++;
        if (a.fileHash         && b.fileHash         && a.fileHash         === b.fileHash)         shared++;
        if (a.assetName        && b.assetName        && a.assetName        === b.assetName)        shared++;
        if (a.mitreTechniqueId && b.mitreTechniqueId && a.mitreTechniqueId === b.mitreTechniqueId) shared++;
        if (shared >= minInd) { grp.push(b); used.add(b.alertId); }
      });

      if (grp.length > 1) groups.push(grp);
    });

    const incidents = groups.map(grp => {
      const ids      = grp.map(a => a.alertId);
      const maxScore = Math.max(...grp.map(a => a.riskScore || 0));
      const pri      = maxScore >= 80 ? 'P1' : maxScore >= 60 ? 'P2' : maxScore >= 35 ? 'P3' : 'P4';
      const ips   = [...new Set(grp.map(a => a.sourceIp).filter(Boolean))];
      const dips  = [...new Set(grp.map(a => a.destinationIp).filter(Boolean))];
      const doms  = [...new Set(grp.map(a => a.domain).filter(Boolean))];
      const hsh   = [...new Set(grp.map(a => a.fileHash).filter(Boolean))];
      const ast   = [...new Set(grp.map(a => a.assetName).filter(Boolean))];
      const inds  = [];
      ips.forEach(v  => inds.push({ type:'Source IP',   value:v }));
      dips.forEach(v => inds.push({ type:'Dest IP',     value:v }));
      doms.forEach(v => inds.push({ type:'Domain',      value:v }));
      hsh.forEach(v  => inds.push({ type:'File Hash',   value:v }));
      ast.forEach(v  => inds.push({ type:'Asset',       value:v }));
      const existing = State.incidents.find(inc =>
        inc.alertIds && inc.alertIds.slice().sort().join(',') === ids.slice().sort().join(',')
      );
      if (existing) return { ...existing, alertIds:ids, priority:pri, riskScore:maxScore, indicators:inds };
      return {
        incidentId: Utils.genIncId(), alertIds:ids, status:'Active',
        priority:pri, riskScore:maxScore, indicators:inds,
        notes:'', createdAt:Utils.nowIso(), updatedAt:Utils.nowIso(),
      };
    });

    State.incidents = incidents;
    Store.save(KEYS.INCIDENTS, State.incidents);
    return incidents;
  },
};

/* =========================================================
   CHART MANAGER
   ========================================================= */
const Charts = {
  C: { crit:'#f85149', high:'#e3b341', med:'#3fb950', low:'#388bfd', purple:'#bc8cff', grid:'rgba(48,54,61,0.6)' },
  destroy(id) { if (State.charts[id]) { State.charts[id].destroy(); delete State.charts[id]; } },
  create(id, cfg) {
    this.destroy(id);
    const el = document.getElementById(id);
    if (!el) return null;
    State.charts[id] = new Chart(el, cfg);
    return State.charts[id];
  },

  buildTrend() {
    const days = 7, labels = [], data = [];
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      labels.push(d.toLocaleDateString('en-GB', { day:'2-digit', month:'short' }));
      const ds = d.toISOString().slice(0,10);
      data.push(State.alerts.filter(a => (a.createdAt || a.timestamp || '').startsWith(ds)).length);
    }
    let cum = 0;
    const cumData = data.map(v => (cum += v, cum));
    this.create('chartTrend', {
      type:'bar', data:{ labels,
        datasets:[
          { label:'Alerts', data, backgroundColor:'rgba(56,139,253,0.5)', borderColor:'#388bfd', borderWidth:1 },
          { label:'Cumulative', data:cumData, type:'line', borderColor:'#bc8cff', backgroundColor:'transparent', pointBackgroundColor:'#bc8cff', tension:0.3, yAxisID:'y2' },
        ],
      },
      options:{ responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ labels:{ color:'#8b949e', font:{size:11} } } },
        scales:{
          x:{ ticks:{color:'#8b949e'}, grid:{color:this.C.grid} },
          y:{ ticks:{color:'#8b949e'}, grid:{color:this.C.grid}, beginAtZero:true },
          y2:{ position:'right', ticks:{color:'#bc8cff'}, grid:{display:false}, beginAtZero:true },
        },
      },
    });
  },

  buildSev() {
    const a = State.alerts;
    const counts = ['Critical','High','Medium','Low'].map(s => a.filter(x => x.severity === s).length);
    this.create('chartSev', {
      type:'doughnut', data:{
        labels:['Critical','High','Medium','Low'],
        datasets:[{ data:counts, backgroundColor:['#f85149','#e3b341','#3fb950','#388bfd'], borderColor:'#1c2230', borderWidth:2 }],
      },
      options:{ responsive:true, maintainAspectRatio:false, cutout:'65%',
        plugins:{ legend:{ position:'right', labels:{ color:'#8b949e', font:{size:11}, padding:12 } } },
      },
    });
  },

  buildSource() {
    const a = State.alerts;
    const sources = [...new Set(a.map(x => x.sourceType).filter(Boolean))];
    const counts  = sources.map(s => a.filter(x => x.sourceType === s).length);
    this.create('chartSource', {
      type:'pie', data:{
        labels:sources,
        datasets:[{ data:counts, backgroundColor:['#388bfd','#e3b341','#3fb950','#f85149','#bc8cff'].slice(0, sources.length), borderColor:'#1c2230', borderWidth:2 }],
      },
      options:{ responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ position:'right', labels:{ color:'#8b949e', font:{size:11}, padding:10 } } },
      },
    });
  },

  buildAssets() {
    const map = {};
    State.alerts.forEach(a => { if (a.assetName) map[a.assetName] = (map[a.assetName] || 0) + 1; });
    const sorted = Object.entries(map).sort((a,b) => b[1]-a[1]).slice(0,6);
    this.create('chartAssets', {
      type:'bar', data:{
        labels:sorted.map(e => e[0]),
        datasets:[{ label:'Alerts', data:sorted.map(e => e[1]), backgroundColor:'rgba(248,81,73,0.6)', borderColor:'#f85149', borderWidth:1 }],
      },
      options:{ indexAxis:'y', responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ display:false } },
        scales:{
          x:{ ticks:{color:'#8b949e'}, grid:{color:this.C.grid}, beginAtZero:true },
          y:{ ticks:{color:'#8b949e', font:{size:11}}, grid:{display:false} },
        },
      },
    });
  },

  buildAll() { this.buildTrend(); this.buildSev(); this.buildSource(); this.buildAssets(); },
};

/* =========================================================
   NAVIGATION
   ========================================================= */
const Nav = {
  TITLES: {
    'dashboard':'Dashboard','add-alert':'Add Alert','import-data':'Import Data',
    'all-alerts':'All Alerts','correlated':'Correlated Incidents','incidents':'Incident Management',
    'fp-analysis':'False-Positive Analysis','mitre':'MITRE ATT&CK','threat-map':'Threat Map',
    'bluf':'BLUF Reports','export':'Export Data','settings':'Settings',
  },
  current: 'dashboard',

  go(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const target = document.getElementById('page-' + page);
    if (target) target.classList.add('active');
    document.querySelectorAll('.nav-link').forEach(a => a.classList.toggle('active', a.dataset.page === page));
    const ht = document.getElementById('headerTitle');
    if (ht) ht.textContent = this.TITLES[page] || page;
    if (page !== 'add-alert') State.editingAlertId = null;
    this.current = page;
    if (window.innerWidth < 992) document.getElementById('sidebar')?.classList.remove('open');
    this.onEnter(page);
  },

  onEnter(page) {
    switch (page) {
      case 'dashboard':   Dashboard.render();       break;
      case 'all-alerts':  AlertsTable.render();     break;
      case 'correlated':  CorrelatedPage.render();  break;
      case 'incidents':   IncidentMgmt.render();    break;
      case 'fp-analysis': FPAnalysis.render();      break;
      case 'mitre':       MitrePage.render();       break;
      case 'threat-map':  ThreatMap.render();       break;
      case 'bluf':        BlufPage.render();        break;
      case 'export':      ExportPage.render();      break;
      case 'settings':    SettingsPage.render();    break;
    }
  },
};

/* =========================================================
   DASHBOARD
   ========================================================= */
const Dashboard = {
  render() {
    const a = State.alerts;
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('kpiTotal',     a.length);
    set('kpiCritical',  a.filter(x => x.severity === 'Critical').length);
    set('kpiHigh',      a.filter(x => x.priority === 'P1' || x.priority === 'P2').length);
    set('kpiIncidents', State.incidents.length);
    set('kpiFP',        a.filter(x => x.status === 'False Positive').length);
    const avg = a.length ? Math.round(a.reduce((s,x) => s + (x.riskScore||0), 0) / a.length) : 0;
    set('kpiAvgScore', avg);
    const cb = document.getElementById('alertCountBadge');
    if (cb) cb.textContent = a.length + ' Alerts';
    Charts.buildAll();
    this._renderRecent();
  },
  _renderRecent() {
    const tbody = document.getElementById('recentAlertsTbody');
    if (!tbody) return;
    const recent = [...State.alerts].sort((a,b) => new Date(b.timestamp)-new Date(a.timestamp)).slice(0,10);
    if (!recent.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">No alerts yet. Load demo data or add alerts.</td></tr>';
      return;
    }
    tbody.innerHTML = recent.map(a => `
      <tr style="cursor:pointer" onclick="TG.openAlertDetail('${Utils.esc(a.alertId)}')">
        <td><span class="mono text-accent">${Utils.esc(a.alertId)}</span></td>
        <td>${Utils.esc(Utils.trunc(a.alertType,30))}</td>
        <td class="text-muted">${Utils.esc(a.sourceType||'—')}</td>
        <td><span class="sev-badge ${Utils.sevCls(a.severity)}">${Utils.esc(a.severity||'—')}</span></td>
        <td>${Utils.riskBar(a.riskScore||0)} <small class="text-muted">${a.riskScore||0}</small></td>
        <td><span class="pri-badge ${Utils.priCls(a.priority)}">${Utils.esc(a.priority||'—')}</span></td>
        <td><span class="status-badge ${Utils.statusCls(a.status)}">${Utils.esc(a.status||'—')}</span></td>
        <td class="text-muted">${Utils.fmtDate(a.timestamp)}</td>
      </tr>`).join('');
  },
};

/* =========================================================
   ALL ALERTS TABLE
   ========================================================= */
const AlertsTable = {
  render() { this.applyFilters(); },
  applyFilters() {
    let alerts = [...State.alerts];
    const search   = (document.getElementById('searchAlerts')?.value   || '').toLowerCase();
    const severity = document.getElementById('filterSeverity')?.value  || '';
    const status   = document.getElementById('filterStatus')?.value    || '';
    const source   = document.getElementById('filterSource')?.value    || '';
    const priority = document.getElementById('filterPriority')?.value  || '';
    const dateFrom = document.getElementById('filterDateFrom')?.value  || '';
    const dateTo   = document.getElementById('filterDateTo')?.value    || '';
    const sort     = document.getElementById('sortAlerts')?.value      || 'timestamp-desc';

    if (search)   alerts = alerts.filter(a =>
      (a.alertId||'').toLowerCase().includes(search) ||
      (a.alertType||'').toLowerCase().includes(search) ||
      (a.sourceIp||'').includes(search) ||
      (a.destinationIp||'').includes(search) ||
      (a.domain||'').toLowerCase().includes(search) ||
      (a.description||'').toLowerCase().includes(search)
    );
    if (severity) alerts = alerts.filter(a => a.severity   === severity);
    if (status)   alerts = alerts.filter(a => a.status     === status);
    if (source)   alerts = alerts.filter(a => a.sourceType === source);
    if (priority) alerts = alerts.filter(a => a.priority   === priority);
    if (dateFrom) alerts = alerts.filter(a => (a.timestamp||'') >= dateFrom);
    if (dateTo)   alerts = alerts.filter(a => (a.timestamp||'').slice(0,10) <= dateTo);

    alerts.sort((a,b) => {
      if (sort === 'timestamp-desc') return new Date(b.timestamp) - new Date(a.timestamp);
      if (sort === 'timestamp-asc')  return new Date(a.timestamp) - new Date(b.timestamp);
      if (sort === 'risk-desc')      return (b.riskScore||0) - (a.riskScore||0);
      if (sort === 'risk-asc')       return (a.riskScore||0) - (b.riskScore||0);
      return 0;
    });

    State.filteredAlerts = alerts;
    State.currentPage    = 1;
    this.renderTable();
  },
  renderTable() {
    const tbody = document.getElementById('allAlertsTbody');
    const pag   = document.getElementById('alertsPagination');
    if (!tbody) return;
    const alerts = State.filteredAlerts;
    const total  = alerts.length;
    const pages  = Math.ceil(total / State.pageSize) || 1;
    const page   = Math.min(State.currentPage, pages);
    const slice  = alerts.slice((page-1)*State.pageSize, page*State.pageSize);

    if (!slice.length) {
      tbody.innerHTML = '<tr><td colspan="11" class="text-center text-muted py-3">No alerts match the current filters.</td></tr>';
      if (pag) pag.innerHTML = '';
      return;
    }
    tbody.innerHTML = slice.map(a => {
      const cl = Utils.classify(a.riskScore||0, a.status);
      return `<tr>
        <td><span class="mono text-accent" style="cursor:pointer" onclick="TG.openAlertDetail('${Utils.esc(a.alertId)}')">${Utils.esc(a.alertId)}</span></td>
        <td>${Utils.esc(Utils.trunc(a.alertType,28))}</td>
        <td class="text-muted">${Utils.esc(a.sourceType||'—')}</td>
        <td><span class="sev-badge ${Utils.sevCls(a.severity)}">${Utils.esc(a.severity||'—')}</span></td>
        <td>${Utils.riskBar(a.riskScore||0)} <small>${a.riskScore||0}</small></td>
        <td><span class="pri-badge ${Utils.priCls(a.priority)}">${Utils.esc(a.priority||'—')}</span></td>
        <td><span class="${cl.cls}">${cl.label}</span></td>
        <td><span class="status-badge ${Utils.statusCls(a.status)}">${Utils.esc(a.status||'—')}</span></td>
        <td class="text-muted truncate">${Utils.esc(a.assetName||'—')}</td>
        <td class="text-muted">${Utils.fmtDate(a.timestamp)}</td>
        <td>
          <button class="btn btn-sm btn-outline-tg py-0 px-1" onclick="TG.openAlertDetail('${Utils.esc(a.alertId)}')"><i class="bi bi-eye"></i></button>
          <button class="btn btn-sm btn-outline-tg py-0 px-1 ms-1" onclick="TG.deleteAlert('${Utils.esc(a.alertId)}')"><i class="bi bi-trash3"></i></button>
        </td>
      </tr>`;
    }).join('');

    if (pag) {
      let html = `<span>Showing ${(page-1)*State.pageSize+1}–${Math.min(page*State.pageSize,total)} of ${total}</span>`;
      html += `<button ${page<=1?'disabled':''} onclick="TG.alertsPage(${page-1})"><i class="bi bi-chevron-left"></i></button>`;
      for (let p = 1; p <= pages; p++) {
        if (pages <= 7 || p === 1 || p === pages || Math.abs(p-page) <= 1)
          html += `<button class="${p===page?'active':''}" onclick="TG.alertsPage(${p})">${p}</button>`;
        else if (Math.abs(p-page) === 2) html += '<span>…</span>';
      }
      html += `<button ${page>=pages?'disabled':''} onclick="TG.alertsPage(${page+1})"><i class="bi bi-chevron-right"></i></button>`;
      pag.innerHTML = html;
    }
  },
};

/* =========================================================
   ALERT DETAIL MODAL
   ========================================================= */
const AlertDetail = {
  open(alertId) {
    const a = State.alerts.find(x => x.alertId === alertId);
    if (!a) return;
    const cl  = Utils.classify(a.riskScore||0, a.status);
    const inc = State.incidents.find(i => i.alertIds?.includes(alertId));
    const loc = Utils.resolveLocation(a);
    const titleEl = document.getElementById('alertDetailTitle');
    const bodyEl  = document.getElementById('alertDetailBody');
    if (titleEl) titleEl.innerHTML = `<span class="mono text-accent">${Utils.esc(a.alertId)}</span> — ${Utils.esc(a.alertType||'')}`;
    if (bodyEl) bodyEl.innerHTML = `
      <div class="bluf-disclaimer">⚠ This alert is fictional and for demonstration purposes only. All assessments require analyst review.</div>
      <div class="modal-detail-grid mb-3">
        ${this._item('Alert ID', a.alertId)}
        ${this._item('Source Type', a.sourceType)}
        ${this._item('Alert Type', a.alertType)}
        ${this._item('Timestamp', Utils.fmtDate(a.timestamp))}
        ${this._item('Severity', `<span class="sev-badge ${Utils.sevCls(a.severity)}">${Utils.esc(a.severity||'—')}</span>`)}
        ${this._item('Priority', `<span class="pri-badge ${Utils.priCls(a.priority)}">${Utils.esc(a.priority||'—')}</span>`)}
        ${this._item('Status', `<span class="status-badge ${Utils.statusCls(a.status)}">${Utils.esc(a.status||'—')}</span>`)}
        ${this._item('Classification', `<span class="${cl.cls}">${cl.label}</span>`)}
        ${this._item('Risk Score', `<strong style="font-size:1.1rem">${a.riskScore||0}</strong> / 100`)}
        ${this._item('Confidence', (a.confidence||0) + '%')}
        ${this._item('Asset', a.assetName||'—')}
        ${this._item('Asset Criticality', a.assetCriticality||'—')}
        ${this._item('Country', loc ? Utils.esc(loc.country) : (a.country||'—'))}
        ${this._item('City', loc ? Utils.esc(loc.city) : (a.city||'—'))}
        ${this._item('Coordinates', loc ? `${loc.lat.toFixed(4)}, ${loc.lng.toFixed(4)}` : '—')}
      </div>
      <hr class="tg-divider"/>
      <div class="mb-3"><div class="detail-label">Description</div><div class="detail-value">${Utils.esc(a.description||'—')}</div></div>
      <div class="modal-detail-grid mb-3">
        ${this._item('Source IP', a.sourceIp||'—')}
        ${this._item('Destination IP', a.destinationIp||'—')}
        ${this._item('Domain', a.domain||'—')}
        ${this._item('Port', a.port||'—')}
        ${this._item('URL', a.url||'—')}
        ${this._item('Malware', a.malwareName||'—')}
        ${this._item('File Hash', Utils.trunc(a.fileHash||'—',40))}
        ${this._item('Threat Category', a.threatCategory||'—')}
      </div>
      <hr class="tg-divider"/>
      <div class="modal-detail-grid mb-3">
        ${this._item('MITRE Tactic', a.mitreTactic||'—')}
        ${this._item('Technique ID', a.mitreTechniqueId||'—')}
        ${this._item('Technique Name', a.mitreTechniqueName||'—')}
        ${this._item('Analyst', a.analystName||'—')}
        ${this._item('Correlated Incident', inc ? inc.incidentId : '—')}
      </div>
      <hr class="tg-divider"/>
      <div class="mb-3"><div class="detail-label">Analyst Notes</div><div class="detail-value">${Utils.esc(a.notes||'—')}</div></div>
      ${RiskEngine.factorsHtml(RiskEngine.calc(a, inc ? inc.alertIds.length-1 : 0).factors, a.riskScore||0)}
      <hr class="tg-divider"/>
      <div>
        <div class="detail-label mb-2">Quick Edit — Status</div>
        <div class="d-flex gap-2 flex-wrap">
          ${['New','Under Investigation','Confirmed','False Positive','Closed'].map(s =>
            `<button class="btn btn-sm ${a.status===s?'btn-primary-tg':'btn-outline-tg'}" onclick="TG.setAlertStatus('${Utils.esc(a.alertId)}','${s}')">${s}</button>`
          ).join('')}
        </div>
      </div>`;
    const editBtn = document.getElementById('btnEditAlert');
    if (editBtn) editBtn.onclick = () => TG.editAlert(alertId);
    const blufBtn = document.getElementById('btnGenerateBlufFromModal');
    if (blufBtn) blufBtn.onclick = () => {
      bootstrap.Modal.getInstance(document.getElementById('alertDetailModal'))?.hide();
      TG.generateBlufFromAlert(alertId);
    };
    new bootstrap.Modal(document.getElementById('alertDetailModal')).show();
  },
  _item(label, value) {
    return `<div class="detail-item"><div class="detail-label">${Utils.esc(label)}</div><div class="detail-value">${value}</div></div>`;
  },
};

/* =========================================================
   ADD / EDIT ALERT FORM
   ========================================================= */
const AlertForm = {
  init() {
    const form = document.getElementById('alertForm');
    if (!form) return;
    form.addEventListener('submit', e => { e.preventDefault(); this.submit(); });
    document.getElementById('btnSaveDraft')?.addEventListener('click', () => this.saveDraft());
    document.getElementById('btnClearForm')?.addEventListener('click', () => this.clear());
    this.setId();
    this.loadDraft();
  },
  setId() {
    const el = document.getElementById('fAlertId');
    if (el) el.value = Utils.genId('ALT');
  },
  clear() {
    document.getElementById('alertForm')?.reset();
    const msgs = document.getElementById('formMessages');
    if (msgs) msgs.innerHTML = '';
    State.editingAlertId = null;
    this.setId();
    localStorage.removeItem(KEYS.DRAFT);
  },
  saveDraft() {
    Store.save(KEYS.DRAFT, this.collect());
    Toast.show('Draft saved.', 'info');
  },
  loadDraft() {
    const d = Store.load(KEYS.DRAFT, null);
    if (!d) return;
    const set = (id, val) => { const el = document.getElementById(id); if (el && val !== undefined) el.value = val; };
    set('fSourceType',d.sourceType); set('fTimestamp',d.timestamp); set('fAlertType',d.alertType); set('fDescription',d.description);
    set('fSourceIp',d.sourceIp); set('fDestIp',d.destinationIp); set('fDomain',d.domain); set('fPort',d.port); set('fUrl',d.url);
    set('fMalware',d.malwareName); set('fFileHash',d.fileHash); set('fThreatCat',d.threatCategory); set('fSeverity',d.severity);
    set('fConfidence',d.confidence); set('fAssetName',d.assetName); set('fAssetCrit',d.assetCriticality);
    set('fMitreTactic',d.mitreTactic); set('fMitreTechId',d.mitreTechniqueId); set('fMitreTechName',d.mitreTechniqueName);
    set('fAnalyst',d.analystName); set('fStatus',d.status); set('fNotes',d.notes);
    set('fCountry',d.country); set('fCity',d.city);
    set('fLat', d.lat != null ? d.lat : ''); set('fLng', d.lng != null ? d.lng : '');
  },
  collect() {
    const v  = id => (document.getElementById(id)?.value || '').trim();
    const vn = id => { const val = document.getElementById(id)?.value; return (val !== '' && val != null) ? parseFloat(val) : null; };
    return {
      sourceType:v('fSourceType'), timestamp:v('fTimestamp'), alertType:v('fAlertType'), description:v('fDescription'),
      sourceIp:v('fSourceIp'), destinationIp:v('fDestIp'), domain:v('fDomain'), port:v('fPort'), url:v('fUrl'),
      malwareName:v('fMalware'), fileHash:v('fFileHash'), threatCategory:v('fThreatCat'), severity:v('fSeverity'),
      confidence:parseInt(v('fConfidence'))||50, assetName:v('fAssetName'), assetCriticality:v('fAssetCrit'),
      mitreTactic:v('fMitreTactic'), mitreTechniqueId:v('fMitreTechId'), mitreTechniqueName:v('fMitreTechName'),
      analystName:v('fAnalyst'), status:v('fStatus')||'New', notes:v('fNotes'),
      country:v('fCountry'), city:v('fCity'), lat:vn('fLat'), lng:vn('fLng'),
    };
  },
  submit() {
    const data = this.collect();
    const msgs = document.getElementById('formMessages');
    const errs = [];
    if (!data.sourceType)       errs.push('Source Type is required.');
    if (!data.timestamp)        errs.push('Timestamp is required.');
    if (!data.alertType)        errs.push('Alert Type is required.');
    if (!data.description)      errs.push('Description is required.');
    if (!data.threatCategory)   errs.push('Threat Category is required.');
    if (!data.severity)         errs.push('Severity is required.');
    if (!data.assetName)        errs.push('Asset Name is required.');
    if (!data.assetCriticality) errs.push('Asset Criticality is required.');
    if (!data.analystName)      errs.push('Analyst Name is required.');
    if (errs.length) { if (msgs) msgs.innerHTML = `<div class="alert-error-tg">${errs.map(e => Utils.esc(e)).join('<br>')}</div>`; return; }

    const editId = State.editingAlertId;
    if (editId) {
      const idx = State.alerts.findIndex(a => a.alertId === editId);
      if (idx >= 0) {
        const updated = { ...State.alerts[idx], ...data, alertId: editId };
        const r = RiskEngine.calc(updated, 0);
        updated.riskScore = r.score; updated.priority = r.priority;
        State.alerts[idx] = updated;
        Store.save(KEYS.ALERTS, State.alerts);
        localStorage.removeItem(KEYS.DRAFT);
        Correlator.run();
        updateThreatMap();
        if (msgs) msgs.innerHTML = `<div class="alert-success-tg">✓ Alert <strong>${Utils.esc(editId)}</strong> updated (risk: ${updated.riskScore}, ${updated.priority}).</div>`;
        State.editingAlertId = null;
        const idEl = document.getElementById('fAlertId');
        if (idEl) idEl.readOnly = true;
        this.setId();
        Toast.show(`Alert ${editId} updated.`, 'success');
        const cb = document.getElementById('alertCountBadge');
        if (cb) cb.textContent = State.alerts.length + ' Alerts';
        return;
      }
    }

    const alert = { alertId: Utils.genId('ALT'), createdAt: Utils.nowIso(), ...data };
    const r = RiskEngine.calc(alert, 0);
    alert.riskScore = r.score; alert.priority = r.priority;
    State.alerts.push(alert);
    Store.save(KEYS.ALERTS, State.alerts);
    localStorage.removeItem(KEYS.DRAFT);
    Correlator.run();
    updateThreatMap();
    if (msgs) msgs.innerHTML = `<div class="alert-success-tg">✓ Alert <strong>${Utils.esc(alert.alertId)}</strong> saved — Risk: <strong>${alert.riskScore}</strong> (${alert.priority}).</div>`;
    this.clear();
    Toast.show(`Alert ${alert.alertId} added.`, 'success');
    const cb = document.getElementById('alertCountBadge');
    if (cb) cb.textContent = State.alerts.length + ' Alerts';
  },
};

/* =========================================================
   IMPORT PAGE
   ========================================================= */
const ImportPage = {
  init() {
    const dz = document.getElementById('dropZone');
    const fi = document.getElementById('fileInput');
    if (!dz || !fi) return;
    dz.addEventListener('click', () => fi.click());
    dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
    dz.addEventListener('drop', e => {
      e.preventDefault(); dz.classList.remove('drag-over');
      if (e.dataTransfer.files[0]) this.readFile(e.dataTransfer.files[0]);
    });
    fi.addEventListener('change', () => { if (fi.files[0]) this.readFile(fi.files[0]); });
    document.getElementById('btnConfirmImport')?.addEventListener('click', () => this.confirm());
    document.getElementById('btnCancelImport')?.addEventListener('click',  () => this.cancel());
    document.getElementById('btnDownloadSample')?.addEventListener('click',() => this.downloadSample());
  },
  readFile(file) {
    const info = document.getElementById('fileInfo');
    if (info) info.innerHTML = `<span class="text-muted">Reading: <strong>${Utils.esc(file.name)}</strong> (${(file.size/1024).toFixed(1)} KB)</span>`;
    const reader = new FileReader();
    reader.onload = e => {
      try {
        let records;
        if (file.name.endsWith('.json')) {
          records = JSON.parse(e.target.result);
          if (!Array.isArray(records)) records = [records];
        } else {
          records = this.parseCSV(e.target.result);
        }
        this.showPreview(records);
      } catch(err) {
        const im = document.getElementById('importMessages');
        if (im) im.innerHTML = `<div class="alert-error-tg">Parse error: ${Utils.esc(err.message)}</div>`;
      }
    };
    reader.readAsText(file);
  },
  parseCSV(text) {
    const lines   = text.trim().split('\n');
    const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g,''));
    return lines.slice(1).filter(l => l.trim()).map(line => {
      const vals = line.split(',').map(v => v.trim().replace(/^"|"$/g,''));
      const obj  = {};
      headers.forEach((h,i) => { obj[h] = vals[i] || ''; });
      return obj;
    });
  },
  showPreview(records) {
    State.pendingImport = records;
    const preview = document.getElementById('importPreview');
    const count   = document.getElementById('previewCount');
    const thead   = document.getElementById('previewHeaders');
    const tbody   = document.getElementById('previewTbody');
    if (!preview||!count||!thead||!tbody) return;
    count.textContent = records.length;
    const fields = ['alertId','alertType','sourceType','severity','timestamp','assetName','status'];
    thead.innerHTML = fields.map(f => `<th>${f}</th>`).join('');
    tbody.innerHTML = records.slice(0,20).map(r =>
      `<tr>${fields.map(f => `<td>${Utils.esc(Utils.trunc(r[f]||'—',30))}</td>`).join('')}</tr>`
    ).join('');
    preview.classList.remove('d-none');
    const im = document.getElementById('importMessages');
    if (im) im.innerHTML = '';
  },
  confirm() {
    let added = 0, skipped = 0;
    State.pendingImport.forEach(r => {
      if (!r.alertType || !r.severity || !r.sourceType || !r.timestamp) { skipped++; return; }
      let id = r.alertId || Utils.genId('ALT');
      if (State.alerts.some(a => a.alertId === id)) id = Utils.genId('ALT');
      const alert = {
        alertId:id, sourceType:r.sourceType||'Manual Entry', timestamp:r.timestamp,
        alertType:r.alertType, description:r.description||'', sourceIp:r.sourceIp||'',
        destinationIp:r.destinationIp||'', domain:r.domain||'', url:r.url||'', port:r.port||'',
        malwareName:r.malwareName||'', fileHash:r.fileHash||'', threatCategory:r.threatCategory||'',
        severity:r.severity, confidence:parseInt(r.confidence)||50,
        assetName:r.assetName||'', assetCriticality:r.assetCriticality||'Medium',
        mitreTactic:r.mitreTactic||'', mitreTechniqueId:r.mitreTechniqueId||'', mitreTechniqueName:r.mitreTechniqueName||'',
        analystName:r.analystName||'', notes:r.notes||'', status:r.status||'New',
        createdAt:r.createdAt||Utils.nowIso(),
        country:r.country||'', city:r.city||'',
        lat: (r.lat !== undefined && r.lat !== '') ? parseFloat(r.lat) : null,
        lng: (r.lng !== undefined && r.lng !== '') ? parseFloat(r.lng) : null,
      };
      const res = RiskEngine.calc(alert, 0);
      alert.riskScore = res.score; alert.priority = res.priority;
      State.alerts.push(alert);
      added++;
    });
    Store.save(KEYS.ALERTS, State.alerts);
    Correlator.run();
    updateThreatMap();
    this.cancel();
    const im = document.getElementById('importMessages');
    if (im) im.innerHTML = `<div class="alert-success-tg">✓ Imported ${added} alert(s). Skipped ${skipped} invalid record(s).</div>`;
    Toast.show(`${added} alert(s) imported.`, 'success');
    const cb = document.getElementById('alertCountBadge');
    if (cb) cb.textContent = State.alerts.length + ' Alerts';
  },
  cancel() {
    State.pendingImport = [];
    document.getElementById('importPreview')?.classList.add('d-none');
  },
  downloadSample() {
    const a = document.createElement('a');
    a.href = 'assets/sample-alerts.json';
    a.download = 'sample-alerts.json';
    a.click();
  },
};

/* =========================================================
   CORRELATED INCIDENTS PAGE
   ========================================================= */
const CorrelatedPage = {
  render() {
    const list = document.getElementById('incidentsList');
    if (!list) return;
    if (!State.incidents.length) {
      list.innerHTML = `<div class="text-center text-muted py-5"><i class="bi bi-diagram-3 display-4 d-block mb-2"></i>No correlated incidents. Add more alerts or adjust correlation settings.</div>`;
      return;
    }
    list.innerHTML = State.incidents.map(inc => this._card(inc)).join('');
  },
  _card(inc) {
    const indHtml = (inc.indicators||[]).slice(0,6).map(ind =>
      `<span class="indicator-pill">${Utils.esc(ind.type)}: ${Utils.esc(Utils.trunc(ind.value,25))}</span>`
    ).join('');
    const alertHtml = inc.alertIds.map(id =>
      `<span class="alert-id-pill" style="cursor:pointer" onclick="TG.openAlertDetail('${Utils.esc(id)}')">${Utils.esc(id)}</span>`
    ).join('');
    return `
    <div class="incident-card">
      <div class="incident-header">
        <span class="incident-id">${Utils.esc(inc.incidentId)}</span>
        <span class="pri-badge ${Utils.priCls(inc.priority)}">${Utils.esc(inc.priority)}</span>
        <span class="status-badge ${Utils.statusCls(inc.status)}">${Utils.esc(inc.status||'Active')}</span>
        <span class="text-muted small">${inc.alertIds.length} alerts — Risk: ${inc.riskScore}</span>
        <button class="btn btn-sm btn-outline-accent ms-auto" onclick="TG.openIncidentDetail('${Utils.esc(inc.incidentId)}')"><i class="bi bi-eye"></i> Detail</button>
      </div>
      <div class="incident-body">
        <div class="mb-2"><span class="text-muted small">Shared Indicators: </span>${indHtml||'<span class="text-muted small">—</span>'}</div>
        <div><span class="text-muted small">Alerts: </span>${alertHtml}</div>
      </div>
    </div>`;
  },
};

/* =========================================================
   INCIDENT MANAGEMENT PAGE
   ========================================================= */
const IncidentMgmt = {
  render() {
    const list = document.getElementById('incidentMgmtList');
    if (!list) return;
    let incs = [...State.incidents];
    const search = (document.getElementById('incidentSearch')?.value || '').toLowerCase();
    const status = document.getElementById('incidentFilterStatus')?.value  || '';
    const pri    = document.getElementById('incidentFilterPriority')?.value || '';
    if (search) incs = incs.filter(i => i.incidentId.toLowerCase().includes(search) || (i.indicators||[]).some(x=>x.value.toLowerCase().includes(search)));
    if (status) incs = incs.filter(i => i.status   === status);
    if (pri)    incs = incs.filter(i => i.priority  === pri);
    if (!incs.length) {
      list.innerHTML = `<div class="text-center text-muted py-5"><i class="bi bi-clipboard2-pulse display-4 d-block mb-2"></i>No incidents match filters.</div>`;
      return;
    }
    list.innerHTML = incs.map(inc => {
      const alertHtml = inc.alertIds.map(id => `<span class="alert-id-pill">${Utils.esc(id)}</span>`).join('');
      return `
      <div class="incident-card">
        <div class="incident-header">
          <span class="incident-id">${Utils.esc(inc.incidentId)}</span>
          <span class="pri-badge ${Utils.priCls(inc.priority)}">${Utils.esc(inc.priority)}</span>
          <span class="status-badge ${Utils.statusCls(inc.status)}">${Utils.esc(inc.status||'Active')}</span>
          <span class="text-muted small">Risk: ${inc.riskScore}</span>
          <button class="btn btn-sm btn-outline-accent ms-auto" onclick="TG.openIncidentDetail('${Utils.esc(inc.incidentId)}')"><i class="bi bi-eye"></i> Manage</button>
        </div>
        <div class="incident-body">
          <div class="d-flex gap-2 flex-wrap mb-2">
            ${['Active','Investigating','Confirmed','Resolved','False Positive'].map(s =>
              `<button class="btn btn-sm ${inc.status===s?'btn-primary-tg':'btn-outline-tg'} py-0" onclick="TG.setIncidentStatus('${Utils.esc(inc.incidentId)}','${s}')">${s}</button>`
            ).join('')}
          </div>
          <div class="text-muted small">Alerts: ${alertHtml}</div>
          ${inc.notes ? `<div class="mt-2 text-muted small"><i class="bi bi-sticky"></i> ${Utils.esc(inc.notes)}</div>` : ''}
        </div>
      </div>`;
    }).join('');
  },
};

/* =========================================================
   INCIDENT DETAIL MODAL
   ========================================================= */
const IncidentDetail = {
  open(incidentId) {
    const inc = State.incidents.find(i => i.incidentId === incidentId);
    if (!inc) return;
    const alerts   = State.alerts.filter(a => inc.alertIds.includes(a.alertId));
    const titleEl  = document.getElementById('incidentModalTitle');
    const bodyEl   = document.getElementById('incidentModalBody');
    if (titleEl) titleEl.textContent = inc.incidentId;
    if (bodyEl) {
      const indHtml = (inc.indicators||[]).map(i =>
        `<span class="indicator-pill">${Utils.esc(i.type)}: ${Utils.esc(i.value)}</span>`
      ).join('');
      const alertRows = alerts.map(a => `
        <tr>
          <td class="mono text-accent" style="cursor:pointer" onclick="TG.openAlertDetail('${Utils.esc(a.alertId)}')">${Utils.esc(a.alertId)}</td>
          <td>${Utils.esc(a.alertType||'')}</td>
          <td><span class="sev-badge ${Utils.sevCls(a.severity)}">${Utils.esc(a.severity||'')}</span></td>
          <td><span class="status-badge ${Utils.statusCls(a.status)}">${Utils.esc(a.status||'')}</span></td>
          <td>${Utils.fmtDate(a.timestamp)}</td>
        </tr>`).join('');
      bodyEl.innerHTML = `
        <div class="modal-detail-grid mb-3">
          <div class="detail-item"><div class="detail-label">Incident ID</div><div class="detail-value text-accent">${Utils.esc(inc.incidentId)}</div></div>
          <div class="detail-item"><div class="detail-label">Priority</div><div class="detail-value"><span class="pri-badge ${Utils.priCls(inc.priority)}">${Utils.esc(inc.priority)}</span></div></div>
          <div class="detail-item"><div class="detail-label">Status</div><div class="detail-value"><span class="status-badge ${Utils.statusCls(inc.status)}">${Utils.esc(inc.status||'')}</span></div></div>
          <div class="detail-item"><div class="detail-label">Risk Score</div><div class="detail-value">${inc.riskScore}</div></div>
          <div class="detail-item"><div class="detail-label">Created</div><div class="detail-value">${Utils.fmtDate(inc.createdAt)}</div></div>
          <div class="detail-item"><div class="detail-label">Alert Count</div><div class="detail-value">${inc.alertIds.length}</div></div>
        </div>
        <div class="mb-3"><div class="detail-label mb-1">Shared Indicators</div>${indHtml||'<span class="text-muted">—</span>'}</div>
        <hr class="tg-divider"/>
        <div class="mb-3">
          <div class="detail-label mb-2">Update Status</div>
          <div class="d-flex gap-2 flex-wrap">
            ${['Active','Investigating','Confirmed','Resolved','False Positive'].map(s =>
              `<button class="btn btn-sm ${inc.status===s?'btn-primary-tg':'btn-outline-tg'}" onclick="TG.setIncidentStatus('${Utils.esc(inc.incidentId)}','${s}')">${s}</button>`
            ).join('')}
          </div>
        </div>
        <div class="mb-3">
          <div class="detail-label mb-1">Notes</div>
          <textarea id="incNoteArea" class="form-control tg-input" rows="2">${Utils.esc(inc.notes||'')}</textarea>
          <button class="btn btn-sm btn-primary-tg mt-2" onclick="TG.saveIncidentNotes('${Utils.esc(inc.incidentId)}')">Save Notes</button>
        </div>
        <hr class="tg-divider"/>
        <div class="detail-label mb-2">Correlated Alerts</div>
        <div class="table-responsive">
          <table class="table tg-table">
            <thead><tr><th>ID</th><th>Type</th><th>Severity</th><th>Status</th><th>Timestamp</th></tr></thead>
            <tbody>${alertRows}</tbody>
          </table>
        </div>`;
    }
    const blufBtn = document.getElementById('btnIncidentBluf');
    if (blufBtn) blufBtn.onclick = () => {
      bootstrap.Modal.getInstance(document.getElementById('incidentModal'))?.hide();
      TG.generateBlufFromIncident(incidentId);
    };
    new bootstrap.Modal(document.getElementById('incidentModal')).show();
  },
};

/* =========================================================
   FALSE-POSITIVE ANALYSIS
   ========================================================= */
const FPAnalysis = {
  render() {
    const list = document.getElementById('fpList');
    if (!list) return;
    let alerts = [...State.alerts];
    const f = State.fpFilter;
    if (f === 'fp')   alerts = alerts.filter(a => Utils.classify(a.riskScore||0,a.status).cls === 'cls-benign');
    if (f === 'mal')  alerts = alerts.filter(a => Utils.classify(a.riskScore||0,a.status).cls === 'cls-malicious');
    if (f === 'susp') alerts = alerts.filter(a => Utils.classify(a.riskScore||0,a.status).cls === 'cls-suspicious');
    if (!alerts.length) {
      list.innerHTML = '<div class="text-center text-muted py-5">No alerts match the selected filter.</div>';
      return;
    }
    list.innerHTML = `
    <div class="table-responsive">
      <table class="table tg-table">
        <thead><tr><th>Alert ID</th><th>Type</th><th>Severity</th><th>Confidence</th><th>Risk Score</th><th>Classification</th><th>Status</th><th>Indicators</th><th>Actions</th></tr></thead>
        <tbody>
          ${alerts.map(a => {
            const cl = Utils.classify(a.riskScore||0, a.status);
            return `<tr>
              <td class="mono text-accent" style="cursor:pointer" onclick="TG.openAlertDetail('${Utils.esc(a.alertId)}')">${Utils.esc(a.alertId)}</td>
              <td>${Utils.esc(Utils.trunc(a.alertType,28))}</td>
              <td><span class="sev-badge ${Utils.sevCls(a.severity)}">${Utils.esc(a.severity||'')}</span></td>
              <td>${a.confidence||0}%</td>
              <td>${Utils.riskBar(a.riskScore||0)} <small>${a.riskScore||0}</small></td>
              <td><span class="${cl.cls}">${cl.label}</span></td>
              <td><span class="status-badge ${Utils.statusCls(a.status)}">${Utils.esc(a.status||'')}</span></td>
              <td class="text-muted small">${this._reasons(a)}</td>
              <td><button class="btn btn-sm btn-outline-tg py-0" onclick="TG.setAlertStatus('${Utils.esc(a.alertId)}','False Positive')">Mark FP</button></td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>`;
  },
  _reasons(a) {
    const r = [];
    if ((a.confidence||100) < 30)                                       r.push('Low confidence');
    if (a.status === 'False Positive')                                   r.push('Analyst: FP');
    if (a.severity === 'Low')                                            r.push('Low severity');
    if ((a.riskScore||100) < 20)                                         r.push('Low risk score');
    if ((a.notes||'').toLowerCase().includes('false positive'))          r.push('Notes: FP');
    if ((a.notes||'').toLowerCase().includes('scanner'))                 r.push('Scanner noise');
    return r.length ? r.join(', ') : '—';
  },
};

/* =========================================================
   MITRE ATT&CK PAGE
   ========================================================= */
const MitrePage = {
  render() {
    const search = State.mitreSearch.toLowerCase();
    const tactic = State.mitreTactic;
    const techMap = {};
    State.alerts.forEach(a => {
      if (!a.mitreTechniqueId) return;
      if (!techMap[a.mitreTechniqueId]) techMap[a.mitreTechniqueId] = { id:a.mitreTechniqueId, name:a.mitreTechniqueName||'', tactic:a.mitreTactic||'', alerts:[], confidence:0 };
      techMap[a.mitreTechniqueId].alerts.push(a.alertId);
    });
    Object.values(techMap).forEach(t => {
      const confs = State.alerts.filter(a => a.mitreTechniqueId === t.id).map(a => parseInt(a.confidence)||50);
      t.confidence = confs.length ? Math.round(confs.reduce((s,v)=>s+v,0)/confs.length) : 0;
    });

    let techs = Object.values(techMap);
    if (search) techs = techs.filter(t => t.id.toLowerCase().includes(search) || t.name.toLowerCase().includes(search));
    if (tactic) techs = techs.filter(t => t.tactic === tactic);

    const tactics = [...new Set(Object.values(techMap).map(t => t.tactic).filter(Boolean))];
    const ov = document.getElementById('mitreOverview');
    if (ov) {
      ov.innerHTML = tactics.map(tac => {
        const cnt = Object.values(techMap).filter(t => t.tactic === tac).length;
        return `<div class="col-6 col-md-3 col-lg-2">
          <div class="mitre-tactic-card">
            <div class="mitre-tactic-name">${Utils.esc(tac)}</div>
            <div class="mitre-count">${cnt}</div>
            <div class="text-muted small">technique${cnt!==1?'s':''}</div>
          </div>
        </div>`;
      }).join('');
    }

    const tbody = document.getElementById('mitreTbody');
    if (!tbody) return;
    if (!techs.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">No techniques found.</td></tr>';
      return;
    }
    tbody.innerHTML = techs.sort((a,b) => b.alerts.length - a.alerts.length).map(t => {
      const str = t.alerts.length >= 3 ? 'Strong' : t.alerts.length >= 2 ? 'Moderate' : 'Weak';
      const cls = t.alerts.length >= 3 ? 'cls-malicious' : t.alerts.length >= 2 ? 'cls-suspicious' : 'cls-inconclusive';
      return `<tr>
        <td class="mono text-accent">${Utils.esc(t.id)}</td>
        <td>${Utils.esc(t.name)}</td>
        <td class="text-muted">${Utils.esc(t.tactic)}</td>
        <td>${t.alerts.map(id => `<span class="alert-id-pill">${Utils.esc(id)}</span>`).join('')}</td>
        <td><span class="${cls}">${str}</span></td>
        <td>${t.confidence}%</td>
      </tr>`;
    }).join('');
  },
};

/* =========================================================
   THREAT MAP — Full implementation
   ========================================================= */
const ThreatMap = {
  _map: null,
  _cluster: null,
  _markers: [],        /* array of { leafletMarker, alertId } */
  _markerMap: {},      /* alertId → leafletMarker */
  _bound: false,
  _usedFallback: false,

  /* ── Public: required by spec ── */
  render() {
    this._bindControls();
    this.initializeThreatMap();
    /* If map was already inited, refresh data immediately */
    if (this._map) {
      this._populateFilterDropdowns();
      this.applyMapFilters();
    }
    /* If _doInit() is running asynchronously via rAF, it will call applyMapFilters itself */
  },

  initializeThreatMap() {
    /* Safe reinit if container was destroyed */
    const container = document.getElementById('threatMapEl');
    if (!container) return;
    if (this._map) {
      /* Map already exists — just invalidate size in case container was hidden */
      try {
        this._map.getContainer();
        /* Force Leaflet to recalculate container size after CSS transition */
        requestAnimationFrame(() => {
          requestAnimationFrame(() => { this._map.invalidateSize({ animate: false }); });
        });
        return;
      } catch(e) {
        /* Container was removed from DOM — full reinit needed */
        this._map = null; this._cluster = null; this._markers = []; this._markerMap = {};
      }
    }
    if (typeof L === 'undefined') {
      console.error('ThreatGuard: Leaflet (L) not loaded. Check CDN links.');
      return;
    }
    /* Leaflet REQUIRES the container to have pixel dimensions at init time.
       The page just became display:block but the browser may not have painted yet.
       Use double-rAF to ensure layout is complete before initializing. */
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        this._doInit();
      });
    });
  },

  _doInit() {
    const container = document.getElementById('threatMapEl');
    if (!container) return;
    const overlay = document.getElementById('mapLoadingOverlay');
    this._map = L.map('threatMapEl', {
      center: [20, 0], zoom: 2, minZoom: 1, maxZoom: 14,
      zoomControl: true,
    });

    /* ── EARTH / SATELLITE TILE THEME ──
       Primary:  ESRI World Imagery (true satellite photography)
       Fallback: CartoDB Dark Matter (dark vector, always works offline) */
    const esriSatellite = L.tileLayer(
      'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
        attribution: 'Tiles &copy; Esri &mdash; Source: Esri, USGS, NOAA',
        maxZoom: 19,
      }
    );
    const cartoLabels = L.tileLayer(
      'https://{s}.basemaps.cartocdn.com/dark_only_labels/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19,
        pane: 'shadowPane',  /* render labels above satellite tiles */
      }
    );
    const cartoDark = L.tileLayer(
      'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19,
      }
    );

    /* Add satellite layer; if tiles fail (offline), fallback to dark vector */
    esriSatellite.addTo(this._map);
    esriSatellite.on('tileerror', () => {
      if (!this._usedFallback) {
        this._usedFallback = true;
        this._map.removeLayer(esriSatellite);
        cartoDark.addTo(this._map);
      }
    });
    /* Add city/country label overlay on top of satellite */
    cartoLabels.addTo(this._map);

    if (typeof L.markerClusterGroup === 'function') {
      this._cluster = L.markerClusterGroup({ chunkedLoading: true, maxClusterRadius: 40 });
      this._map.addLayer(this._cluster);
    }
    /* Remove loading overlay */
    if (overlay) {
      overlay.classList.add('hidden');
      setTimeout(() => { try { overlay.remove(); } catch(e) {} }, 600);
    }
    /* Ensure map fills container after init */
    this._map.invalidateSize({ animate: false });
    /* Now place markers */
    this._populateFilterDropdowns();
    this.applyMapFilters();
  },

  updateThreatMap() {
    this.applyMapFilters();
  },

  clearThreatMap() {
    if (!this._map) return;
    this._markers.forEach(m => {
      if (this._cluster) this._cluster.removeLayer(m.leafletMarker);
      else this._map.removeLayer(m.leafletMarker);
    });
    this._markers = [];
    this._markerMap = {};
    this._renderTable([]);
    this._updateKpis([]);
    const emptyEl = document.getElementById('mapEmptyState');
    if (emptyEl) emptyEl.classList.remove('d-none');
  },

  createMapMarker(alert) {
    const loc = Utils.resolveLocation(alert);
    if (!loc) return null;
    const sevClass = ({ Critical:'marker-critical', High:'marker-high', Medium:'marker-medium', Low:'marker-low' })[alert.severity] || 'marker-low';
    const icon = L.divIcon({
      className: '',
      html: `<div class="tg-marker-icon ${sevClass}">${Utils.esc(alert.severity ? alert.severity[0] : '?')}</div>`,
      iconSize: [28, 28],
      iconAnchor: [14, 14],
    });
    const marker = L.marker([loc.lat, loc.lng], { icon });
    marker.bindPopup(`
      <div class="map-popup">
        <div class="map-popup-title">${Utils.esc(alert.alertId)} &#8212; ${Utils.esc(Utils.trunc(alert.alertType, 40))}</div>
        <div class="map-popup-row"><span class="map-popup-label">Type</span><span class="map-popup-value">${Utils.esc(alert.alertType||'—')}</span></div>
        <div class="map-popup-row"><span class="map-popup-label">Country</span><span class="map-popup-value">${Utils.esc(loc.country||'—')}</span></div>
        <div class="map-popup-row"><span class="map-popup-label">City</span><span class="map-popup-value">${Utils.esc(loc.city||'—')}</span></div>
        <div class="map-popup-row"><span class="map-popup-label">Source IP</span><span class="map-popup-value">${Utils.esc(alert.sourceIp||'—')}</span></div>
        <div class="map-popup-row"><span class="map-popup-label">Severity</span><span class="map-popup-value">${Utils.esc(alert.severity||'—')}</span></div>
        <div class="map-popup-row"><span class="map-popup-label">Risk Score</span><span class="map-popup-value">${alert.riskScore||0}/100</span></div>
        <div class="map-popup-row"><span class="map-popup-label">MITRE</span><span class="map-popup-value">${Utils.esc(alert.mitreTechniqueId||'—')}</span></div>
        <div class="map-popup-row"><span class="map-popup-label">Timestamp</span><span class="map-popup-value">${Utils.esc(Utils.fmtDate(alert.timestamp))}</span></div>
        <button class="map-popup-btn" onclick="TG.openAlertDetail('${Utils.esc(alert.alertId)}')">View Full Detail</button>
      </div>`, { maxWidth: 300 });
    return { leafletMarker: marker, alertId: alert.alertId, loc };
  },

  applyMapFilters() {
    if (!this._map) return;
    const sev     = document.getElementById('mapFilterSeverity')?.value  || '';
    const country = document.getElementById('mapFilterCountry')?.value   || '';
    const source  = document.getElementById('mapFilterSource')?.value    || '';
    const mitre   = document.getElementById('mapFilterMitre')?.value     || '';
    const risk    = document.getElementById('mapFilterRisk')?.value      || '';
    const from    = document.getElementById('mapFilterDateFrom')?.value  || '';
    const to      = document.getElementById('mapFilterDateTo')?.value    || '';

    /* All alerts that have resolvable location */
    let alerts = State.alerts.filter(a => Utils.resolveLocation(a) !== null);
    if (sev)     alerts = alerts.filter(a => a.severity   === sev);
    if (country) alerts = alerts.filter(a => (a.country||'') === country);
    if (source)  alerts = alerts.filter(a => a.sourceType === source);
    if (mitre)   alerts = alerts.filter(a => a.mitreTechniqueId === mitre);
    if (risk)    alerts = alerts.filter(a => (a.riskScore||0) >= parseInt(risk));
    if (from)    alerts = alerts.filter(a => (a.timestamp||'') >= from);
    if (to)      alerts = alerts.filter(a => (a.timestamp||'').slice(0,10) <= to);

    this._updateKpis(alerts);
    this._placeMarkers(alerts);
    this._renderTable(alerts);
  },

  focusAlertOnMap(alertId) {
    const mo = this._markerMap[alertId];
    if (!mo || !this._map) return;
    this._map.setView([mo.loc.lat, mo.loc.lng], 6, { animate: true });
    mo.leafletMarker.openPopup();
    /* Highlight table row */
    document.querySelectorAll('#mapAlertsTbody tr').forEach(tr => {
      tr.classList.remove('map-focus-pulse');
      if (tr.dataset.alertId === alertId) tr.classList.add('map-focus-pulse');
    });
  },

  _updateKpis(alerts) {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('mapKpiTotal',     alerts.length);
    set('mapKpiCritical',  alerts.filter(a => a.severity === 'Critical').length);
    set('mapKpiHigh',      alerts.filter(a => a.severity === 'High').length);
    set('mapKpiCountries', new Set(alerts.map(a => (Utils.resolveLocation(a)||{}).country).filter(Boolean)).size);
    set('mapKpiMaxRisk',   alerts.length ? Math.max(...alerts.map(a => a.riskScore||0)) : 0);
  },

  _placeMarkers(alerts) {
    if (!this._map) return;
    /* Remove old */
    this._markers.forEach(m => {
      if (this._cluster) this._cluster.removeLayer(m.leafletMarker);
      else this._map.removeLayer(m.leafletMarker);
    });
    this._markers = [];
    this._markerMap = {};

    const emptyEl = document.getElementById('mapEmptyState');
    if (!alerts.length) {
      if (emptyEl) emptyEl.classList.remove('d-none');
      return;
    }
    if (emptyEl) emptyEl.classList.add('d-none');

    const target = this._cluster || this._map;
    alerts.forEach(a => {
      const mo = this.createMapMarker(a);
      if (!mo) return;
      target.addLayer(mo.leafletMarker);
      this._markers.push(mo);
      this._markerMap[a.alertId] = mo;
    });
  },

  _renderTable(alerts) {
    const tbody = document.getElementById('mapAlertsTbody');
    const count = document.getElementById('mapTableCount');
    if (count) count.textContent = alerts.length;
    if (!tbody) return;
    if (!alerts.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-3">No mapped alerts match filters.</td></tr>';
      return;
    }
    tbody.innerHTML = alerts.map(a => {
      const loc = Utils.resolveLocation(a) || {};
      return `<tr data-alert-id="${Utils.esc(a.alertId)}">
        <td class="mono text-accent" style="cursor:pointer" onclick="TG.openAlertDetail('${Utils.esc(a.alertId)}')">${Utils.esc(a.alertId)}</td>
        <td>${Utils.esc(loc.country||a.country||'—')}</td>
        <td>${Utils.esc(loc.city||a.city||'—')}</td>
        <td><span class="sev-badge ${Utils.sevCls(a.severity)}">${Utils.esc(a.severity||'—')}</span></td>
        <td>${Utils.riskBar(a.riskScore||0)} <small>${a.riskScore||0}</small></td>
        <td class="text-muted">${Utils.esc(a.sourceType||'—')}</td>
        <td class="text-muted">${Utils.fmtDate(a.timestamp)}</td>
        <td class="text-muted mono">${Utils.esc(a.mitreTechniqueId||'—')}</td>
        <td><button class="btn btn-sm btn-outline-accent py-0 px-1" onclick="TG.focusAlertOnMap('${Utils.esc(a.alertId)}')"><i class="bi bi-crosshair"></i> Focus</button></td>
      </tr>`;
    }).join('');
  },

  _populateFilterDropdowns() {
    /* Populate countries from all alerts with resolvable locations */
    const mapped = State.alerts.filter(a => Utils.resolveLocation(a) !== null);
    const countries = [...new Set(mapped.map(a => {
      const loc = Utils.resolveLocation(a); return loc ? loc.country : null;
    }).filter(Boolean))].sort();
    const cSel = document.getElementById('mapFilterCountry');
    if (cSel) {
      cSel.innerHTML = '<option value="">All Countries</option>' +
        countries.map(c => `<option value="${Utils.esc(c)}">${Utils.esc(c)}</option>`).join('');
    }
    const mitres = [...new Set(mapped.map(a => a.mitreTechniqueId).filter(Boolean))].sort();
    const mSel = document.getElementById('mapFilterMitre');
    if (mSel) {
      mSel.innerHTML = '<option value="">All MITRE Techniques</option>' +
        mitres.map(m => `<option value="${Utils.esc(m)}">${Utils.esc(m)}</option>`).join('');
    }
  },

  _bindControls() {
    if (this._bound) return;
    this._bound = true;
    const refresh = () => { this._populateFilterDropdowns(); this.applyMapFilters(); };
    ['mapFilterSeverity','mapFilterCountry','mapFilterSource','mapFilterMitre',
     'mapFilterRisk','mapFilterDateFrom','mapFilterDateTo'].forEach(id => {
      document.getElementById(id)?.addEventListener('change', refresh);
      document.getElementById(id)?.addEventListener('input',  refresh);
    });
    document.getElementById('btnMapClearFilters')?.addEventListener('click', () => {
      ['mapFilterSeverity','mapFilterCountry','mapFilterSource','mapFilterMitre',
       'mapFilterRisk','mapFilterDateFrom','mapFilterDateTo'].forEach(id => {
        const el = document.getElementById(id); if (el) el.value = '';
      });
      refresh();
    });
    document.getElementById('btnMapRefresh')?.addEventListener('click', refresh);
    document.getElementById('btnMapFitAll')?.addEventListener('click', () => {
      if (!this._map || !this._markers.length) return;
      const group = L.featureGroup(this._markers.map(m => m.leafletMarker));
      this._map.fitBounds(group.getBounds().pad(0.15));
    });
    document.getElementById('btnMapClear')?.addEventListener('click', () => this.clearThreatMap());
  },
};

/* ── Top-level wrappers required by spec ── */
function initializeThreatMap() { ThreatMap.initializeThreatMap(); }
function updateThreatMap()     { if (Nav.current === 'threat-map') ThreatMap.updateThreatMap(); }
function applyMapFilters()     { ThreatMap.applyMapFilters(); }
function focusAlertOnMap(id)   { ThreatMap.focusAlertOnMap(id); }
function clearThreatMap()      { ThreatMap.clearThreatMap(); }


/* =========================================================
   BLUF REPORT PAGE
   ========================================================= */
const BlufPage = {
  render() { this.populateSelector(); this.renderSavedList(); },
  populateSelector() {
    const sel = document.getElementById('blufSelector');
    if (!sel) return;
    const aOpts = State.alerts.map(a =>
      `<option value="alert:${Utils.esc(a.alertId)}">[Alert] ${Utils.esc(a.alertId)} — ${Utils.esc(Utils.trunc(a.alertType,35))}</option>`
    ).join('');
    const iOpts = State.incidents.map(i =>
      `<option value="incident:${Utils.esc(i.incidentId)}">[Incident] ${Utils.esc(i.incidentId)} — ${i.alertIds.length} alerts</option>`
    ).join('');
    sel.innerHTML = `<option value="">— Select —</option>${aOpts}${iOpts}`;
  },
  renderSavedList() {
    const div = document.getElementById('blufReportList');
    if (!div) return;
    if (!State.reports.length) { div.innerHTML = '<p class="text-muted small">No saved reports yet.</p>'; return; }
    div.innerHTML = [...State.reports].reverse().map(r => `
      <div class="bluf-report-item" onclick="TG.loadBlufReport('${Utils.esc(r.reportId)}')">
        <div class="report-id">${Utils.esc(r.reportId)}</div>
        <div class="report-meta">${Utils.esc(Utils.trunc(r.title,45))} · ${Utils.fmtDateShort(r.createdAt)}</div>
      </div>`).join('');
  },
  generate(type, id) {
    if (type === 'alert') {
      const a = State.alerts.find(x => x.alertId === id);
      if (!a) { Toast.show('Alert not found.', 'error'); return; }
      State.currentBluf = this._fromAlert(a);
    } else {
      const inc = State.incidents.find(x => x.incidentId === id);
      if (!inc) { Toast.show('Incident not found.', 'error'); return; }
      State.currentBluf = this._fromIncident(inc);
    }
    this.display(State.currentBluf);
  },
  _fromAlert(a) {
    const inc = State.incidents.find(i => i.alertIds?.includes(a.alertId));
    const cl  = Utils.classify(a.riskScore||0, a.status);
    const loc = Utils.resolveLocation(a);
    return {
      reportId: Utils.genRptId(), title:`${a.alertId} — ${a.alertType}`, createdAt:Utils.nowIso(),
      sourceType:'alert', sourceId:a.alertId,
      bluf:`[FICTIONAL] ${a.alertType} detected by ${a.sourceType}. Risk: ${a.riskScore||0}/100 (${a.priority}). Classification: ${cl.label}. Immediate analyst review recommended.`,
      threatAssessment:`${a.description||'No description.'} Automated classification: ${cl.label}. Confidence: ${a.confidence||0}%.`,
      keyEvidence:[
        a.sourceIp      ? `Source IP: ${a.sourceIp}`    : null,
        a.destinationIp ? `Dest IP: ${a.destinationIp}` : null,
        a.domain        ? `Domain: ${a.domain}`          : null,
        a.fileHash      ? `File Hash: ${a.fileHash}`     : null,
        a.malwareName   ? `Malware: ${a.malwareName}`    : null,
        a.url           ? `URL: ${a.url}`                : null,
        loc             ? `Location: ${loc.city}, ${loc.country}` : null,
      ].filter(Boolean),
      affectedAssets:`${a.assetName||'Unknown'} (Criticality: ${a.assetCriticality||'Unknown'})`,
      riskScore:a.riskScore||0, priority:a.priority,
      mitreTactic:a.mitreTactic||'—', mitreTechId:a.mitreTechniqueId||'—', mitreTechName:a.mitreTechniqueName||'—',
      gaps:'Full forensic investigation required. Attribution not confirmed. Impact scope unknown.',
      recommendations:[
        'Isolate affected asset and preserve system logs.',
        'Block identified IOCs at network perimeter.',
        'Conduct memory forensics on affected endpoints.',
        'Review authentication logs for lateral movement indicators.',
        'Notify relevant stakeholders per incident response plan.',
      ],
      confidence:`${a.confidence||50}% — Single automated detection. Analyst verification required.`,
      analyst:a.analystName||'Automated', incident:inc ? inc.incidentId : null,
    };
  },
  _fromIncident(inc) {
    const alerts = State.alerts.filter(a => inc.alertIds.includes(a.alertId));
    const types  = [...new Set(alerts.map(a => a.alertType).filter(Boolean))].join(', ');
    const assets = [...new Set(alerts.map(a => a.assetName).filter(Boolean))];
    const tactics= [...new Set(alerts.map(a => a.mitreTactic).filter(Boolean))].join(', ');
    const conf   = alerts.length ? Math.round(alerts.reduce((s,a)=>s+(parseInt(a.confidence)||50),0)/alerts.length) : 50;
    return {
      reportId: Utils.genRptId(), title:`${inc.incidentId} — Correlated Incident`, createdAt:Utils.nowIso(),
      sourceType:'incident', sourceId:inc.incidentId,
      bluf:`[FICTIONAL] Correlated incident: ${alerts.length} alert(s). Types: ${types}. Max Risk: ${inc.riskScore}/100 (${inc.priority}). Multi-stage attack pattern suspected.`,
      threatAssessment:`Multiple correlated alerts sharing common indicators. Types: ${types}. Tactics: ${tactics||'—'}.`,
      keyEvidence:(inc.indicators||[]).slice(0,5).map(i => `${i.type}: ${i.value}`),
      affectedAssets:assets.join(', ')||'—', riskScore:inc.riskScore, priority:inc.priority,
      mitreTactic:tactics||'—',
      mitreTechId:[...new Set(alerts.map(a=>a.mitreTechniqueId).filter(Boolean))].join(', ')||'—',
      mitreTechName:[...new Set(alerts.map(a=>a.mitreTechniqueName).filter(Boolean))].join(', ')||'—',
      gaps:'Full scope of compromise unknown. Attribution requires investigation. Lateral movement extent unconfirmed.',
      recommendations:[
        'Immediately isolate all affected assets.',
        'Block all shared IOCs at network and host level.',
        'Conduct full incident response per organisation playbook.',
        'Preserve all logs from affected systems.',
        'Escalate to senior analyst or CISO as appropriate.',
      ],
      confidence:`${conf}% — Multi-alert correlation increases confidence. Full analyst review required.`,
      analyst:alerts[0]?.analystName||'Automated', incident:inc.incidentId,
    };
  },
  display(r) {
    const content = document.getElementById('blufContent');
    const actions = document.getElementById('blufActions');
    if (!content) return;
    const evList  = (r.keyEvidence||[]).map(e => `<li>${Utils.esc(e)}</li>`).join('');
    const recList = (r.recommendations||[]).map(e => `<li>${Utils.esc(e)}</li>`).join('');
    content.innerHTML = `
      <div class="bluf-disclaimer">⚠ PROTOTYPE — FICTIONAL DATA — All assessments require qualified analyst review before any action.</div>
      <div class="bluf-report">
        <div class="bluf-bottom-line"><strong>BOTTOM LINE UP FRONT:</strong> ${Utils.esc(r.bluf)}</div>
        <div class="bluf-section"><div class="bluf-section-title">1. Threat Assessment</div><p>${Utils.esc(r.threatAssessment)}</p></div>
        <div class="bluf-section"><div class="bluf-section-title">2. Key Evidence (IOCs)</div>${evList?`<ul>${evList}</ul>`:'<p class="text-muted">No specific IOCs extracted.</p>'}</div>
        <div class="bluf-section"><div class="bluf-section-title">3. Affected Assets</div><p>${Utils.esc(r.affectedAssets)}</p></div>
        <div class="bluf-section"><div class="bluf-section-title">4. Risk Score &amp; Priority</div><p>Risk: <strong>${r.riskScore}/100</strong> | Priority: <span class="pri-badge ${Utils.priCls(r.priority)}">${Utils.esc(r.priority)}</span></p></div>
        <div class="bluf-section"><div class="bluf-section-title">5. MITRE ATT&amp;CK Mapping</div><p>Tactic: <strong>${Utils.esc(r.mitreTactic)}</strong> | Technique: <strong>${Utils.esc(r.mitreTechId)}</strong> — ${Utils.esc(r.mitreTechName)}</p></div>
        <div class="bluf-section"><div class="bluf-section-title">6. Intelligence Gaps</div><p>${Utils.esc(r.gaps)}</p></div>
        <div class="bluf-section"><div class="bluf-section-title">7. Recommended Defensive Investigation Steps</div><ol>${recList}</ol></div>
        <div class="bluf-section"><div class="bluf-section-title">8. Confidence Level</div><p>${Utils.esc(r.confidence)}</p></div>
        <div class="bluf-section"><div class="bluf-section-title">9. Report Metadata</div><p>Report ID: <strong>${Utils.esc(r.reportId)}</strong> | Generated: ${Utils.esc(r.createdAt)} | Analyst: ${Utils.esc(r.analyst)}</p></div>
      </div>`;
    if (actions) { actions.classList.remove('d-none'); actions.style.display = ''; }
  },
  save() {
    if (!State.currentBluf) { Toast.show('No report to save.', 'warn'); return; }
    const idx = State.reports.findIndex(r => r.reportId === State.currentBluf.reportId);
    if (idx >= 0) State.reports[idx] = State.currentBluf;
    else State.reports.push(State.currentBluf);
    Store.save(KEYS.REPORTS, State.reports);
    this.renderSavedList();
    Toast.show(`Report ${State.currentBluf.reportId} saved.`, 'success');
  },
  loadReport(reportId) {
    const r = State.reports.find(x => x.reportId === reportId);
    if (!r) return;
    State.currentBluf = r;
    this.display(r);
    Nav.go('bluf');
  },
  copy() {
    const c = document.getElementById('blufContent');
    if (c) navigator.clipboard?.writeText(c.innerText).then(() => Toast.show('Copied to clipboard.', 'success'));
  },
  download() {
    if (!State.currentBluf) return;
    const text = document.getElementById('blufContent')?.innerText || '';
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type:'text/plain' }));
    a.download = `${State.currentBluf.reportId}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  },
  print() { window.print(); },
};

/* =========================================================
   EXPORT PAGE
   ========================================================= */
const ExportPage = {
  render() {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('expAlerts',    State.alerts.length);
    set('expIncidents', State.incidents.length);
    set('expReports',   State.reports.length);
    set('expMitre',     new Set(State.alerts.map(a => a.mitreTechniqueId).filter(Boolean)).size);
    this.renderLog();
  },
  logExport(name) {
    const log = Store.load(KEYS.EXPLOG, []);
    log.unshift({ name, timestamp: Utils.nowIso() });
    if (log.length > 20) log.pop();
    Store.save(KEYS.EXPLOG, log);
    this.renderLog();
  },
  renderLog() {
    const div = document.getElementById('exportLog');
    if (!div) return;
    const log = Store.load(KEYS.EXPLOG, []);
    if (!log.length) { div.innerHTML = '<p class="text-muted">No exports yet.</p>'; return; }
    div.innerHTML = log.map(e =>
      `<div class="text-muted mb-1"><i class="bi bi-download text-accent"></i> ${Utils.esc(e.name)} <span class="ms-2">${Utils.fmtDate(e.timestamp)}</span></div>`
    ).join('');
  },
  _alertRows() {
    const fields = ['alertId','sourceType','timestamp','alertType','description','sourceIp','destinationIp',
      'domain','url','port','malwareName','fileHash','threatCategory','severity','confidence',
      'assetName','assetCriticality','mitreTactic','mitreTechniqueId','mitreTechniqueName',
      'analystName','status','riskScore','priority','notes','createdAt','country','city','lat','lng'];
    return [fields, ...State.alerts.map(a => fields.map(f => a[f] ?? ''))];
  },
  _incidentRows() {
    return [
      ['incidentId','status','priority','riskScore','alertIds','indicators','notes','createdAt','updatedAt'],
      ...State.incidents.map(i => [
        i.incidentId, i.status, i.priority, i.riskScore,
        (i.alertIds||[]).join('; '),
        (i.indicators||[]).map(x=>x.type+':'+x.value).join('; '),
        i.notes||'', i.createdAt||'', i.updatedAt||'',
      ]),
    ];
  },
  _reportRows() {
    return [
      ['reportId','title','createdAt','sourceType','sourceId','bluf','affectedAssets','riskScore','priority','analyst'],
      ...State.reports.map(r => [r.reportId,r.title,r.createdAt,r.sourceType,r.sourceId,r.bluf,r.affectedAssets||'',r.riskScore||'',r.priority||'',r.analyst]),
    ];
  },
  _mitreRows() {
    const map = {};
    State.alerts.forEach(a => {
      if (!a.mitreTechniqueId) return;
      if (!map[a.mitreTechniqueId]) map[a.mitreTechniqueId] = { id:a.mitreTechniqueId, name:a.mitreTechniqueName, tactic:a.mitreTactic, alerts:[], conf:[] };
      map[a.mitreTechniqueId].alerts.push(a.alertId);
      map[a.mitreTechniqueId].conf.push(parseInt(a.confidence)||50);
    });
    return [
      ['techniqueId','techniqueName','tactic','alertCount','alerts','avgConfidence'],
      ...Object.values(map).map(t => [
        t.id, t.name, t.tactic, t.alerts.length,
        t.alerts.join('; '),
        Math.round(t.conf.reduce((s,v)=>s+v,0)/t.conf.length),
      ]),
    ];
  },
  exportExcel(sheets = 'all') {
    if (!State.alerts.length) { Toast.show('No data to export.', 'warn'); return; }
    if (!window.XLSX) { Toast.show('SheetJS library not loaded.', 'error'); return; }
    const wb = XLSX.utils.book_new();
    if (sheets === 'all' || sheets === 'alerts') XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(this._alertRows()), 'Alerts');
    if (sheets === 'all') {
      XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(this._incidentRows()), 'Incidents');
      XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(this._reportRows()), 'BLUF Reports');
      XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(this._mitreRows()), 'MITRE Mappings');
    }
    const d     = new Date().toISOString().slice(0,10);
    const fname = sheets === 'all' ? `ThreatGuard_Export_${d}.xlsx` : `ThreatGuard_Alerts_${d}.xlsx`;
    XLSX.writeFile(wb, fname);
    this.logExport(fname);
    Toast.show(`Exported: ${fname}`, 'success');
  },
  exportCSV(type = 'all') {
    if (!State.alerts.length) { Toast.show('No data to export.', 'warn'); return; }
    let rows, fname;
    const d = new Date().toISOString().slice(0,10);
    if      (type === 'alerts')    { rows = this._alertRows();    fname = `ThreatGuard_Alerts_${d}.csv`; }
    else if (type === 'incidents') { rows = this._incidentRows(); fname = `ThreatGuard_Incidents_${d}.csv`; }
    else                           { rows = this._alertRows();    fname = `ThreatGuard_All_${d}.csv`; }
    const csv  = rows.map(r => r.map(v => `"${String(v||'').replace(/"/g,'""')}"`).join(',')).join('\n');
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(new Blob([csv], { type:'text/csv' }));
    a.download = fname;
    a.click();
    URL.revokeObjectURL(a.href);
    this.logExport(fname);
    Toast.show(`Exported: ${fname}`, 'success');
  },
};

/* =========================================================
   SETTINGS PAGE
   ========================================================= */
const SettingsPage = {
  render() {
    const e1 = document.getElementById('corrTimeWindow');
    const e2 = document.getElementById('corrMinIndicators');
    if (e1) e1.value = State.settings.corrTimeWindow;
    if (e2) e2.value = State.settings.corrMinIndicators;
    const si = document.getElementById('storageInfo');
    if (si) si.textContent = Store.info();
  },
  save() {
    State.settings.corrTimeWindow    = parseInt(document.getElementById('corrTimeWindow')?.value)    || 60;
    State.settings.corrMinIndicators = parseInt(document.getElementById('corrMinIndicators')?.value) || 1;
    Store.save(KEYS.SETTINGS, State.settings);
    Toast.show('Settings saved.', 'success');
  },
  backup() {
    const blob = new Blob([JSON.stringify({
      alerts:State.alerts, incidents:State.incidents,
      reports:State.reports, settings:State.settings,
      exportedAt:Utils.nowIso()
    }, null, 2)], { type:'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `ThreatGuard_Backup_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    Toast.show('Backup downloaded.', 'success');
  },
  clearAll() {
    Object.values(KEYS).forEach(k => localStorage.removeItem(k));
    State.alerts = []; State.incidents = []; State.reports = [];
    State.settings = { ...DEFAULT_SETTINGS };
    document.getElementById('clearWarning')?.classList.add('d-none');
    const cb = document.getElementById('alertCountBadge');
    if (cb) cb.textContent = '0 Alerts';
    Toast.show('All data cleared.', 'warn');
    this.render();
  },
};

/* =========================================================
   DEMO DATA LOADER
   ========================================================= */

/* Inline fallback — used when fetch fails (e.g. file:// protocol).
   Mirrors assets/sample-alerts.json exactly, with lat/lng/country/city. */
const DEMO_FALLBACK = [
  { alertId:"ALT-1001", sourceType:"SIEM", timestamp:"2026-09-14T02:15:00", alertType:"Brute Force Login", description:"[FICTIONAL] Multiple failed SSH login attempts detected from external IP targeting administrative accounts.", sourceIp:"203.0.113.45", destinationIp:"192.0.2.10", domain:"admin.fictional-corp.test", url:"", port:"22", malwareName:"", fileHash:"", threatCategory:"Credential Access", severity:"High", confidence:82, assetName:"INFRA-SRV-01", assetCriticality:"Critical", mitreTactic:"Credential Access", mitreTechniqueId:"T1110", mitreTechniqueName:"Brute Force", analystName:"Analyst Harper", notes:"Over 500 failed attempts in 10 minutes.", status:"Under Investigation", riskScore:0, priority:"P3", createdAt:"2026-09-14T02:20:00", country:"Iron Plateau", city:"Steel City", lat:55.7558, lng:37.6173 },
  { alertId:"ALT-1002", sourceType:"Cyber Sensor", timestamp:"2026-09-14T02:45:00", alertType:"Command & Control Beacon", description:"[FICTIONAL] Outbound beaconing traffic detected at regular 30-second intervals to known suspicious domain.", sourceIp:"192.0.2.55", destinationIp:"198.51.100.200", domain:"update.bad-fictional-domain.test", url:"http://update.bad-fictional-domain.test/check", port:"443", malwareName:"FictiBot.A", fileHash:"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", threatCategory:"Command and Control", severity:"Critical", confidence:88, assetName:"WORKSTATION-042", assetCriticality:"High", mitreTactic:"Command and Control", mitreTechniqueId:"T1071", mitreTechniqueName:"Application Layer Protocol", analystName:"Analyst Rivera", notes:"Beacon interval consistent with FictiBot malware family.", status:"Confirmed", riskScore:0, priority:"P3", createdAt:"2026-09-14T02:50:00", country:"Fictional East", city:"Cyber Valley", lat:35.6762, lng:139.6503 },
  { alertId:"ALT-1003", sourceType:"Intelligence Report", timestamp:"2026-09-14T03:10:00", alertType:"Phishing Campaign", description:"[FICTIONAL] Intelligence report indicates active spear-phishing campaign targeting defence sector.", sourceIp:"198.51.100.77", destinationIp:"192.0.2.30", domain:"policy-docs.fictional-phish.test", url:"http://policy-docs.fictional-phish.test/Q3-Policy.docx", port:"80", malwareName:"PhishDrop.B", fileHash:"b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3", threatCategory:"Initial Access", severity:"Critical", confidence:75, assetName:"EMAIL-GW-01", assetCriticality:"Critical", mitreTactic:"Initial Access", mitreTechniqueId:"T1566", mitreTechniqueName:"Phishing", analystName:"Analyst Chen", notes:"Campaign attributed to fictional threat actor SHADOW-GROUP-7.", status:"Under Investigation", riskScore:0, priority:"P3", createdAt:"2026-09-14T03:15:00", country:"Phantom Coast", city:"Ghost City", lat:40.7128, lng:-74.0060 },
  { alertId:"ALT-1004", sourceType:"SIEM", timestamp:"2026-09-14T04:00:00", alertType:"Lateral Movement", description:"[FICTIONAL] Unusual PowerShell execution detected attempting to enumerate domain controllers.", sourceIp:"192.0.2.55", destinationIp:"192.0.2.100", domain:"", url:"", port:"445", malwareName:"", fileHash:"c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", threatCategory:"Lateral Movement", severity:"High", confidence:79, assetName:"WORKSTATION-042", assetCriticality:"High", mitreTactic:"Execution", mitreTechniqueId:"T1059", mitreTechniqueName:"Command and Scripting Interpreter", analystName:"Analyst Rivera", notes:"Same source IP as ALT-1002. PowerShell encoded command detected.", status:"Under Investigation", riskScore:0, priority:"P3", createdAt:"2026-09-14T04:05:00", country:"Fictional East", city:"Cyber Valley", lat:35.6762, lng:139.6503 },
  { alertId:"ALT-1005", sourceType:"Satellite Feed", timestamp:"2026-09-14T05:30:00", alertType:"Data Exfiltration Suspected", description:"[FICTIONAL] Anomalous outbound data transfer detected. 4.7 GB transferred to external IP outside business hours.", sourceIp:"192.0.2.100", destinationIp:"203.0.113.200", domain:"storage.fictional-exfil.test", url:"ftp://storage.fictional-exfil.test/upload", port:"21", malwareName:"", fileHash:"", threatCategory:"Exfiltration", severity:"Critical", confidence:70, assetName:"DB-SERVER-02", assetCriticality:"Critical", mitreTactic:"Exfiltration", mitreTechniqueId:"T1041", mitreTechniqueName:"Exfiltration Over C2 Channel", analystName:"Analyst Harper", notes:"Transfer volume unusually high. Destination IP not in approved list.", status:"New", riskScore:0, priority:"P3", createdAt:"2026-09-14T05:35:00", country:"Dark Continent", city:"Signal Hill", lat:-26.2041, lng:28.0473 },
  { alertId:"ALT-1006", sourceType:"SIEM", timestamp:"2026-09-14T06:00:00", alertType:"Impossible Travel Login", description:"[FICTIONAL] User account logged in from two geographically distant locations within 15 minutes.", sourceIp:"203.0.113.45", destinationIp:"192.0.2.10", domain:"auth.fictional-corp.test", url:"", port:"443", malwareName:"", fileHash:"", threatCategory:"Credential Access", severity:"High", confidence:85, assetName:"AUTH-SRV-01", assetCriticality:"Critical", mitreTactic:"Credential Access", mitreTechniqueId:"T1110", mitreTechniqueName:"Brute Force", analystName:"Analyst Chen", notes:"Impossible travel alert. Same source IP as ALT-1001.", status:"Under Investigation", riskScore:0, priority:"P3", createdAt:"2026-09-14T06:05:00", country:"Fictional Land", city:"Demo City", lat:51.5074, lng:-0.1278 },
  { alertId:"ALT-1007", sourceType:"Manual Entry", timestamp:"2026-09-14T07:15:00", alertType:"Vulnerability Scanner Noise", description:"[FICTIONAL] Repeated port scan alerts from internal vulnerability scanner. Scheduled scan confirmed.", sourceIp:"192.0.2.250", destinationIp:"192.0.2.10", domain:"", url:"", port:"0-65535", malwareName:"", fileHash:"", threatCategory:"Discovery", severity:"Low", confidence:15, assetName:"VULN-SCANNER-01", assetCriticality:"Low", mitreTactic:"Discovery", mitreTechniqueId:"T1046", mitreTechniqueName:"Network Service Scanning", analystName:"Analyst Patel", notes:"Confirmed scheduled scan. Likely false positive.", status:"False Positive", riskScore:0, priority:"P4", createdAt:"2026-09-14T07:20:00", country:"Coral Reach", city:"Reef Station", lat:1.3521, lng:103.8198 },
  { alertId:"ALT-1008", sourceType:"Cyber Sensor", timestamp:"2026-09-14T08:00:00", alertType:"Malware Execution", description:"[FICTIONAL] Endpoint detection sensor triggered on execution of suspicious executable. File hash matches known ransomware dropper.", sourceIp:"192.0.2.75", destinationIp:"198.51.100.150", domain:"cdn.fictional-malware-dist.test", url:"http://cdn.fictional-malware-dist.test/payload.exe", port:"80", malwareName:"RansomDrop.X", fileHash:"d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5", threatCategory:"Execution", severity:"Critical", confidence:92, assetName:"FINANCE-WS-07", assetCriticality:"High", mitreTactic:"Execution", mitreTechniqueId:"T1059", mitreTechniqueName:"Command and Scripting Interpreter", analystName:"Analyst Rivera", notes:"Endpoint isolated immediately.", status:"Confirmed", riskScore:0, priority:"P3", createdAt:"2026-09-14T08:05:00", country:"Neon Delta", city:"Neon Bay", lat:22.3193, lng:114.1694 },
  { alertId:"ALT-1009", sourceType:"Intelligence Report", timestamp:"2026-09-14T09:00:00", alertType:"Insider Threat Indicator", description:"[FICTIONAL] User account accessing unusually large volume of sensitive documents outside normal working hours.", sourceIp:"192.0.2.88", destinationIp:"192.0.2.200", domain:"fileserver.fictional-corp.test", url:"", port:"445", malwareName:"", fileHash:"", threatCategory:"Collection", severity:"Medium", confidence:60, assetName:"FILE-SRV-01", assetCriticality:"High", mitreTactic:"Collection", mitreTechniqueId:"T1213", mitreTechniqueName:"Data from Information Repositories", analystName:"Analyst Patel", notes:"HR notified for review.", status:"Under Investigation", riskScore:0, priority:"P3", createdAt:"2026-09-14T09:05:00", country:"Frozen Reach", city:"Ice Station", lat:59.9139, lng:10.7522 },
  { alertId:"ALT-1010", sourceType:"SIEM", timestamp:"2026-09-14T10:00:00", alertType:"Privilege Escalation", description:"[FICTIONAL] Standard user account attempted to modify group policy objects and add itself to Domain Admins group.", sourceIp:"192.0.2.55", destinationIp:"192.0.2.100", domain:"dc.fictional-corp.test", url:"", port:"389", malwareName:"FictiBot.A", fileHash:"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", threatCategory:"Privilege Escalation", severity:"Critical", confidence:95, assetName:"WORKSTATION-042", assetCriticality:"High", mitreTactic:"Privilege Escalation", mitreTechniqueId:"T1068", mitreTechniqueName:"Exploitation for Privilege Escalation", analystName:"Analyst Rivera", notes:"Same source IP and asset as ALT-1002 and ALT-1004.", status:"Confirmed", riskScore:0, priority:"P3", createdAt:"2026-09-14T10:05:00", country:"Desert Pulse", city:"Sand Fortress", lat:25.2048, lng:55.2708 },
  { alertId:"ALT-1011", sourceType:"Cyber Sensor", timestamp:"2026-09-14T10:30:00", alertType:"DNS Tunnelling", description:"[FICTIONAL] Anomalous DNS query patterns detected. High-frequency TXT record requests to suspicious subdomain.", sourceIp:"192.0.2.75", destinationIp:"198.51.100.200", domain:"tunnel.fictional-exfil-dns.test", url:"", port:"53", malwareName:"DNSTun.C", fileHash:"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6", threatCategory:"Exfiltration", severity:"High", confidence:72, assetName:"FINANCE-WS-07", assetCriticality:"High", mitreTactic:"Exfiltration", mitreTechniqueId:"T1048", mitreTechniqueName:"Exfiltration Over Alternative Protocol", analystName:"Analyst Harper", notes:"Same source asset as ALT-1008.", status:"Under Investigation", riskScore:0, priority:"P3", createdAt:"2026-09-14T10:35:00", country:"Fictional South", city:"Shadow Port", lat:-33.8688, lng:151.2093 },
  { alertId:"ALT-1012", sourceType:"Manual Entry", timestamp:"2026-09-14T11:00:00", alertType:"Security Scanner Alert", description:"[FICTIONAL] Automated security scanner reported open port 8080 on development server. Approved configuration.", sourceIp:"192.0.2.250", destinationIp:"192.0.2.180", domain:"dev.fictional-corp.test", url:"", port:"8080", malwareName:"", fileHash:"", threatCategory:"Discovery", severity:"Low", confidence:10, assetName:"DEV-SRV-03", assetCriticality:"Low", mitreTactic:"Discovery", mitreTechniqueId:"T1046", mitreTechniqueName:"Network Service Scanning", analystName:"Analyst Patel", notes:"Approved dev configuration.", status:"False Positive", riskScore:0, priority:"P4", createdAt:"2026-09-14T11:05:00", country:"Fictional Land", city:"Demo City", lat:51.5074, lng:-0.1278 },
];

const Demo = {
  async load() {
    let data;
    try {
      /* Try fetching the JSON file first (works on a local server) */
      const res = await fetch('assets/sample-alerts.json');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      data = await res.json();
    } catch(fetchErr) {
      /* Fallback: use inline data (needed for file:// protocol) */
      console.warn('ThreatGuard: fetch failed (' + fetchErr.message + '). Using inline demo data.');
      data = DEMO_FALLBACK;
    }
    try {
      let added = 0;
      data.forEach(a => {
        if (State.alerts.some(x => x.alertId === a.alertId)) return;
        if (!a.createdAt) a.createdAt = a.timestamp || Utils.nowIso();
        const r = RiskEngine.calc(a, 0);
        a.riskScore = r.score; a.priority = r.priority;
        State.alerts.push(a);
        added++;
      });
      Store.save(KEYS.ALERTS, State.alerts);
      Correlator.run();
      this.rescoreAll();
      Toast.show(`${added} demo alert(s) loaded.`, 'success');
      const cb = document.getElementById('alertCountBadge');
      if (cb) cb.textContent = State.alerts.length + ' Alerts';
      if (Nav.current === 'dashboard')  Dashboard.render();
      if (Nav.current === 'threat-map') {
        ThreatMap._populateFilterDropdowns();
        ThreatMap.applyMapFilters();
      }
    } catch(e) {
      Toast.show('Failed to load demo data: ' + e.message, 'error');
    }
  },
  rescoreAll() {
    State.alerts.forEach(a => {
      const inc = State.incidents.find(i => i.alertIds?.includes(a.alertId));
      const r = RiskEngine.calc(a, inc ? inc.alertIds.length - 1 : 0);
      a.riskScore = r.score; a.priority = r.priority;
    });
    Store.save(KEYS.ALERTS, State.alerts);
  },
};

/* =========================================================
   PUBLIC API — used by inline HTML handlers
   ========================================================= */
const TG = {
  navigate(page)      { Nav.go(page); },
  alertsPage(n)       { State.currentPage = n; AlertsTable.renderTable(); },
  openAlertDetail(id) { AlertDetail.open(id); },
  focusAlertOnMap(id) { ThreatMap.focusAlertOnMap(id); },
  deleteAlert(id) {
    State.pendingDeleteId = id;
    const el = document.getElementById('deleteAlertId');
    if (el) el.textContent = id;
    new bootstrap.Modal(document.getElementById('deleteConfirmModal')).show();
  },
  confirmDelete() {
    if (!State.pendingDeleteId) return;
    State.alerts = State.alerts.filter(a => a.alertId !== State.pendingDeleteId);
    Store.save(KEYS.ALERTS, State.alerts);
    Correlator.run();
    if (Nav.current === 'threat-map') {
      ThreatMap._populateFilterDropdowns();
      ThreatMap.applyMapFilters();
    }
    State.pendingDeleteId = null;
    bootstrap.Modal.getInstance(document.getElementById('deleteConfirmModal'))?.hide();
    Toast.show('Alert deleted.', 'warn');
    AlertsTable.render();
    const cb = document.getElementById('alertCountBadge');
    if (cb) cb.textContent = State.alerts.length + ' Alerts';
  },
  setAlertStatus(id, status) {
    const a = State.alerts.find(x => x.alertId === id);
    if (!a) return;
    a.status = status;
    const r = RiskEngine.calc(a, 0);
    a.riskScore = r.score; a.priority = r.priority;
    Store.save(KEYS.ALERTS, State.alerts);
    const modal = bootstrap.Modal.getInstance(document.getElementById('alertDetailModal'));
    if (modal) { modal.hide(); setTimeout(() => AlertDetail.open(id), 300); }
    Toast.show(`Status: ${status}`, 'info');
    if (Nav.current === 'all-alerts')  AlertsTable.render();
    if (Nav.current === 'fp-analysis') FPAnalysis.render();
    if (Nav.current === 'threat-map')  ThreatMap.applyMapFilters();
  },
  editAlert(id) {
    const a = State.alerts.find(x => x.alertId === id);
    if (!a) return;
    bootstrap.Modal.getInstance(document.getElementById('alertDetailModal'))?.hide();
    State.editingAlertId = id;
    Nav.go('add-alert');
    setTimeout(() => {
      document.getElementById('alertForm')?.reset();
      const msgs = document.getElementById('formMessages');
      if (msgs) msgs.innerHTML = '';
      const set = (eid, val) => { const el = document.getElementById(eid); if (el && val !== undefined) el.value = val; };
      set('fAlertId',a.alertId); set('fSourceType',a.sourceType); set('fTimestamp',a.timestamp); set('fAlertType',a.alertType);
      set('fDescription',a.description); set('fSourceIp',a.sourceIp); set('fDestIp',a.destinationIp);
      set('fDomain',a.domain); set('fPort',a.port); set('fUrl',a.url);
      set('fMalware',a.malwareName); set('fFileHash',a.fileHash); set('fThreatCat',a.threatCategory);
      set('fSeverity',a.severity); set('fConfidence',a.confidence); set('fAssetName',a.assetName);
      set('fAssetCrit',a.assetCriticality); set('fMitreTactic',a.mitreTactic);
      set('fMitreTechId',a.mitreTechniqueId); set('fMitreTechName',a.mitreTechniqueName);
      set('fAnalyst',a.analystName); set('fStatus',a.status); set('fNotes',a.notes);
      set('fCountry',a.country); set('fCity',a.city);
      set('fLat', a.lat != null ? a.lat : ''); set('fLng', a.lng != null ? a.lng : '');
      const idEl = document.getElementById('fAlertId');
      if (idEl) { idEl.value = a.alertId; idEl.readOnly = true; }
      if (msgs) msgs.innerHTML = `<div class="bluf-disclaimer">✏ Editing <strong>${Utils.esc(a.alertId)}</strong> — submit to save changes.</div>`;
    }, 200);
  },
  openIncidentDetail(id) { IncidentDetail.open(id); },
  setIncidentStatus(id, status) {
    const inc = State.incidents.find(i => i.incidentId === id);
    if (!inc) return;
    inc.status = status; inc.updatedAt = Utils.nowIso();
    Store.save(KEYS.INCIDENTS, State.incidents);
    Toast.show(`Incident ${id}: ${status}`, 'info');
    if (Nav.current === 'incidents')  IncidentMgmt.render();
    if (Nav.current === 'correlated') CorrelatedPage.render();
    const mb = document.getElementById('incidentModalBody');
    if (mb && mb.innerHTML) IncidentDetail.open(id);
  },
  saveIncidentNotes(id) {
    const inc = State.incidents.find(i => i.incidentId === id);
    if (!inc) return;
    inc.notes = document.getElementById('incNoteArea')?.value || '';
    inc.updatedAt = Utils.nowIso();
    Store.save(KEYS.INCIDENTS, State.incidents);
    Toast.show('Notes saved.', 'success');
  },
  generateBlufFromAlert(id)    { Nav.go('bluf'); setTimeout(() => BlufPage.generate('alert',    id), 200); },
  generateBlufFromIncident(id) { Nav.go('bluf'); setTimeout(() => BlufPage.generate('incident', id), 200); },
  loadBlufReport(id)           { BlufPage.loadReport(id); },
};

/* =========================================================
   APP INIT
   ========================================================= */
function initApp() {
  Store.loadAll();

  /* Navigation */
  document.querySelectorAll('.nav-link[data-page]').forEach(a => {
    a.addEventListener('click', e => { e.preventDefault(); Nav.go(a.dataset.page); });
  });
  document.getElementById('sidebarToggle')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.toggle('open');
  });

  /* Dashboard */
  document.getElementById('btnDashRefresh')?.addEventListener('click', () => Dashboard.render());
  document.getElementById('btnResetDemo')?.addEventListener('click',   () => Demo.load());
  document.getElementById('btnLoadDemo')?.addEventListener('click',    () => Demo.load());

  /* Alert Form */
  AlertForm.init();

  /* Import */
  ImportPage.init();

  /* All Alerts filters */
  ['searchAlerts','filterSeverity','filterStatus','filterSource','filterPriority','filterDateFrom','filterDateTo','sortAlerts'].forEach(id => {
    document.getElementById(id)?.addEventListener('input',  () => AlertsTable.applyFilters());
    document.getElementById(id)?.addEventListener('change', () => AlertsTable.applyFilters());
  });
  document.getElementById('btnClearFilters')?.addEventListener('click', () => {
    ['searchAlerts','filterSeverity','filterStatus','filterSource','filterPriority','filterDateFrom','filterDateTo'].forEach(id => {
      const el = document.getElementById(id); if (el) el.value = '';
    });
    const sa = document.getElementById('sortAlerts'); if (sa) sa.value = 'timestamp-desc';
    AlertsTable.applyFilters();
  });

  /* Correlation */
  document.getElementById('btnRunCorrelation')?.addEventListener('click',  () => { Correlator.run(); Demo.rescoreAll(); CorrelatedPage.render(); Toast.show('Correlation complete.','info'); });
  document.getElementById('btnRunCorrelation2')?.addEventListener('click', () => { Correlator.run(); Demo.rescoreAll(); IncidentMgmt.render();   Toast.show('Correlation complete.','info'); });

  /* Incident filters */
  ['incidentSearch','incidentFilterStatus','incidentFilterPriority'].forEach(id => {
    document.getElementById(id)?.addEventListener('input',  () => IncidentMgmt.render());
    document.getElementById(id)?.addEventListener('change', () => IncidentMgmt.render());
  });
  document.getElementById('btnIncidentFilterClear')?.addEventListener('click', () => {
    ['incidentSearch','incidentFilterStatus','incidentFilterPriority'].forEach(id => {
      const el = document.getElementById(id); if (el) el.value = '';
    });
    IncidentMgmt.render();
  });

  /* FP Analysis */
  document.getElementById('btnFpAll')?.addEventListener('click',  () => { State.fpFilter = 'all';  FPAnalysis.render(); });
  document.getElementById('btnFpFP')?.addEventListener('click',   () => { State.fpFilter = 'fp';   FPAnalysis.render(); });
  document.getElementById('btnFpMal')?.addEventListener('click',  () => { State.fpFilter = 'mal';  FPAnalysis.render(); });
  document.getElementById('btnFpSusp')?.addEventListener('click', () => { State.fpFilter = 'susp'; FPAnalysis.render(); });

  /* MITRE filters */
  document.getElementById('mitreSearch')?.addEventListener('input',        e => { State.mitreSearch = e.target.value; MitrePage.render(); });
  document.getElementById('mitreTacticFilter')?.addEventListener('change', e => { State.mitreTactic = e.target.value; MitrePage.render(); });
  document.getElementById('btnMitreClear')?.addEventListener('click', () => {
    State.mitreSearch = ''; State.mitreTactic = '';
    const ms = document.getElementById('mitreSearch');       if (ms) ms.value = '';
    const mt = document.getElementById('mitreTacticFilter'); if (mt) mt.value = '';
    MitrePage.render();
  });

  /* BLUF */
  document.getElementById('btnGenerateBluf')?.addEventListener('click', () => {
    const sel = document.getElementById('blufSelector');
    if (!sel?.value) { Toast.show('Select an alert or incident first.', 'warn'); return; }
    const colonIdx = sel.value.indexOf(':');
    BlufPage.generate(sel.value.slice(0, colonIdx), sel.value.slice(colonIdx + 1));
  });
  document.getElementById('btnSaveBluf')?.addEventListener('click',     () => BlufPage.save());
  document.getElementById('btnCopyBluf')?.addEventListener('click',     () => BlufPage.copy());
  document.getElementById('btnDownloadBluf')?.addEventListener('click', () => BlufPage.download());
  document.getElementById('btnPrintBluf')?.addEventListener('click',    () => BlufPage.print());

  /* Export */
  document.getElementById('btnExportAll')?.addEventListener('click',          () => ExportPage.exportExcel('all'));
  document.getElementById('btnExportAlerts')?.addEventListener('click',       () => ExportPage.exportExcel('alerts'));
  document.getElementById('btnExportCSV')?.addEventListener('click',          () => ExportPage.exportCSV('all'));
  document.getElementById('btnExportAlertsCSV')?.addEventListener('click',    () => ExportPage.exportCSV('alerts'));
  document.getElementById('btnExportIncidentsCSV')?.addEventListener('click', () => ExportPage.exportCSV('incidents'));

  /* Settings */
  document.getElementById('btnSaveSettings')?.addEventListener('click', () => SettingsPage.save());
  document.getElementById('btnExportBackup')?.addEventListener('click', () => SettingsPage.backup());
  document.getElementById('btnClearAll')?.addEventListener('click',     () => document.getElementById('clearWarning')?.classList.remove('d-none'));
  document.getElementById('btnConfirmClear')?.addEventListener('click', () => SettingsPage.clearAll());
  document.getElementById('btnCancelClear')?.addEventListener('click',  () => document.getElementById('clearWarning')?.classList.add('d-none'));

  /* Delete confirm */
  document.getElementById('btnConfirmDelete')?.addEventListener('click', () => TG.confirmDelete());

  /* Initial render */
  Correlator.run();
  Demo.rescoreAll();
  Dashboard.render();
}

document.addEventListener('DOMContentLoaded', initApp);
