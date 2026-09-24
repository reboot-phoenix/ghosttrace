/* GhostTrace v3 — Frontend */

// ── State ──────────────────────────────────────────────────────────────────────
let currentTab   = 'name';
let currentResult = null;
const HISTORY_KEY = 'gt3_history';

// ── Tab switching ──────────────────────────────────────────────────────────────
function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.scan-form').forEach(f => f.classList.add('hidden'));
  document.getElementById('form-' + tab).classList.remove('hidden');
  clearError();
}

// ── Filter tags (name mode) ────────────────────────────────────────────────────
const _filters = [];
function addFilter() {
  const inp = document.getElementById('filter-input');
  const val = inp.value.trim();
  if (!val || _filters.includes(val)) return;
  _filters.push(val);
  renderFilters();
  inp.value = '';
}
function removeFilter(i) {
  _filters.splice(i, 1);
  renderFilters();
}
function renderFilters() {
  const container = document.getElementById('filter-tags');
  container.innerHTML = _filters.map((f, i) =>
    `<span class="filter-tag">${esc(f)}<button onclick="removeFilter(${i})">×</button></span>`
  ).join('');
}

// ── Scan ──────────────────────────────────────────────────────────────────────
async function runScan() {
  const { query, scan_type } = getInput();
  if (!query) { showError('Please enter a value to scan.'); return; }

  setLoading(true);
  showLoading(scan_type);

  try {
    const body = { query, scan_type, filters: currentTab === 'name' ? [..._filters] : [] };
    const res  = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok || data.error) { showError(data.error || 'Scan failed.'); setLoading(false); return; }
    currentResult = data;
    saveHistory(data);
    renderResult(data);
  } catch (e) {
    showError('Network error: ' + e.message);
  }
  setLoading(false);
}

function getInput() {
  const tab = currentTab;
  let query = '';
  if (tab === 'name')     query = (document.getElementById('input-name')?.value     || '').trim();
  if (tab === 'username') query = (document.getElementById('input-username')?.value  || '').trim();
  if (tab === 'email')    query = (document.getElementById('input-email')?.value     || '').trim();
  if (tab === 'phone') {
    const code = document.getElementById('phone-code').value;
    const num  = (document.getElementById('input-phone')?.value || '').trim();
    query = num ? (code + num) : '';
  }
  if (tab === 'ip')     query = (document.getElementById('input-ip')?.value     || '').trim();
  if (tab === 'domain') query = (document.getElementById('input-domain')?.value || '').trim();
  return { query, scan_type: tab };
}

// ── Loading messages ───────────────────────────────────────────────────────────
const LOADING_STEPS = {
  email:    ['Checking Gravatar profile…', 'Running Holehe (120+ sites)…', 'Searching GitHub commits…', 'Checking breach databases…', 'Running web search…'],
  username: ['Checking GitHub, Reddit, GitLab…', 'Querying 30+ native APIs…', 'Launching Maigret (3,100+ sites)…', 'Parsing profile data…', 'Deduplicating results…'],
  phone:    ['Detecting country prefix…', 'Building format variants…', 'Running web search…', 'Fetching deep-links…'],
  name:     ['Building 14 Google dorks…', 'Running web search…', 'Filtering social hits…'],
  ip:       ['Geolocating via ip-api…', 'Querying Shodan InternetDB…', 'Fetching RDAP data…'],
  domain:   ['Resolving domain…', 'Fetching DNS records…', 'Running crt.sh subdomain search…', 'Querying Shodan InternetDB…', 'Fetching WHOIS/RDAP…'],
};

function showLoading(type) {
  hide('empty-state'); hide('results');
  show('loading-state');
  const steps = LOADING_STEPS[type] || ['Running scan…'];
  const stepsEl = document.getElementById('loading-steps');
  let i = 0;
  stepsEl.innerHTML = '';
  const interval = setInterval(() => {
    if (i >= steps.length) { clearInterval(interval); return; }
    const div = document.createElement('div');
    div.className = 'loading-step';
    div.innerHTML = `<div class="step-dot"></div><span>${esc(steps[i])}</span>`;
    if (i > 0) stepsEl.children[i-1]?.querySelector('.step-dot')?.classList.add('done');
    stepsEl.appendChild(div);
    stepsEl.scrollTop = stepsEl.scrollHeight;
    i++;
  }, 700);
}

// ── Render results ─────────────────────────────────────────────────────────────
function renderResult(data) {
  hide('empty-state'); hide('loading-state');
  show('results');

  // Header
  const badge = document.getElementById('result-type-badge');
  badge.className = 'type-badge ' + (data.type || data.scan_type || 'email');
  badge.textContent = (data.type || data.scan_type || '').toUpperCase();
  document.getElementById('result-query').textContent = data.query;
  document.getElementById('result-time').textContent = new Date(data.timestamp * 1000).toLocaleTimeString();

  // Score ring
  animateScore(data.score || 0);

  // Chips
  const chipsEl = document.getElementById('chips-area');
  chipsEl.innerHTML = (data.chips || []).map(c => `<span class="chip ${c.color}">${esc(c.label)}</span>`).join('');

  // Dynamic sections
  const body = document.getElementById('results-body');
  body.innerHTML = '';

  const t = data.type || data.scan_type;
  if (t === 'email')    body.innerHTML = renderEmail(data);
  if (t === 'username') body.innerHTML = renderUsername(data);
  if (t === 'phone')    body.innerHTML = renderPhone(data);
  if (t === 'name')     body.innerHTML = renderName(data);
  if (t === 'ip')       body.innerHTML = renderIP(data);
  if (t === 'domain')   body.innerHTML = renderDomain(data);

  // Make section headers collapsible
  document.querySelectorAll('.section-header').forEach(h => {
    h.addEventListener('click', () => h.closest('.section').classList.toggle('collapsed'));
  });
}

// ── Email renderer ─────────────────────────────────────────────────────────────
function renderEmail(data) {
  let html = '';

  // Gravatar
  if (data.gravatar?.found) {
    const g = data.gravatar;
    html += section('🖼️ Gravatar Profile', `
      <div class="gravatar-card">
        ${g.avatar ? `<img class="gravatar-avatar" src="${esc(g.avatar)}" onerror="this.style.display='none'">` : ''}
        <div>
          ${g.name ? `<div style="font-weight:600;font-size:14px">${esc(g.name)}</div>` : ''}
          ${g.bio  ? `<div style="font-size:12px;color:var(--text2);margin-top:4px">${esc(g.bio)}</div>` : ''}
          <a class="card-link" href="${esc(g.profile_url)}" target="_blank" rel="noopener">View profile →</a>
          ${(g.urls||[]).length ? `<div style="margin-top:6px;font-size:11px;color:var(--text3)">Linked: ${g.urls.map(u=>`<a href="${esc(u)}" target="_blank" class="card-link" style="font-size:11px">${esc(u)}</a>`).join(', ')}</div>` : ''}
        </div>
      </div>
    `);
  }

  // GitHub commits
  if (data.github?.commits?.length) {
    const gh = data.github;
    html += section(`🐙 GitHub Commits (${gh.commits.length} found)`, `
      ${gh.author_name ? `<div class="kv-row"><div class="kv-key">Author name</div><div class="kv-val green">${esc(gh.author_name)}</div></div>` : ''}
      ${gh.repos?.length ? `<div class="kv-row"><div class="kv-key">Repositories</div><div class="kv-val">${gh.repos.map(r=>`<a class="card-link" href="${esc(r.url)}" target="_blank">${esc(r.name)}</a>`).join(' · ')}</div></div>` : ''}
      <div class="commit-list" style="margin-top:12px">
        ${gh.commits.map(c => `
          <div class="commit-item">
            <div class="commit-sha">${esc(c.sha)}</div>
            <div class="commit-msg">${esc(c.message)}</div>
            <div class="commit-repo">${esc(c.repo)} · <a class="card-link" href="${esc(c.url)}" target="_blank" style="font-size:11px">View commit →</a></div>
          </div>
        `).join('')}
      </div>
    `);
  }

  // Holehe
  if (data.holehe?.found?.length) {
    html += section(`🕵️ Holehe — Site Registrations (${data.holehe.found.length})`, `
      <div class="accounts-grid">
        ${data.holehe.found.map(f => `
          <div class="account-card">
            <div class="card-top">
              <div class="card-avatar-placeholder">🌐</div>
              <div><div class="card-site">${esc(f.site)}</div><div class="card-cat">Registered</div></div>
            </div>
            <a class="card-link" href="${esc(f.url)}" target="_blank" rel="noopener">Visit site →</a>
          </div>
        `).join('')}
      </div>
    `);
  }

  // Breach
  if (data.breach?.breached) {
    const b = data.breach;
    html += section(`⚠️ Data Breaches (${b.count})`, `
      <div class="tag-list">
        ${(b.sources||[]).map(s=>`<span class="tag" style="color:var(--red);border-color:rgba(231,76,60,.25)">${esc(s)}</span>`).join('')}
      </div>
    `);
  }

  // EmailRep
  if (data.emailrep && Object.keys(data.emailrep).length) {
    const e = data.emailrep;
    html += section('🔎 Email Reputation', `
      <div class="kv-table">
        ${kv('Reputation',  e.reputation || 'N/A', e.reputation === 'high' ? 'green' : e.reputation === 'low' ? 'red' : '')}
        ${kv('Suspicious',  e.suspicious ? '⚠️ Yes' : 'No', e.suspicious ? 'red' : 'green')}
        ${kv('Blacklisted', e.blacklisted ? 'Yes' : 'No', e.blacklisted ? 'red' : 'green')}
        ${kv('Spam',        e.spam ? 'Yes' : 'No', e.spam ? 'red' : 'green')}
        ${kv('Malicious',   e.malicious ? 'Yes' : 'No', e.malicious ? 'red' : 'green')}
        ${e.profiles?.length ? kv('Profiles seen on', e.profiles.join(', ')) : ''}
      </div>
    `);
  }

  // Web results
  if (data.web_results?.length) {
    html += section(`🌐 Web Results (${data.web_results.length})`, renderWebResults(data.web_results));
  }

  html += renderDeepLinks(data.deep_links);
  return html;
}

// ── Username renderer ──────────────────────────────────────────────────────────
function renderUsername(data) {
  let html = '';

  // Category breakdown
  if (data.categories && Object.keys(data.categories).length) {
    const catIcons = { social:'💬', coding:'💻', gaming:'🎮', dating:'❤️', other:'📌' };
    html += `<div class="section"><div class="section-body"><div class="cat-breakdown">
      ${Object.entries(data.categories).map(([cat, n]) => `
        <div class="cat-stat">
          <div class="cat-stat-num">${n}</div>
          <div style="display:flex;flex-direction:column">
            <span style="font-size:16px">${catIcons[cat]||'📌'}</span>
            <span class="cat-stat-label">${cat}</span>
          </div>
        </div>
      `).join('')}
    </div></div></div>`;
  }

  // All found accounts
  if (data.found?.length) {
    html += section(`✅ Found Accounts (${data.found.length})`, `
      <div class="accounts-grid">
        ${data.found.map(a => `
          <div class="account-card">
            <div class="card-top">
              ${a.avatar ? `<img class="card-avatar" src="${esc(a.avatar)}" onerror="this.parentNode.innerHTML='<div class=card-avatar-placeholder>🌐</div>'">` : `<div class="card-avatar-placeholder">🌐</div>`}
              <div>
                <div class="card-site">${esc(a.site)}</div>
                <span class="cat-badge ${esc(a.category||'other')}">${esc(a.category||'other')}</span>
              </div>
            </div>
            ${a.name     ? `<div class="card-name">👤 ${esc(a.name)}</div>` : ''}
            ${a.bio      ? `<div class="card-bio">${esc(a.bio)}</div>` : ''}
            ${a.location ? `<div class="card-bio">📍 ${esc(a.location)}</div>` : ''}
            ${renderMeta(a.meta)}
            ${a.url ? `<a class="card-link" href="${esc(a.url)}" target="_blank" rel="noopener">View profile →</a>` : ''}
          </div>
        `).join('')}
      </div>
    `);
  }

  // Maigret stats
  if (data.maigret) {
    html += section('🤖 Maigret Engine Stats', `
      <div class="kv-table">
        ${kv('Sites checked', data.maigret.total_checked?.toString() || '?')}
        ${kv('Summary', data.maigret.summary || '?')}
      </div>
    `);
  }

  html += renderDeepLinks(data.deep_links);
  return html;
}

function renderMeta(meta) {
  if (!meta || !Object.keys(meta).length) return '';
  const items = Object.entries(meta).filter(([,v]) => v != null && v !== '');
  if (!items.length) return '';
  return `<div class="card-meta">${items.map(([k,v])=>`<span>${esc(k)}: ${esc(String(v))}</span>`).join('')}</div>`;
}

// ── Phone renderer ─────────────────────────────────────────────────────────────
function renderPhone(data) {
  let html = '';
  const c = data.country || {};

  html += section('📱 Number Info', `
    <div class="kv-table">
      ${kv('Normalized',   data.normalized || data.query)}
      ${kv('Country',      (c.flag||'') + ' ' + (c.country||'Unknown'))}
      ${kv('Dial prefix',  c.prefix || '?')}
    </div>
    <div style="margin-top:12px"><div class="form-label">Format variants</div>
    <div class="tag-list" style="margin-top:6px">${(data.formats||[]).map(f=>`<span class="tag" style="font-family:var(--mono)">${esc(f)}</span>`).join('')}</div></div>
  `);

  if (data.web_results?.length) {
    html += section(`🌐 Web Results (${data.web_results.length})`, renderWebResults(data.web_results));
  }

  html += renderDeepLinks(data.deep_links);
  return html;
}

// ── Name renderer ──────────────────────────────────────────────────────────────
function renderName(data) {
  let html = '';

  // Dork grid
  if (data.dorks?.length) {
    html += section('🔎 Google Dork Queries — Click to Search', `
      <div class="dorks-grid">
        ${data.dorks.map(d => `
          <a class="dork-card" href="${esc(d.url)}" target="_blank" rel="noopener">
            <div class="dork-icon">${d.icon||'🔍'}</div>
            <div><div class="dork-label">${esc(d.label)}</div><div class="dork-query">${esc(d.query)}</div></div>
          </a>
        `).join('')}
      </div>
    `);
  }

  if (data.social_hits?.length) {
    html += section(`🟢 Social Media Hits (${data.social_hits.length})`, renderWebResults(data.social_hits));
  }

  if (data.general_hits?.length) {
    html += section(`🌐 General Web Results (${data.general_hits.length})`, renderWebResults(data.general_hits));
  }

  html += renderDeepLinks(data.deep_links);
  return html;
}

// ── IP renderer ───────────────────────────────────────────────────────────────
function renderIP(data) {
  let html = '';
  const g = data.geo || {};
  const s = data.shodan || {};

  if (Object.keys(g).length) {
    html += section('📍 Geolocation & Network', `
      <div class="kv-table">
        ${kv('IP Address',    g.ip || data.query)}
        ${kv('Country',       (g.country||'') + (g.country_code ? ` (${g.country_code})` : ''))}
        ${kv('Region / City', [g.region, g.city].filter(Boolean).join(', '))}
        ${kv('ISP',           g.isp || '?')}
        ${kv('Organisation',  g.org || '?')}
        ${kv('ASN',           g.asn || '?')}
        ${kv('Timezone',      g.timezone || '?')}
        ${kv('Reverse DNS',   g.reverse_dns || '—')}
        ${kv('Mobile',        g.mobile ? '✅ Yes' : 'No',   g.mobile ? 'green' : '')}
        ${kv('VPN/Proxy',     g.proxy ? '⚠️ Yes' : 'No',   g.proxy ? 'red' : 'green')}
        ${kv('Hosting/DC',    g.hosting ? '⚠️ Yes' : 'No', g.hosting ? 'orange' : '')}
      </div>
    `);
  }

  if (s.ports?.length || s.vulns?.length) {
    html += section('🛡️ Shodan InternetDB', `
      ${s.ports?.length ? `<div class="form-label">Open Ports</div><div class="port-list" style="margin:8px 0 14px">${s.ports.map(p=>`<span class="port-badge">${p}</span>`).join('')}</div>` : ''}
      ${s.vulns?.length ? `<div class="form-label">CVEs</div><div class="cve-list" style="margin:8px 0 14px">${s.vulns.map(v=>`<a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/${esc(v)}" target="_blank">${esc(v)}</a>`).join('')}</div>` : ''}
      ${s.hostnames?.length ? `<div class="form-label">Hostnames</div><div class="tag-list" style="margin-top:8px">${s.hostnames.map(h=>`<span class="tag" style="color:var(--teal)">${esc(h)}</span>`).join('')}</div>` : ''}
      ${s.tags?.length ? `<div class="form-label" style="margin-top:12px">Tags</div><div class="tag-list" style="margin-top:8px">${s.tags.map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</div>` : ''}
    `);
  }

  if (data.rdap && Object.keys(data.rdap).length) {
    const r = data.rdap;
    html += section('📋 RDAP / WHOIS', `
      <div class="kv-table">
        ${r.name  ? kv('Network name', r.name) : ''}
        ${r.country  ? kv('Country', r.country) : ''}
        ${r.cidr  ? kv('CIDR', r.cidr) : ''}
        ${r.start_address ? kv('Start address', r.start_address) : ''}
        ${r.end_address   ? kv('End address',   r.end_address)   : ''}
      </div>
    `);
  }

  html += renderDeepLinks(data.deep_links);
  return html;
}

// ── Domain renderer ───────────────────────────────────────────────────────────
function renderDomain(data) {
  let html = '';
  const r = data.rdap || {};
  const d = data.dns  || {};
  const s = data.shodan || {};
  const g = data.geo  || {};

  if (Object.keys(r).length) {
    html += section('📋 WHOIS / RDAP', `
      <div class="kv-table">
        ${r.registrar  ? kv('Registrar',  r.registrar) : ''}
        ${r.registered ? kv('Registered', r.registered) : ''}
        ${r.updated    ? kv('Updated',    r.updated) : ''}
        ${r.expiry     ? kv('Expires',    r.expiry) : ''}
        ${r.status?.length ? kv('Status', r.status.join(', ')) : ''}
        ${r.nameservers?.length ? kv('Nameservers', r.nameservers.join('<br>')) : ''}
      </div>
    `);
  }

  if (data.resolved_ip || Object.keys(g).length) {
    html += section('🌐 IP & Geolocation', `
      <div class="kv-table">
        ${kv('Resolved IP', data.resolved_ip || '?')}
        ${g.country ? kv('Country', g.country) : ''}
        ${g.isp     ? kv('ISP',     g.isp) : ''}
        ${g.org     ? kv('Org',     g.org) : ''}
        ${g.asn     ? kv('ASN',     g.asn) : ''}
      </div>
    `);
  }

  if (Object.values(d).some(v => v?.length)) {
    html += section('🔡 DNS Records', `
      <div>
        ${Object.entries(d).map(([type, vals]) => vals?.length ? `
          <div class="dns-record-type">${esc(type)}</div>
          ${vals.map(v => `<div class="dns-value">${esc(v)}</div>`).join('')}
        ` : '').join('')}
      </div>
    `);
  }

  if (data.subdomains?.length) {
    html += section(`🗂️ Subdomains via crt.sh (${data.subdomains.length})`, `
      <div class="subdomain-list">
        ${data.subdomains.map(sub => `<div class="subdomain-entry">${esc(sub)}</div>`).join('')}
      </div>
    `);
  }

  if (s.ports?.length || s.vulns?.length) {
    html += section('🛡️ Shodan InternetDB', `
      ${s.ports?.length ? `<div class="port-list" style="margin-bottom:12px">${s.ports.map(p=>`<span class="port-badge">${p}</span>`).join('')}</div>` : ''}
      ${s.vulns?.length ? `<div class="cve-list">${s.vulns.map(v=>`<a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/${esc(v)}" target="_blank">${esc(v)}</a>`).join('')}</div>` : ''}
    `);
  }

  html += renderDeepLinks(data.deep_links);
  return html;
}

// ── Shared helpers ─────────────────────────────────────────────────────────────
function section(title, bodyHtml, count = '') {
  return `<div class="section">
    <div class="section-header">
      <div class="section-title">${title}</div>
      <span class="section-chevron">▾</span>
    </div>
    <div class="section-body">${bodyHtml}</div>
  </div>`;
}

function kv(key, val, cls = '') {
  return `<div class="kv-row"><div class="kv-key">${esc(key)}</div><div class="kv-val ${cls}">${val}</div></div>`;
}

function renderWebResults(results) {
  return results.map(r => `
    <div class="web-result">
      <div class="wr-title"><a href="${esc(r.link)}" target="_blank" rel="noopener">${esc(r.title||r.link)}</a></div>
      <div class="wr-url">${esc(r.link)}</div>
      ${r.snippet ? `<div class="wr-snippet">${esc(r.snippet)}</div>` : ''}
    </div>
  `).join('');
}

function renderDeepLinks(links) {
  if (!links?.length) return '';
  return section('🔗 Deep Links & External Tools', `
    <div class="deeplinks-grid">
      ${links.map(l => `<a class="deeplink" href="${esc(l.url)}" target="_blank" rel="noopener">🔗 ${esc(l.label)}</a>`).join('')}
    </div>
  `);
}

// ── Score ring animation ───────────────────────────────────────────────────────
function animateScore(score) {
  const fill = document.getElementById('ring-fill');
  const valEl = document.getElementById('score-val');
  const circumference = 327;
  fill.className = 'ring-fill ' + (score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low');
  fill.style.strokeDashoffset = circumference - (circumference * score / 100);
  let current = 0;
  const step = () => {
    current = Math.min(current + 2, score);
    valEl.textContent = current + '%';
    if (current < score) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ── History ────────────────────────────────────────────────────────────────────
function saveHistory(data) {
  const hist = getHistory();
  hist.unshift({ type: data.type, query: data.query, timestamp: data.timestamp, data });
  if (hist.length > 8) hist.pop();
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(hist)); } catch (e) {}
  renderHistory();
}

function getHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch { return []; }
}

function renderHistory() {
  const list = document.getElementById('history-list');
  const hist = getHistory();
  if (!hist.length) { list.innerHTML = '<div style="font-size:11px;color:var(--text3)">No scans yet.</div>'; return; }
  list.innerHTML = hist.map((h, i) => `
    <div class="history-item" onclick="replayHistory(${i})">
      <div class="h-type">${esc(h.type||'')}</div>
      <div class="h-query">${esc(h.query||'')}</div>
      <div class="h-time">${timeAgo(h.timestamp)}</div>
    </div>
  `).join('');
}

function replayHistory(i) {
  const h = getHistory()[i];
  if (!h) return;
  currentResult = h.data;
  renderResult(h.data);
}

function timeAgo(ts) {
  const diff = Date.now() / 1000 - ts;
  if (diff < 60)     return 'just now';
  if (diff < 3600)   return Math.floor(diff/60) + 'm ago';
  if (diff < 86400)  return Math.floor(diff/3600) + 'h ago';
  return Math.floor(diff/86400) + 'd ago';
}

// ── Export ────────────────────────────────────────────────────────────────────
function copyReport() {
  if (!currentResult) return;
  navigator.clipboard.writeText(JSON.stringify(currentResult, null, 2))
    .then(() => alert('Copied to clipboard!'));
}

function downloadReport() {
  if (!currentResult) return;
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ghosttrace_${currentResult.query}_${Date.now()}.json`;
  a.click();
}

// ── Theme ──────────────────────────────────────────────────────────────────────
function toggleTheme() {
  const curr = document.documentElement.dataset.theme;
  const next = curr === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  document.querySelector('.theme-toggle').textContent = next === 'dark' ? '☀️ Light mode' : '🌙 Dark mode';
  try { localStorage.setItem('gt3_theme', next); } catch {}
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(str) {
  if (str == null) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function show(id) { const el = document.getElementById(id); if (el) el.classList.remove('hidden'); }
function hide(id) { const el = document.getElementById(id); if (el) el.classList.add('hidden'); }
function setLoading(v) {
  const btn = document.getElementById('scan-btn');
  const lbl = document.getElementById('btn-label');
  btn.classList.toggle('loading', v);
  btn.disabled = v;
  lbl.textContent = v ? '⏳ Scanning…' : '🔍 Run Scan';
}
function showError(msg) {
  const el = document.getElementById('error-msg');
  el.textContent = msg;
  el.classList.remove('hidden');
}
function clearError() {
  const el = document.getElementById('error-msg');
  el.classList.add('hidden');
  el.textContent = '';
}

// ── Enter key to scan ──────────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && document.activeElement?.matches?.('.input-main')) runScan();
});

// ── Init ──────────────────────────────────────────────────────────────────────
(function init() {
  try {
    const theme = localStorage.getItem('gt3_theme');
    if (theme) {
      document.documentElement.dataset.theme = theme;
      document.querySelector('.theme-toggle').textContent = theme === 'dark' ? '☀️ Light mode' : '🌙 Dark mode';
    }
  } catch {}
  renderHistory();
  show('empty-state');
})();
