/* GhostTrace v3 — Intelligence Report Frontend */

let currentTab    = 'name';
let currentResult = null;
let currentMode   = 'fast';
const HISTORY_KEY = 'gt3_history';

const CONFIDENCE_ICONS  = { CONFIRMED: '✅', PROBABLE: '⚠️', LINKED: '🔗', 'NOT FOUND': '❌' };
const CONFIDENCE_COLORS = { CONFIRMED: 'green', PROBABLE: 'orange', LINKED: 'blue', 'NOT FOUND': 'gray' };

// ── Tab + Mode ─────────────────────────────────────────────────────────────────
function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.type-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.scan-form').forEach(f => f.classList.add('hidden'));
  document.getElementById('form-' + tab).classList.remove('hidden');
  clearError();
}

function setMode(mode) {
  currentMode = mode;
  document.getElementById('mode-fast').classList.toggle('active', mode === 'fast');
  document.getElementById('mode-deep').classList.toggle('active', mode === 'deep');
  document.getElementById('mode-hint').textContent = mode === 'fast'
    ? 'Fast: ~15-30s · Basic scan only'
    : 'Deep: ~60-120s · Auto-correlates findings across sources';
}

// ── Filters ────────────────────────────────────────────────────────────────────
const _filters = [];
function addFilter() {
  const inp = document.getElementById('filter-input');
  const val = inp.value.trim();
  if (!val || _filters.includes(val)) return;
  _filters.push(val);
  renderFilters();
  inp.value = '';
}
function removeFilter(i) { _filters.splice(i, 1); renderFilters(); }
function renderFilters() {
  document.getElementById('filter-tags').innerHTML = _filters.map((f, i) =>
    `<span class="filter-tag">${esc(f)}<button onclick="removeFilter(${i})">×</button></span>`
  ).join('');
}

// ── Scan ──────────────────────────────────────────────────────────────────────
async function runScan() {
  const { query, scan_type } = getInput();
  if (!query) { showError('Please enter a value to scan.'); return; }
  setLoading(true);
  showLoading(scan_type, currentMode);
  try {
    const res  = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, scan_type, filters: currentTab === 'name' ? [..._filters] : [], mode: currentMode }),
    });
    const data = await res.json();
    if (!res.ok || data.error) { showError(data.error || 'Scan failed.'); setLoading(false); return; }
    currentResult = data;
    saveHistory(data);
    renderResult(data);
  } catch (e) { showError('Network error: ' + e.message); }
  setLoading(false);
}

function getInput() {
  let query = '';
  if (currentTab === 'name')     query = (document.getElementById('input-name')?.value     || '').trim();
  if (currentTab === 'username') query = (document.getElementById('input-username')?.value  || '').trim();
  if (currentTab === 'email')    query = (document.getElementById('input-email')?.value     || '').trim();
  if (currentTab === 'phone') {
    const code = document.getElementById('phone-code').value;
    const num  = (document.getElementById('input-phone')?.value || '').trim();
    query = num ? (code + num) : '';
  }
  if (currentTab === 'ip')     query = (document.getElementById('input-ip')?.value     || '').trim();
  if (currentTab === 'domain') query = (document.getElementById('input-domain')?.value || '').trim();
  return { query, scan_type: currentTab };
}

// ── Loading ────────────────────────────────────────────────────────────────────
const LOADING_STEPS = {
  email:    ['Checking Gravatar…', 'Searching GitHub commits…', 'Running Holehe (120+ sites)…', 'Checking breach databases…', 'Querying EmailRep…', 'Running web search…', 'Building intelligence report…'],
  username: ['Querying GitHub, Reddit, GitLab APIs…', 'Checking npm, PyPI, Docker Hub…', 'Checking gaming platforms…', 'Launching Maigret (3,100+ sites)…', 'Correlating findings…', 'Building intelligence report…'],
  phone:    ['Detecting country prefix…', 'Generating format variants…', 'Running web search…', 'Building report…'],
  name:     ['Running LinkedIn search…', 'Running GitHub search…', 'Running Twitter search…', 'Running 11 more platform searches…', 'Correlating findings…', 'Building report…'],
  ip:       ['Geolocating…', 'Querying Shodan InternetDB…', 'Fetching RDAP…', 'Building report…'],
  domain:   ['Resolving domain…', 'Fetching DNS records…', 'Running crt.sh subdomain search…', 'Querying Shodan…', 'Fetching WHOIS/RDAP…', 'Building report…'],
};
const DEEP_EXTRA = ['Running correlation engine…', 'Pivoting on discovered identities…', 'Cross-referencing findings…'];

function showLoading(type, mode) {
  hide('empty-state'); hide('results');
  show('loading-state');
  const steps = [...(LOADING_STEPS[type] || ['Running scan…']), ...(mode === 'deep' ? DEEP_EXTRA : [])];
  const stepsEl = document.getElementById('loading-steps');
  stepsEl.innerHTML = '';
  let i = 0;
  const iv = setInterval(() => {
    if (i >= steps.length) { clearInterval(iv); return; }
    const div = document.createElement('div');
    div.className = 't-line';
    div.innerHTML = `<span class="t-prompt">$</span><span>${esc(steps[i])}</span>`;
    stepsEl.appendChild(div);
    stepsEl.scrollTop = stepsEl.scrollHeight;
    i++;
  }, 800);
}

// ── Main render ────────────────────────────────────────────────────────────────
function renderResult(data) {
  hide('empty-state'); hide('loading-state');
  show('results');

  const report = data.report || {};
  const t      = data.type || data.scan_type || '';

  // Header
  const badge = document.getElementById('result-type-badge');
  badge.className   = 'type-badge ' + t;
  badge.textContent = t.toUpperCase();
  document.getElementById('result-query').textContent = data.query;
  document.getElementById('result-time').textContent  = new Date(data.timestamp * 1000).toLocaleTimeString();

  const modeBadge = document.getElementById('result-mode-badge');
  modeBadge.textContent  = (data.mode || 'fast').toUpperCase() + ' SCAN';
  modeBadge.className    = 'mode-badge ' + (data.mode === 'deep' ? 'deep' : 'fast');

  // Intelligence summary bar
  renderSummaryBar(report, data);

  // Identity card
  renderIdentityCard(report.identity_card || []);

  // Tabs
  renderFindingsTab(report, data);
  renderPlatformsTab(report.platforms || {}, data);
  renderSecurityTab(report.security || {});
  renderRawDataTab(data);
  renderNotesTab(report.notes || []);
  renderAIBriefTab();

  // Activate first tab
  showReportTab('findings');

  // Section collapse
  document.querySelectorAll('.section-header').forEach(h => {
    h.addEventListener('click', () => h.closest('.section').classList.toggle('collapsed'));
  });
}

// ── Summary bar ───────────────────────────────────────────────────────────────
function renderSummaryBar(report, data) {
  const risk    = report.risk || {};
  const summary = report.summary || '';
  const pivots  = report.pivot_count || 0;

  document.getElementById('intel-summary').innerHTML = `
    <div class="summary-text">${esc(summary) || 'Scan complete. Review findings below.'}</div>
    <div class="summary-stats">
      <div class="stat-pill ${risk.color || 'gray'}">
        Risk: ${esc(risk.level || 'LOW')} (${risk.score || 0}/100)
      </div>
      ${pivots ? `<div class="stat-pill blue">${pivots} correlation pivot(s)</div>` : ''}
      <div class="stat-pill gray">Score: ${data.score || 0}%</div>
    </div>
  `;
}

// ── Identity card ─────────────────────────────────────────────────────────────
function renderIdentityCard(fields) {
  const found = fields.filter(f => f.found);
  if (!found.length) { document.getElementById('identity-card-section').innerHTML = ''; return; }

  document.getElementById('identity-card-section').innerHTML = `
    <div class="identity-card">
      <div class="identity-header">
        <span class="identity-title">🪪 SUBJECT IDENTITY</span>
        <span class="identity-sub">Confirmed fields only — no assumptions</span>
      </div>
      <div class="identity-fields">
        ${fields.map(f => `
          <div class="identity-field ${f.found ? '' : 'not-found'}">
            <div class="id-label">${esc(f.label)}</div>
            <div class="id-value">
              <span class="conf-icon">${f.icon}</span>
              <span class="conf-value ${f.color}">${f.found ? esc(String(f.value).slice(0,80)) : '—'}</span>
            </div>
            ${f.found && f.source ? `<div class="id-source">via ${esc(f.source)}</div>` : ''}
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ── Report tabs ───────────────────────────────────────────────────────────────
function showReportTab(name) {
  document.querySelectorAll('.report-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.add('hidden'));
  document.getElementById('tab-' + name).classList.add('active');
  document.getElementById('tab-content-' + name).classList.remove('hidden');
}

// ── Findings tab ──────────────────────────────────────────────────────────────
function renderFindingsTab(report, data) {
  const findings = report.findings || [];
  const t = data.type || data.scan_type || '';
  let html = '';

  if (!findings.length) {
    html = '<div style="color:var(--text3);font-family:var(--mono);font-size:12px;padding:20px">No structured findings available. Check Raw Data tab.</div>';
  } else {
    // Group by category
    const groups = {};
    for (const f of findings) {
      if (!groups[f.category]) groups[f.category] = [];
      groups[f.category].push(f);
    }

    const catIcons = { IDENTITY:'🪪', PLATFORMS:'🌐', SECURITY:'🛡️', INFRASTRUCTURE:'🔧', LOCATION:'📍', ORGANISATION:'🏢', CONTACT:'📧' };
    for (const [cat, items] of Object.entries(groups)) {
      html += section(`${catIcons[cat]||'📋'} ${cat}`,
        items.map(f => `
          <div class="finding-row">
            <div class="finding-conf">
              <span class="conf-badge ${CONFIDENCE_COLORS[f.confidence]||'gray'}">${CONFIDENCE_ICONS[f.confidence]||'?'} ${esc(f.confidence)}</span>
            </div>
            <div class="finding-desc">${esc(f.description)}</div>
            <div class="finding-evidence">📎 ${esc(f.evidence)}</div>
          </div>`).join('')
      );
    }
  }

  // Deep mode: social profile candidates (IG / FB / X / TikTok)
  const social = report.social_candidates || [];
  if (data.mode === 'deep') {
    html += section('📱 SOCIAL PROFILE CANDIDATES', social.length
      ? social.map(c => `
          <div class="finding-row">
            <div class="finding-conf"><span class="conf-badge ${CONFIDENCE_COLORS[c.confidence]||'gray'}">${CONFIDENCE_ICONS[c.confidence]||'?'} ${esc(c.confidence)}</span></div>
            <div class="finding-desc"><a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.platform)} · @${esc(c.handle)}</a>${c.profile_name ? ' — ' + esc(c.profile_name) : ''}</div>
            <div class="finding-evidence">📎 score ${esc(String(c.score))} · ${esc((c.reasons||[]).join('; '))} · ${esc(c.note)}</div>
          </div>`).join('')
      : '<div style="color:var(--text3);font-family:var(--mono);font-size:12px;padding:12px">No candidate profiles found from available evidence.</div>');
  }

  // Add type-specific raw sections below findings
  html += renderTypeSections(data);

  document.getElementById('tab-content-findings').innerHTML = html;
  document.querySelectorAll('#tab-content-findings .section-header').forEach(h => {
    h.addEventListener('click', () => h.closest('.section').classList.toggle('collapsed'));
  });
}

function renderTypeSections(data) {
  const t = data.type || data.scan_type || '';
  let html = '';

  if (t === 'name') {
    const dorks = data.dork_results || [];
    const found = dorks.filter(d => d.found);
    const empty = dorks.filter(d => !d.found);
    if (found.length) {
      html += section(`🔍 Search Results by Platform (${found.length} platforms returned results)`,
        found.map(d => `
          <div class="dork-result-block">
            <div class="dork-result-header">
              <span class="dork-icon">${d.icon}</span>
              <span class="dork-result-label">${esc(d.label)}</span>
              <span class="dork-result-count">${d.count} result${d.count!==1?'s':''}</span>
              <a class="deeplink" href="${esc(d.url)}" target="_blank" style="margin-left:auto;font-size:10px">open in Google →</a>
            </div>
            <div class="dork-results-list">
              ${d.results.map(r=>`
                <div class="web-result">
                  <div class="wr-title"><a href="${esc(r.link)}" target="_blank">${esc(r.title||r.link)}</a></div>
                  <div class="wr-url">${esc(r.link)}</div>
                  ${r.snippet?`<div class="wr-snippet">${esc(r.snippet)}</div>`:''}
                </div>`).join('')}
            </div>
          </div>`).join('')
      );
    }
    if (empty.length) {
      html += section(`⬜ No Results (${empty.length} platforms)`,
        `<div class="tag-list">${empty.map(d=>`<span class="tag">${d.icon} ${esc(d.label)}</span>`).join('')}</div>`
      );
    }
  }

  if (t === 'email') {
    if (data.github?.commits?.length) {
      const gh = data.github;
      html += section(`🐙 GitHub Commits (${gh.commits.length})`, `
        <div class="kv-table">
          ${gh.author_name ? kv('Real name confirmed', gh.author_name, 'green') : ''}
          ${gh.repos?.length ? kv('Repositories', gh.repos.map(r=>`<a class="card-link" href="${esc(r.url)}" target="_blank">${esc(r.name)}</a>`).join(' · ')) : ''}
        </div>
        <div class="commit-list" style="margin-top:10px">
          ${gh.commits.map(c=>`
            <div class="commit-item">
              <div class="commit-sha">${esc(c.sha)}</div>
              <div class="commit-msg">${esc(c.message)}</div>
              <div class="commit-repo">${esc(c.repo)} · <a class="card-link" href="${esc(c.url)}" target="_blank">view →</a></div>
            </div>`).join('')}
        </div>`);
    }
    if (data.holehe?.found?.length) {
      html += section(`🕵️ Registered On These Sites (${data.holehe.found.length} confirmed via Holehe)`, `
        <div class="accounts-grid">
          ${data.holehe.found.map(f=>`
            <div class="account-card">
              <div class="card-top"><div class="card-avatar-placeholder">🌐</div>
              <div><div class="card-site">${esc(f.site)}</div>
              <span class="conf-badge green" style="font-size:9px">✅ CONFIRMED</span></div></div>
              <a class="card-link" href="${esc(f.url)}" target="_blank">Visit site →</a>
            </div>`).join('')}
        </div>`);
    }
    if (data.web_results?.length) {
      html += section(`🌐 Web Mentions (${data.web_results.length})`, renderWebResults(data.web_results));
    }
  }

  if (t === 'username') {
    if (data.found?.length) {
      const cats = {};
      for (const a of data.found) { const c=a.category||'other'; if(!cats[c])cats[c]=[]; cats[c].push(a); }
      const catIcons2 = {social:'💬',coding:'💻',gaming:'🎮',dating:'❤️',other:'📌'};
      for (const [cat, accs] of Object.entries(cats)) {
        html += section(`${catIcons2[cat]||'📌'} ${cat.toUpperCase()} (${accs.length})`, `
          <div class="accounts-grid">
            ${accs.map(a=>`
              <div class="account-card">
                <div class="card-top">
                  ${a.avatar?`<img class="card-avatar" src="${esc(a.avatar)}" onerror="this.parentNode.innerHTML='<div class=card-avatar-placeholder>🌐</div>'">`:`<div class="card-avatar-placeholder">🌐</div>`}
                  <div><div class="card-site">${esc(a.site)}</div>
                  <span class="conf-badge green" style="font-size:9px">✅ CONFIRMED</span></div>
                </div>
                ${a.name?`<div class="card-name">👤 ${esc(a.name)}</div>`:''}
                ${a.bio?`<div class="card-bio">${esc(a.bio.slice(0,100))}</div>`:''}
                ${a.location?`<div class="card-bio">📍 ${esc(a.location)}</div>`:''}
                ${renderMeta(a.meta)}
                ${a.url?`<a class="card-link" href="${esc(a.url)}" target="_blank">View profile →</a>`:''}
              </div>`).join('')}
          </div>`);
      }
    }
  }

  if (t === 'phone') {
    if (data.web_results?.length) html += section(`🌐 Web Mentions (${data.web_results.length})`, renderWebResults(data.web_results));
  }

  if (data.deep_links?.length) html += renderDeepLinks(data.deep_links);

  return html;
}

// ── Platforms tab ──────────────────────────────────────────────────────────────
function renderPlatformsTab(platforms, data) {
  const confirmed = platforms.confirmed || [];
  const probable  = platforms.probable  || [];
  let html = '';

  if (!confirmed.length && !probable.length) {
    html = '<div style="color:var(--text3);font-family:var(--mono);font-size:12px;padding:20px">No platform data available for this scan type.</div>';
  } else {
    if (confirmed.length) {
      html += section(`✅ CONFIRMED — Direct API Verification (${confirmed.length})`, `
        <div class="platform-list">
          ${confirmed.map(p => `
            <div class="platform-row">
              <div class="platform-name">${esc(p.name)}</div>
              <span class="conf-badge green">✅ CONFIRMED</span>
              <div class="platform-source">via ${esc(p.source||'')}</div>
              ${p.url ? `<a class="card-link" href="${esc(p.url)}" target="_blank" rel="noopener">${esc(p.url.slice(0,50))}${p.url.length>50?'…':''} →</a>` : ''}
              ${p.title ? `<div class="platform-title">${esc(p.title.slice(0,80))}</div>` : ''}
              ${p.snippet ? `<div class="platform-snippet">${esc(p.snippet.slice(0,120))}</div>` : ''}
            </div>`).join('')}
        </div>`);
    }
    if (probable.length) {
      html += section(`⚠️ PROBABLE — Web Search Evidence (${probable.length})`, `
        <div class="platform-list">
          ${probable.map(p => `
            <div class="platform-row">
              <div class="platform-name">${esc(p.name)}</div>
              <span class="conf-badge orange">⚠️ PROBABLE</span>
              <div class="platform-source">via ${esc(p.source||'')}</div>
              ${p.url ? `<a class="card-link" href="${esc(p.url)}" target="_blank" rel="noopener">${esc(p.url.slice(0,60))}${p.url.length>60?'…':''} →</a>` : ''}
              ${p.snippet ? `<div class="platform-snippet">${esc(p.snippet.slice(0,120))}</div>` : ''}
            </div>`).join('')}
        </div>`);
    }
  }
  document.getElementById('tab-content-platforms').innerHTML = html;
  document.querySelectorAll('#tab-content-platforms .section-header').forEach(h => {
    h.addEventListener('click', () => h.closest('.section').classList.toggle('collapsed'));
  });
}

// ── Security tab ───────────────────────────────────────────────────────────────
function renderSecurityTab(security) {
  const items = security.items || [];
  const levelColors = { CRITICAL:'red', HIGH:'red', MEDIUM:'orange', LOW:'green', INFO:'gray' };
  let html = '';

  if (security.highest_level) {
    html += `<div class="security-header security-${(security.highest_level||'INFO').toLowerCase()}">
      Overall security level: <strong>${esc(security.highest_level)}</strong>
      ${security.breach_count ? ` · ${security.breach_count} breach${security.breach_count!==1?'es':''}` : ''}
    </div>`;
  }

  html += items.map(item => `
    <div class="security-item security-item-${(item.level||'INFO').toLowerCase()}">
      <div class="security-item-header">
        <span class="security-icon">${item.icon||'ℹ️'}</span>
        <span class="security-title">${esc(item.title)}</span>
        <span class="conf-badge ${levelColors[item.level]||'gray'}">${esc(item.level||'INFO')}</span>
        <span class="conf-badge ${CONFIDENCE_COLORS[item.confidence]||'gray'}" style="margin-left:4px">${CONFIDENCE_ICONS[item.confidence]||'?'} ${esc(item.confidence||'')}</span>
      </div>
      ${item.detail?`<div class="security-detail">${esc(item.detail)}</div>`:''}
      ${item.action?`<div class="security-action">→ ${esc(item.action)}</div>`:''}
    </div>`).join('');

  document.getElementById('tab-content-security').innerHTML = html || '<div style="color:var(--text3);padding:20px;font-family:var(--mono);font-size:12px">No security assessment available.</div>';
}

// ── Raw data tab ───────────────────────────────────────────────────────────────
function renderRawDataTab(data) {
  const t = data.type || data.scan_type || '';
  let html = '';

  if (t === 'ip' || t === 'domain') {
    const g = data.geo || {}, s = data.shodan || {};
    if (Object.keys(g).length) {
      html += section('📍 Geolocation (ip-api.com)', `<div class="kv-table">
        ${kv('IP',         g.ip||data.query)}
        ${kv('Country',    (g.country||'')+(g.country_code?` (${g.country_code})`:'' ))}
        ${kv('Region',     [g.region,g.city].filter(Boolean).join(', '))}
        ${kv('ISP',        g.isp||'—')}
        ${kv('Org',        g.org||'—')}
        ${kv('ASN',        g.asn||'—')}
        ${kv('Timezone',   g.timezone||'—')}
        ${kv('Reverse DNS',g.reverse_dns||'—')}
        ${kv('VPN/Proxy',  g.proxy?'⚠️ YES':'No', g.proxy?'red':'green')}
        ${kv('Hosting/DC', g.hosting?'⚠️ YES':'No', g.hosting?'orange':'')}
        ${kv('Mobile',     g.mobile?'Yes':'No', g.mobile?'green':'')}
      </div>`);
    }
    if (s.ports?.length || s.vulns?.length) {
      html += section('🛡️ Shodan InternetDB', `
        ${s.ports?.length?`<div class="form-label" style="margin-bottom:8px">Open Ports</div><div class="port-list" style="margin-bottom:14px">${s.ports.map(p=>`<span class="port-badge">${p}</span>`).join('')}</div>`:''}
        ${s.vulns?.length?`<div class="form-label" style="margin-bottom:8px">CVEs</div><div class="cve-list" style="margin-bottom:14px">${s.vulns.map(v=>`<a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/${esc(v)}" target="_blank">${esc(v)}</a>`).join('')}</div>`:''}
        ${s.hostnames?.length?`<div class="form-label" style="margin-bottom:8px">Hostnames</div><div class="tag-list">${s.hostnames.map(h=>`<span class="tag" style="color:var(--teal)">${esc(h)}</span>`).join('')}</div>`:''}
        ${s.tags?.length?`<div class="form-label" style="margin-top:12px;margin-bottom:8px">Tags</div><div class="tag-list">${s.tags.map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</div>`:''}
      `);
    }
    if (t === 'domain') {
      const r = data.rdap || {}, d = data.dns || {};
      if (Object.keys(r).length) {
        html += section('📋 WHOIS / RDAP', `<div class="kv-table">
          ${r.registrar?kv('Registrar',r.registrar):''}
          ${r.registered?kv('Registered',r.registered):''}
          ${r.updated?kv('Updated',r.updated):''}
          ${r.expiry?kv('Expires',r.expiry):''}
          ${r.status?.length?kv('Status',r.status.join(', ')):''}
          ${r.nameservers?.length?kv('Nameservers',r.nameservers.join('<br>')):''}
        </div>`);
      }
      if (Object.values(d).some(v=>v?.length)) {
        html += section('🔡 DNS Records', `<div>
          ${Object.entries(d).map(([type,vals])=>vals?.length?`
            <div class="dns-record-type">${esc(type)}</div>
            ${vals.map(v=>`<div class="dns-value">${esc(v)}</div>`).join('')}`:'').join('')}
        </div>`);
      }
      if (data.subdomains?.length) {
        html += section(`🗂️ Subdomains via crt.sh (${data.subdomains.length})`, `
          <div class="subdomain-list">${data.subdomains.map(s=>`<div class="subdomain-entry">${esc(s)}</div>`).join('')}</div>`);
      }
    }
  }

  if (t === 'phone') {
    const c = data.country || {};
    html += section('📱 Number Details', `<div class="kv-table">
      ${kv('Normalized', data.normalized||data.query)}
      ${kv('Country', (c.flag||'')+' '+(c.country||'Unknown'))}
      ${kv('Prefix', c.prefix||'?')}
    </div>
    <div style="margin-top:12px"><div class="form-label">Format Variants</div>
    <div class="tag-list" style="margin-top:6px">${(data.formats||[]).map(f=>`<span class="tag" style="font-family:var(--mono)">${esc(f)}</span>`).join('')}</div></div>`);
  }

  if (t === 'email') {
    const er = data.emailrep || {};
    if (Object.keys(er).length) {
      html += section('🔎 EmailRep.io Analysis', `<div class="kv-table">
        ${kv('Reputation',  er.reputation||'N/A', er.reputation==='high'?'green':er.reputation==='low'?'red':'')}
        ${kv('Suspicious',  er.suspicious?'⚠️ Yes':'No', er.suspicious?'red':'green')}
        ${kv('Blacklisted', er.blacklisted?'Yes':'No', er.blacklisted?'red':'green')}
        ${kv('Spam',        er.spam?'Yes':'No', er.spam?'red':'green')}
        ${kv('Malicious',   er.malicious?'Yes':'No', er.malicious?'red':'green')}
        ${er.profiles?.length?kv('Known profiles', er.profiles.join(', ')):''}
      </div>`);
    }
    if (data.breach?.sources?.length) {
      html += section(`💀 Breach Sources (${data.breach.count})`, `
        <div class="tag-list">${data.breach.sources.map(s=>`<span class="tag" style="color:var(--red);border-color:rgba(255,68,102,.3)">${esc(s)}</span>`).join('')}</div>`);
    }
  }

  if (!html) {
    html = '<div style="color:var(--text3);font-family:var(--mono);font-size:12px;padding:20px">Raw data displayed in Findings tab for this scan type.</div>';
  }

  if (data.deep_links?.length) html += renderDeepLinks(data.deep_links);

  document.getElementById('tab-content-rawdata').innerHTML = html;
  document.querySelectorAll('#tab-content-rawdata .section-header').forEach(h => {
    h.addEventListener('click', () => h.closest('.section').classList.toggle('collapsed'));
  });
}

// ── Notes tab ──────────────────────────────────────────────────────────────────
function renderNotesTab(notes) {
  const risk = currentResult?.report?.risk || {};
  let html = '';

  if (risk.factors?.length) {
    html += section('📊 Risk Factor Breakdown', `
      <div class="kv-table">
        ${kv('Overall Score', `${risk.score}/100`, risk.color||'gray')}
        ${kv('Level', risk.level||'LOW', risk.color||'gray')}
      </div>
      <div style="margin-top:12px;display:flex;flex-direction:column;gap:6px">
        ${risk.factors.map(f=>`
          <div style="display:flex;align-items:center;gap:10px;padding:7px 10px;background:var(--bg2);border:1px solid var(--border)">
            <span class="conf-badge ${f.level==='CRITICAL'||f.level==='HIGH'?'red':f.level==='MEDIUM'?'orange':'green'}">${esc(f.level)}</span>
            <span style="font-size:12px;color:var(--text)">${esc(f.factor)}</span>
            <span style="margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--cyan)">+${f.points}pts</span>
          </div>`).join('')}
      </div>`);
  }

  if (notes.length) {
    html += section('📝 Investigator Notes & Next Steps', `
      <div style="display:flex;flex-direction:column;gap:8px">
        ${notes.map((n,i)=>`
          <div style="display:flex;gap:10px;padding:10px 12px;background:var(--bg2);border:1px solid var(--border);border-left:2px solid var(--cyan)">
            <span style="font-family:var(--mono);font-size:11px;color:var(--cyan);flex-shrink:0">${String(i+1).padStart(2,'0')}.</span>
            <span style="font-size:12px;color:var(--text);line-height:1.5">${esc(n)}</span>
          </div>`).join('')}
      </div>`);
  }

  document.getElementById('tab-content-notes').innerHTML = html || '<div style="color:var(--text3);font-family:var(--mono);font-size:12px;padding:20px">No investigation notes available.</div>';
  document.querySelectorAll('#tab-content-notes .section-header').forEach(h => {
    h.addEventListener('click', () => h.closest('.section').classList.toggle('collapsed'));
  });
}

// ── AI Brief tab ───────────────────────────────────────────────────────────────
function renderAIBriefTab() {
  document.getElementById('tab-content-aibrief').innerHTML = `
    <div style="padding:4px 0">
      <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:14px;line-height:1.6">
        Generate an AI-written intelligence brief based on all findings above.<br>
        Requires <strong style="color:var(--cyan)">ANTHROPIC_API_KEY</strong> in Railway environment variables.
      </div>
      <button class="btn-scan" style="max-width:260px;margin-bottom:16px" onclick="generateBrief()">🤖 Generate Intelligence Brief</button>
      <div id="brief-content"></div>
    </div>`;
}

async function generateBrief() {
  if (!currentResult) return;
  const el = document.getElementById('brief-content');
  el.innerHTML = `
    <div class="t-line"><span class="t-prompt">$</span><span>Analysing all intelligence data…</span></div>
    <div class="t-line"><span class="t-prompt">$</span><span>Writing classified report…<span class="t-cursor"></span></span></div>`;
  try {
    const res  = await fetch('/brief', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ scan_result: currentResult }),
    });
    const data = await res.json();
    if (data.error && !data.brief) {
      el.innerHTML = `<div style="color:var(--red);font-family:var(--mono);font-size:11px;line-height:1.7">
        ⚠️ ${esc(data.error)}<br><br>
        Add <strong>ANTHROPIC_API_KEY</strong> to Railway → Variables.<br>
        Get a free key at <a href="https://console.anthropic.com" target="_blank" style="color:var(--cyan)">console.anthropic.com</a>
      </div>`;
      return;
    }
    if (data.brief) {
      el.innerHTML = `<div class="brief-output">${formatBrief(data.brief)}</div>
        <button class="action-btn" style="margin-top:12px" onclick="copyBrief('${btoa(encodeURIComponent(data.brief))}')">[ COPY BRIEF ]</button>`;
    }
  } catch (e) {
    el.innerHTML = `<div style="color:var(--red);font-family:var(--mono);font-size:11px">Network error: ${esc(e.message)}</div>`;
  }
}

function copyBrief(b64) {
  try { navigator.clipboard.writeText(decodeURIComponent(atob(b64))).then(() => alert('Brief copied!')); } catch {}
}

function formatBrief(text) {
  return text.split('\n').map(line => {
    if (line.match(/^(SUBJECT|SCAN TYPE|CONFIDENCE|EXECUTIVE SUMMARY|KEY FINDINGS|DIGITAL FOOTPRINT|RISK INDICATORS|RECOMMENDED FOLLOW-UP):/))
      return `<div style="color:var(--cyan);font-weight:700;margin-top:10px;letter-spacing:.06em">${esc(line)}</div>`;
    if (line.startsWith('---')) return `<hr style="border-color:var(--border);margin:10px 0">`;
    if (line.startsWith('- ')||line.startsWith('• ')) return `<div style="padding-left:12px;color:var(--text)">▸ ${esc(line.slice(2))}</div>`;
    if (line.trim()==='') return '<div style="height:4px"></div>';
    return `<div style="color:var(--text2)">${esc(line)}</div>`;
  }).join('');
}

// ── Shared helpers ─────────────────────────────────────────────────────────────
function section(title, bodyHtml) {
  return `<div class="section">
    <div class="section-header"><div class="section-title">${title}</div><span class="section-chevron">▾</span></div>
    <div class="section-body">${bodyHtml}</div>
  </div>`;
}
function kv(key, val, cls='') {
  return `<div class="kv-row"><div class="kv-key">${esc(key)}</div><div class="kv-val ${cls}">${val}</div></div>`;
}
function renderWebResults(results) {
  return results.map(r=>`
    <div class="web-result">
      <div class="wr-title"><a href="${esc(r.link)}" target="_blank" rel="noopener">${esc(r.title||r.link)}</a></div>
      <div class="wr-url">${esc(r.link)}</div>
      ${r.snippet?`<div class="wr-snippet">${esc(r.snippet)}</div>`:''}
    </div>`).join('');
}
function renderDeepLinks(links) {
  if (!links?.length) return '';
  return section('🔗 Deep Links & External Tools', `
    <div class="deeplinks-grid">${links.map(l=>`<a class="deeplink" href="${esc(l.url)}" target="_blank" rel="noopener">🔗 ${esc(l.label)}</a>`).join('')}</div>`);
}
function renderMeta(meta) {
  if (!meta||!Object.keys(meta).length) return '';
  const items = Object.entries(meta).filter(([,v])=>v!=null&&v!=='');
  if (!items.length) return '';
  return `<div class="card-meta">${items.map(([k,v])=>`<span>${esc(k)}: ${esc(String(v))}</span>`).join('')}</div>`;
}

// ── Score ring ─────────────────────────────────────────────────────────────────
function animateScore(score) {
  const fill = document.getElementById('ring-fill');
  const valEl = document.getElementById('score-val');
  if (!fill || !valEl) return;
  const circumference = 2 * Math.PI * 48;
  fill.setAttribute('stroke-dasharray', circumference);
  fill.setAttribute('stroke-dashoffset', circumference);
  fill.className = 'ring-fill ' + (score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low');
  fill.style.strokeDashoffset = circumference - (circumference * score / 100);
  let c = 0;
  const step = () => { c = Math.min(c + 2, score); valEl.textContent = c + '%'; if (c < score) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}

// ── History ────────────────────────────────────────────────────────────────────
function saveHistory(data) {
  const hist = getHistory();
  hist.unshift({type: data.type, query: data.query, timestamp: data.timestamp, data});
  if (hist.length > 8) hist.pop();
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(hist)); } catch {}
  renderHistory();
}
function getHistory() { try { return JSON.parse(localStorage.getItem(HISTORY_KEY)||'[]'); } catch { return []; } }
function renderHistory() {
  const list = document.getElementById('history-list');
  const hist = getHistory();
  if (!hist.length) { list.innerHTML = '<div style="font-size:11px;color:var(--text3);padding:8px 10px">No scans yet.</div>'; return; }
  list.innerHTML = hist.map((h,i)=>`
    <div class="history-item" onclick="replayHistory(${i})">
      <div class="h-type">${esc(h.type||'')}</div>
      <div class="h-query">${esc(h.query||'')}</div>
      <div class="h-time">${timeAgo(h.timestamp)}</div>
    </div>`).join('');
}
function replayHistory(i) { const h=getHistory()[i]; if (!h) return; currentResult=h.data; renderResult(h.data); }
function timeAgo(ts) {
  const d = Date.now()/1000 - ts;
  if (d<60) return 'just now';
  if (d<3600) return Math.floor(d/60)+'m ago';
  if (d<86400) return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago';
}

// ── Export ────────────────────────────────────────────────────────────────────
function copyReport() {
  if (!currentResult) return;
  navigator.clipboard.writeText(JSON.stringify(currentResult, null, 2)).then(() => alert('Copied to clipboard!'));
}
function downloadReport() {
  if (!currentResult) return;
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ghosttrace_${currentResult.query}_${Date.now()}.json`;
  a.click();
}

// ── Theme ──────────────────────────────────────────────────────────────────────
function toggleTheme() {
  const next = document.documentElement.dataset.theme==='dark'?'light':'dark';
  document.documentElement.dataset.theme = next;
  document.querySelector('.theme-toggle').textContent = next==='dark'?'[ LIGHT ]':'[ DARK ]';
  try { localStorage.setItem('gt3_theme', next); } catch {}
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(str) {
  if (str==null) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function show(id) { const el=document.getElementById(id); if(el) el.classList.remove('hidden'); }
function hide(id) { const el=document.getElementById(id); if(el) el.classList.add('hidden'); }
function setLoading(v) {
  const btn=document.getElementById('scan-btn'), lbl=document.getElementById('btn-label');
  btn.classList.toggle('loading',v); btn.disabled=v;
  lbl.textContent = v ? '⏳ SCANNING…' : '▶ EXECUTE SCAN';
}
function showError(msg) { const el=document.getElementById('error-msg'); el.textContent=msg; el.classList.remove('hidden'); }
function clearError() { const el=document.getElementById('error-msg'); el.classList.add('hidden'); el.textContent=''; }

document.addEventListener('keydown', e => {
  if (e.key==='Enter' && document.activeElement?.matches?.('.input-main')) runScan();
});

(function init() {
  try {
    const theme = localStorage.getItem('gt3_theme');
    if (theme) {
      document.documentElement.dataset.theme = theme;
      document.querySelector('.theme-toggle').textContent = theme==='dark'?'[ LIGHT ]':'[ DARK ]';
    }
  } catch {}
  renderHistory();
  show('empty-state');
})();
