// ==========================================================
// GhostTrace v2.1 — Investigation Console
// ==========================================================

let scanType = "name";
let lastScanData = null;

const HISTORY_KEY = "ghosttrace_history";
const MAX_HISTORY = 6;

// ---------- init ----------

document.addEventListener("DOMContentLoaded", () => {
    renderHistory();

    document.getElementById("btn-name").addEventListener("click",     () => setType("name"));
    document.getElementById("btn-username").addEventListener("click", () => setType("username"));
    document.getElementById("btn-email").addEventListener("click",    () => setType("email"));
    document.getElementById("btn-phone").addEventListener("click",    () => setType("phone"));

    document.querySelector(".scan-btn").addEventListener("click", () => runScan());

    const exportBtn = document.getElementById("export-btn");
    if (exportBtn) exportBtn.addEventListener("click", exportReport);

    const copyBtn = document.getElementById("copy-btn");
    if (copyBtn) copyBtn.addEventListener("click", copyReport);

    const clearBtn = document.getElementById("clear-history-btn");
    if (clearBtn) clearBtn.addEventListener("click", clearHistory);

    // Live input filtering
    const nameFirst  = document.getElementById("name-first");
    const nameMiddle = document.getElementById("name-middle");
    const nameLast   = document.getElementById("name-last");
    const phoneNumber = document.getElementById("phone-number");
    const emailInput  = document.getElementById("email-input");
    const usernameInput = document.getElementById("username-input");

    [nameFirst, nameMiddle, nameLast].forEach(el => {
        el.addEventListener("input", () => {
            el.value = el.value.replace(/[^a-zA-Z\s'-]/g, "");
        });
        el.addEventListener("keypress", (e) => { if (e.key === "Enter") runScan(); });
    });

    phoneNumber.addEventListener("input", () => {
        phoneNumber.value = phoneNumber.value.replace(/[^0-9]/g, "");
    });
    phoneNumber.addEventListener("keypress", (e) => { if (e.key === "Enter") runScan(); });

    emailInput.addEventListener("input", () => {
        emailInput.value = emailInput.value.replace(/[^a-zA-Z0-9@._%+\-]/g, "");
    });
    emailInput.addEventListener("keypress", (e) => { if (e.key === "Enter") runScan(); });

    usernameInput.addEventListener("input", () => {
        usernameInput.value = usernameInput.value.replace(/[^a-zA-Z0-9._\-]/g, "");
    });
    usernameInput.addEventListener("keypress", (e) => { if (e.key === "Enter") runScan(); });

    document.getElementById("filter-select").addEventListener("change", (e) => {
        const type = e.target.value;
        if (!type) return;
        addFilterTag(type);
        e.target.value = "";
    });
});

// ---------- filter tags ----------

const FILTER_LABELS = {
    college: "🎓 College / School",
    location: "📍 Location",
    company: "🏢 Company",
    jobtitle: "💼 Job Title"
};

const FILTER_PLACEHOLDERS = {
    college: "e.g. Techno India University",
    location: "e.g. Kolkata, India",
    company: "e.g. Tech Mahindra",
    jobtitle: "e.g. Software Engineer"
};

function addFilterTag(type) {
    if (document.querySelector(`.filter-tag[data-filter="${type}"]`)) return;

    const tag = document.createElement("div");
    tag.className = "filter-tag";
    tag.dataset.filter = type;
    tag.innerHTML = `
        <span class="filter-tag-label">${FILTER_LABELS[type]}</span>
        <input type="text" class="filter-tag-input" placeholder="${FILTER_PLACEHOLDERS[type]}" autocomplete="off" spellcheck="false" />
        <button type="button" class="filter-tag-remove" title="Remove">×</button>
    `;

    const input = tag.querySelector(".filter-tag-input");
    input.addEventListener("input", () => { input.value = input.value.replace(/"/g, ""); });
    input.addEventListener("keypress", (e) => { if (e.key === "Enter") runScan(); });
    tag.querySelector(".filter-tag-remove").addEventListener("click", () => {
        tag.remove();
        updateFilterSelectOptions();
    });

    document.getElementById("filter-tags").appendChild(tag);
    updateFilterSelectOptions();
    input.focus();
}

function updateFilterSelectOptions() {
    const select = document.getElementById("filter-select");
    const usedTypes = [...document.querySelectorAll(".filter-tag")].map(t => t.dataset.filter);
    [...select.options].forEach(opt => {
        if (!opt.value) return;
        opt.disabled = usedTypes.includes(opt.value);
    });
}

function getActiveFilters() {
    return [...document.querySelectorAll(".filter-tag")]
        .map(tag => document.querySelector(`.filter-tag[data-filter="${tag.dataset.filter}"] .filter-tag-input`).value.trim())
        .filter(Boolean);
}

function clearFilterTags() {
    document.getElementById("filter-tags").innerHTML = "";
    updateFilterSelectOptions();
}

// ---------- type toggle ----------

function clearAllInputs() {
    document.getElementById("name-first").value    = "";
    document.getElementById("name-middle").value   = "";
    document.getElementById("name-last").value     = "";
    document.getElementById("phone-number").value  = "";
    document.getElementById("phone-country").selectedIndex = 0;
    document.getElementById("email-input").value   = "";
    document.getElementById("username-input").value = "";
    clearFilterTags();
}

function setType(type) {
    scanType = type;

    ["name", "username", "email", "phone"].forEach(t => {
        document.getElementById(`btn-${t}`).classList.toggle("active", t === type);
        document.getElementById(`group-${t}`).classList.toggle("hidden", t !== type);
    });

    clearAllInputs();
    document.getElementById("results-card").classList.add("hidden");
    lastScanData = null;
    document.getElementById("status").textContent = "";
}

// ---------- validation ----------

function getValidatedQuery() {
    if (scanType === "name") {
        const first  = document.getElementById("name-first").value.trim();
        const middle = document.getElementById("name-middle").value.trim();
        const last   = document.getElementById("name-last").value.trim();

        if (!first || !last) {
            alert("Please enter at least a first and last name.");
            return null;
        }

        const fullName = [first, middle, last].filter(Boolean).join(" ");
        const filters  = getActiveFilters();
        const phrases  = [`"${fullName}"`, ...filters.map(f => `"${f}"`)];
        return phrases.join(" ");
    }

    if (scanType === "username") {
        const username = document.getElementById("username-input").value.trim().replace(/^@/, "");
        if (!username || username.length < 2) {
            alert("Please enter a username (at least 2 characters).");
            return null;
        }
        return username;
    }

    if (scanType === "email") {
        const email = document.getElementById("email-input").value.trim();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            alert("Please enter a valid email address (e.g. name@example.com).");
            return null;
        }
        return email;
    }

    if (scanType === "phone") {
        const country = document.getElementById("phone-country").value;
        const number  = document.getElementById("phone-number").value.trim();
        if (!/^[0-9]{6,14}$/.test(number)) {
            alert("Please enter a valid phone number — digits only, 6–14 digits.");
            return null;
        }
        return country + number;
    }

    return null;
}

// ---------- scan ----------

async function runScan(prefillQuery) {
    let query = prefillQuery || getValidatedQuery();
    if (query === null) return;

    const btn    = document.querySelector(".scan-btn");
    const status = document.getElementById("status");

    btn.disabled = true;
    btn.querySelector(".scan-btn-text").textContent =
        scanType === "username" ? "⚡ SCANNING 50+ PLATFORMS..." : "⚡ SCANNING...";
    status.classList.remove("error");
    status.textContent = scanType === "username"
        ? "[ CHECKING 50+ PLATFORMS — THIS TAKES ~10 SECONDS... ]"
        : "[ TRACING DIGITAL FOOTPRINT... ]";
    status.classList.add("scanning");
    document.getElementById("results-card").classList.add("hidden");

    try {
        const res = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ type: scanType, query })
        });

        const data = await res.json();

        if (!data.success) {
            status.textContent = "❌ " + (data.error || "Something went wrong.");
            status.classList.add("error");
            return;
        }

        lastScanData = data;
        showResults(data);
        saveToHistory(data);
        status.textContent = "✅ TRACE COMPLETE";
    } catch (e) {
        status.textContent = "❌ CONNECTION FAILED — is the server running?";
        status.classList.add("error");
    } finally {
        btn.disabled = false;
        btn.querySelector(".scan-btn-text").textContent = "INITIATE TRACE";
        status.classList.remove("scanning");
    }
}

// ---------- render results ----------

function showResults(data) {
    const card         = document.getElementById("results-card");
    const scoreNum     = document.getElementById("score-number");
    const scoreLabel   = document.getElementById("score-label");
    const scoreDesc    = document.getElementById("score-desc");
    const grid         = document.getElementById("results-grid");
    const autoSection  = document.getElementById("auto-section");
    const manualGrid   = document.getElementById("manual-grid");
    const manualSection = document.getElementById("manual-section");
    const ringFill     = document.getElementById("score-ring-fill");
    const summaryRow   = document.getElementById("summary-row");

    const score = data.score;
    const circumference = 251.2;
    const offset = circumference - (score / 100) * circumference;

    scoreNum.textContent = score + "%";
    ringFill.style.strokeDashoffset = circumference;
    requestAnimationFrame(() => {
        setTimeout(() => { ringFill.style.strokeDashoffset = offset; }, 80);
    });

    if (data.type === "email") {
        ringFill.style.stroke = score >= 50 ? "#00ff88" : "#555";
        scoreNum.style.color  = score >= 50 ? "#00ff88" : "#555";
        scoreLabel.textContent = "PUBLIC EXPOSURE";
        scoreDesc.textContent  = score > 0
            ? "This email has publicly linked data — breaches, profiles, or web mentions"
            : "No public profile data found for this email";
    } else if (data.type === "username") {
        ringFill.style.stroke = "#ff2d78";
        scoreNum.style.color  = "#ff2d78";
        scoreLabel.textContent = "PLATFORM PRESENCE";
        const found = data.summary?.platforms_found || 0;
        const checked = data.summary?.platforms_checked || 30;
        scoreDesc.textContent = found > 0
            ? `Confirmed on ${found} platform${found !== 1 ? "s" : ""} out of ${checked} checked`
            : `No confirmed accounts found across ${checked} platforms`;

        // update heading label
        const autoHeading = document.querySelector("#auto-section .results-heading span:nth-child(2)");
        if (autoHeading) autoHeading.textContent = "✅ CONFIRMED ACCOUNTS";
    } else if (data.type === "phone") {
        ringFill.style.stroke = "#ffe040";
        scoreNum.style.color  = "#ffe040";
        scoreLabel.textContent = "SEARCH COVERAGE";
        scoreDesc.textContent  = "Click the specialist links below — they search real caller databases";
    } else {
        ringFill.style.stroke = "#00aaff";
        scoreNum.style.color  = "#00aaff";
        scoreLabel.textContent = "SEARCH COVERAGE";
        scoreDesc.textContent  = "Search links generated across major platforms — click through to check for real matches";
    }

    // Summary chips
    summaryRow.innerHTML = "";
    if (data.summary) {
        Object.entries(data.summary).forEach(([key, value]) => {
            const chip = document.createElement("div");
            chip.className = "chip";
            chip.innerHTML = `${formatLabel(key)}: <strong>${escapeHtml(String(value))}</strong>`;
            summaryRow.appendChild(chip);
        });
    }

    // Auto-verified results
    grid.innerHTML = "";
    const autoResults = data.results.filter(r => r.type === "auto" && r.status === "found");

    if (autoResults.length > 0) {
        autoSection.classList.remove("hidden");

        if (data.type === "username") {
            // Username scan: show profile cards
            grid.className = "results-grid profile-grid";
            autoResults.forEach(r => {
                const a = document.createElement("a");
                a.className = "profile-card";
                a.href = r.url || "#";
                a.target = "_blank";
                a.rel = "noopener noreferrer";

                const avatarHtml = r.avatar
                    ? `<img class="profile-avatar" src="${escapeHtml(r.avatar)}" alt="" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'" /><div class="profile-avatar-fallback" style="display:none">${escapeHtml(r.icon || "👤")}</div>`
                    : `<div class="profile-avatar-fallback">${escapeHtml(r.icon || "👤")}</div>`;

                const bioHtml = r.bio
                    ? `<div class="profile-bio">${escapeHtml(r.bio)}</div>` : "";

                const metaHtml = r.meta
                    ? `<div class="profile-meta">${escapeHtml(r.meta)}</div>` : "";

                a.innerHTML = `
                    <div class="profile-card-top">
                        <div class="profile-avatar-wrap">${avatarHtml}</div>
                        <div class="profile-info">
                            <div class="profile-platform">${escapeHtml(r.icon || "")} ${escapeHtml(r.platform)}</div>
                            <div class="profile-name">@${escapeHtml(r.display_name || r.platform)}</div>
                            ${bioHtml}
                            ${metaHtml}
                        </div>
                    </div>
                    <div class="profile-card-footer">VIEW PROFILE →</div>
                `;
                grid.appendChild(a);
            });
        } else {
            // Name/email scan: plain result items
            grid.className = "results-grid";
            autoResults.forEach(r => {
                const a = document.createElement("a");
                a.className = `result-item ${r.status}`;
                a.href = r.url || "#";
                a.target = "_blank";
                a.rel = "noopener noreferrer";
                a.innerHTML = `
                    <div class="dot"></div>
                    <div class="result-name">${r.icon ? r.icon + " " : ""}${escapeHtml(r.platform)}</div>
                    <div class="result-arrow">→</div>
                `;
                grid.appendChild(a);
            });
        }
    } else {
        autoSection.classList.add("hidden");
    }

    // Manual / link results
    manualGrid.innerHTML = "";
    const manualResults = data.results.filter(r => r.type === "manual");

    if (manualResults.length > 0) {
        manualSection.classList.remove("hidden");
        manualResults.forEach(r => {
            const a = document.createElement("a");
            a.className = `result-item ${r.status}`;
            a.href = r.url || "#";
            a.target = "_blank";
            a.rel = "noopener noreferrer";
            a.innerHTML = `
                <div class="dot"></div>
                <div class="result-name">${r.icon ? r.icon + " " : ""}${escapeHtml(r.platform)}</div>
                <div class="result-arrow">→</div>
            `;
            manualGrid.appendChild(a);
        });
    } else {
        manualSection.classList.add("hidden");
    }

    card.classList.remove("hidden");
    card.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------- helpers ----------

function formatLabel(key) {
    return key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : String(str);
    return div.innerHTML;
}

// ---------- history ----------

function getHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
    catch (e) { return []; }
}

function saveToHistory(data) {
    let history = getHistory();
    history = history.filter(h => !(h.query === data.query && h.type === data.type));
    history.unshift({ query: data.query, type: data.type, score: data.score, time: Date.now() });
    history = history.slice(0, MAX_HISTORY);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    renderHistory();
}

function clearHistory() {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
}

function renderHistory() {
    const list = document.getElementById("history-list");
    const wrap = document.getElementById("history-card");
    if (!list || !wrap) return;

    const history = getHistory();
    if (history.length === 0) { wrap.classList.add("hidden"); return; }

    wrap.classList.remove("hidden");
    list.innerHTML = "";

    history.forEach(h => {
        const item = document.createElement("div");
        item.className = "history-item";
        item.innerHTML = `
            <span class="h-query">${escapeHtml(h.query)}</span>
            <span class="h-meta">${h.type} · ${h.score}% · ${timeAgo(h.time)}</span>
        `;
        item.addEventListener("click", () => {
            setType(h.type);
            runScan(h.query);
        });
        list.appendChild(item);
    });
}

function timeAgo(ts) {
    const diff = Math.floor((Date.now() - ts) / 1000);
    if (diff < 60) return "just now";
    if (diff < 3600) return Math.floor(diff / 60) + "m ago";
    if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
    return Math.floor(diff / 86400) + "d ago";
}

// ---------- report generation ----------

function buildReportText() {
    if (!lastScanData) return null;
    const d = lastScanData;
    const lines = [];
    lines.push("GHOSTTRACE INVESTIGATION REPORT");
    lines.push("================================");
    lines.push(`Query:      ${d.query}`);
    lines.push(`Type:       ${d.type}`);
    lines.push(`Score:      ${d.score}%`);
    lines.push(`Generated:  ${new Date().toISOString()}`);
    lines.push("");
    lines.push("Summary");
    lines.push("-------");
    Object.entries(d.summary || {}).forEach(([k, v]) => {
        lines.push(`${formatLabel(k)}: ${v}`);
    });
    lines.push("");
    lines.push("Results");
    lines.push("-------");
    d.results.forEach(r => {
        lines.push(`[${(r.status || "").toUpperCase()}] ${r.platform} — ${r.url}`);
    });
    lines.push("");
    lines.push("Generated by GhostTrace — for educational / personal OSINT use only.");
    lines.push("Breach data powered by LeakCheck (leakcheck.io)");
    return lines.join("\n");
}

function exportReport() {
    const text = buildReportText();
    if (!text) return;
    const d = lastScanData;
    const blob = new Blob([text], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url;
    a.download = `ghosttrace_${d.type}_${d.query.replace(/[^a-z0-9]/gi, "_")}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function copyReport() {
    const text = buildReportText();
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById("copy-btn");
        const original = btn.textContent;
        btn.textContent = "✅ COPIED!";
        setTimeout(() => { btn.textContent = original; }, 2000);
    }).catch(() => {
        alert("Copy failed — try the Export button instead.");
    });
}
