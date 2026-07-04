// ==========================================================
// GhostTrace — Investigation Console
// ==========================================================

let scanType = "name";
let lastScanData = null;

const HISTORY_KEY = "ghosttrace_history";
const MAX_HISTORY = 6;

// ---------- init ----------

document.addEventListener("DOMContentLoaded", () => {
    renderHistory();

    document.getElementById("btn-name").addEventListener("click", () => setType("name"));
    document.getElementById("btn-phone").addEventListener("click", () => setType("phone"));
    document.getElementById("btn-email").addEventListener("click", () => setType("email"));

    document.querySelector(".scan-btn").addEventListener("click", () => runScan());

    const exportBtn = document.getElementById("export-btn");
    if (exportBtn) exportBtn.addEventListener("click", exportReport);

    const clearBtn = document.getElementById("clear-history-btn");
    if (clearBtn) clearBtn.addEventListener("click", clearHistory);

    // --- live input filtering ---

    const nameFirst   = document.getElementById("name-first");
    const nameMiddle  = document.getElementById("name-middle");
    const nameLast    = document.getElementById("name-last");
    const phoneNumber = document.getElementById("phone-number");
    const emailInput  = document.getElementById("email-input");

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

    document.getElementById("filter-select").addEventListener("change", (e) => {
        const type = e.target.value;
        if (!type) return;
        addFilterTag(type);
        e.target.value = "";
    });
});

// ---------- filter tags ----------

const FILTER_LABELS = {
    college:  "🎓 College / School",
    location: "📍 Location",
    company:  "🏢 Company",
    jobtitle: "💼 Job Title"
};

const FILTER_PLACEHOLDERS = {
    college:  "e.g. Techno India University",
    location: "e.g. Kolkata, India",
    company:  "e.g. Tech Mahindra",
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
    input.addEventListener("input", () => {
        input.value = input.value.replace(/"/g, "");
    });
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
        .map(tag => tag.querySelector(".filter-tag-input").value.trim())
        .filter(Boolean);
}

function clearFilterTags() {
    document.getElementById("filter-tags").innerHTML = "";
    updateFilterSelectOptions();
}

// ---------- type toggle ----------

function clearAllInputs() {
    document.getElementById("name-first").value = "";
    document.getElementById("name-middle").value = "";
    document.getElementById("name-last").value = "";
    document.getElementById("phone-number").value = "";
    document.getElementById("phone-country").selectedIndex = 0;
    document.getElementById("email-input").value = "";
    clearFilterTags();
}

function setType(type) {
    scanType = type;
    document.getElementById("btn-name").classList.toggle("active", type === "name");
    document.getElementById("btn-phone").classList.toggle("active", type === "phone");
    document.getElementById("btn-email").classList.toggle("active", type === "email");

    document.getElementById("group-name").classList.toggle("hidden", type !== "name");
    document.getElementById("group-phone").classList.toggle("hidden", type !== "phone");
    document.getElementById("group-email").classList.toggle("hidden", type !== "email");

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
            setStatus("⚠️ Please enter at least a first and last name.", "error");
            return null;
        }

        const fullName = [first, middle, last].filter(Boolean).join(" ");
        const filters  = getActiveFilters();
        const phrases  = [`"${fullName}"`, ...filters.map(f => `"${f}"`)];
        return phrases.join(" ");
    }

    if (scanType === "phone") {
        const country = document.getElementById("phone-country").value;   // e.g. "+91"
        const number  = document.getElementById("phone-number").value.trim();

        if (!/^[0-9]{6,14}$/.test(number)) {
            setStatus("⚠️ Enter digits only — between 6 and 14 numbers.", "error");
            return null;
        }
        // Strip the leading + from the country code for the query
        // so we get e.g. "919876543210" which detector.py handles as phone
        const countryDigits = country.replace(/\D/g, "");
        return countryDigits + number;
    }

    if (scanType === "email") {
        const email = document.getElementById("email-input").value.trim();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            setStatus("⚠️ Enter a valid email address (e.g. name@example.com).", "error");
            return null;
        }
        return email;
    }

    return null;
}

// ---------- scan ----------

// FIX: never use textContent on the button — it wipes child <span> elements.
// Use a data-label span inside instead.
function setScanBtnState(scanning) {
    const btn  = document.querySelector(".scan-btn");
    const text = btn.querySelector(".scan-btn-text");
    btn.disabled = scanning;
    if (text) {
        text.textContent = scanning ? "SCANNING..." : "INITIATE TRACE";
    }
}

function setStatus(msg, type = "") {
    const el = document.getElementById("status");
    el.textContent = msg;
    el.className   = "status-line" + (type ? " " + type : "");
}

async function runScan(prefillQuery) {
    let query;

    if (prefillQuery) {
        query = prefillQuery;
    } else {
        query = getValidatedQuery();
        if (query === null) return;
    }

    setScanBtnState(true);
    setStatus("[ TRACING DIGITAL FOOTPRINT... ]", "scanning");
    document.getElementById("results-card").classList.add("hidden");

    try {
        const res = await fetch("/scan", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ type: scanType, query })
        });

        const data = await res.json();

        if (!data.success) {
            setStatus("❌ " + (data.error || "Something went wrong."), "error");
            return;
        }

        lastScanData = data;
        showResults(data);
        saveToHistory(data);
        setStatus("✅ TRACE COMPLETE");

    } catch (e) {
        setStatus("❌ CONNECTION FAILED — is the server running?", "error");
    } finally {
        setScanBtnState(false);
    }
}

// ---------- render results ----------

function showResults(data) {
    const card          = document.getElementById("results-card");
    const scoreNum      = document.getElementById("score-number");
    const scoreLabel    = document.getElementById("score-label");
    const scoreDesc     = document.getElementById("score-desc");
    const grid          = document.getElementById("results-grid");
    const autoSection   = document.getElementById("auto-section");
    const manualGrid    = document.getElementById("manual-grid");
    const manualSection = document.getElementById("manual-section");
    const ringFill      = document.getElementById("score-ring-fill");
    const summaryRow    = document.getElementById("summary-row");

    const score = data.score;
    const circumference = 314.16;
    const offset = circumference - (score / 100) * circumference;

    scoreNum.textContent = score + "%";
    ringFill.style.strokeDashoffset = circumference;
    requestAnimationFrame(() => {
        setTimeout(() => { ringFill.style.strokeDashoffset = offset; }, 80);
    });

    if (data.type === "email") {
        ringFill.style.stroke = score >= 30 ? "#00ff9d" : "#5a7090";
        scoreNum.style.color  = score >= 30 ? "#00ff9d" : "#5a7090";
        scoreLabel.textContent = "EXPOSURE";
        scoreDesc.textContent  = score > 0
            ? "This email has publicly linked data online."
            : "No public profile data found for this email.";
    } else if (data.type === "phone") {
        ringFill.style.stroke = score >= 30 ? "#ff2d78" : "#5a7090";
        scoreNum.style.color  = score >= 30 ? "#ff2d78" : "#5a7090";
        scoreLabel.textContent = "EXPOSURE";
        scoreDesc.textContent  = score > 0
            ? "This number has public mentions online."
            : "No public mentions found — check the manual links below.";
    } else {
        ringFill.style.stroke = "#00d4ff";
        scoreNum.style.color  = "#00d4ff";
        scoreLabel.textContent = "EXPOSURE";
        scoreDesc.textContent  = "Social platform matches found — click through to verify.";
    }

    // summary chips — skip internal/noisy keys
    const SKIP_KEYS = new Set(["normalized", "international", "search_note", "breach_note"]);
    summaryRow.innerHTML = "";
    if (data.summary) {
        Object.entries(data.summary).forEach(([key, value]) => {
            if (SKIP_KEYS.has(key)) return;
            const chip = document.createElement("div");
            chip.className = "chip";
            chip.innerHTML = `${formatLabel(key)}: <strong>${escapeHtml(String(value))}</strong>`;
            summaryRow.appendChild(chip);
        });
    }

    // auto results
    grid.innerHTML = "";
    const autoResults = (data.results || []).filter(r => r.type === "auto");
    if (autoResults.length > 0) {
        autoSection.classList.remove("hidden");
        autoResults.forEach(r => grid.appendChild(makeResultEl(r)));
    } else {
        autoSection.classList.add("hidden");
    }

    // manual results
    manualGrid.innerHTML = "";
    const manualResults = (data.results || []).filter(r => r.type === "manual");
    if (manualResults.length > 0) {
        manualSection.classList.remove("hidden");
        manualResults.forEach(r => manualGrid.appendChild(makeResultEl(r)));
    } else {
        manualSection.classList.add("hidden");
    }

    card.classList.remove("hidden");
    card.scrollIntoView({ behavior: "smooth", block: "start" });
}

function makeResultEl(r) {
    const a = document.createElement("a");
    a.className = `result-item ${r.status || "link"}`;
    a.href      = r.url || "#";
    a.target    = "_blank";
    a.rel       = "noopener noreferrer";
    a.innerHTML = `
        <div class="dot"></div>
        <div class="result-name">${r.icon ? r.icon + " " : ""}${escapeHtml(r.platform || "")}</div>
        <div class="result-arrow">→</div>
    `;
    return a;
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

// ---------- export ----------

function exportReport() {
    if (!lastScanData) return;
    const d = lastScanData;
    const lines = [
        "GHOSTTRACE INVESTIGATION REPORT",
        "================================",
        `Query:     ${d.query}`,
        `Type:      ${d.type}`,
        `Score:     ${d.score}%`,
        `Generated: ${new Date().toISOString()}`,
        "",
        "Summary", "-------",
        ...Object.entries(d.summary || {}).map(([k, v]) => `${formatLabel(k)}: ${v}`),
        "",
        "Results", "-------",
        ...(d.results || []).map(r => `[${(r.status || "").toUpperCase()}] ${r.platform} — ${r.url}`),
        "",
        "Generated by GhostTrace — for educational / personal OSINT use only.",
    ];

    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `ghosttrace_${d.type}_${d.query.replace(/[^a-z0-9]/gi, "_")}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
