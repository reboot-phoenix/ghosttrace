// ==========================================================
// GhostTrace — Investigation Console
// ==========================================================

let scanType = "name";
let lastScanData = null;

// Shows the tab-switch input-rule hint only once per tab, per page load,
// so it doesn't fire an alert() every single time you click the tab.
const hintsShown = { phone: false, email: false };

const HISTORY_KEY = "ghosttrace_history";
const MAX_HISTORY = 6;

// ---------- init ----------

document.addEventListener("DOMContentLoaded", () => {
    renderHistory();

    document.getElementById("btn-name").addEventListener("click", () => setType("name"));

    document.getElementById("btn-phone").addEventListener("click", () => {
        setType("phone");
        if (!hintsShown.phone) {
            alert("📱 Enter numeric values only for the phone number.");
            hintsShown.phone = true;
        }
    });

    document.getElementById("btn-email").addEventListener("click", () => {
        setType("email");
        if (!hintsShown.email) {
            alert("📧 Enter a valid email address — it must contain @ and a domain (e.g. name@example.com).");
            hintsShown.email = true;
        }
    });
    document.querySelector(".scan-btn").addEventListener("click", () => runScan());

    const exportBtn = document.getElementById("export-btn");
    if (exportBtn) exportBtn.addEventListener("click", exportReport);

    const clearBtn = document.getElementById("clear-history-btn");
    if (clearBtn) clearBtn.addEventListener("click", clearHistory);

    // --- live input filtering (blocks invalid characters as you type) ---

    const nameFirst = document.getElementById("name-first");
    const nameMiddle = document.getElementById("name-middle");
    const nameLast = document.getElementById("name-last");
    const phoneNumber = document.getElementById("phone-number");
    const emailInput = document.getElementById("email-input");

    // Names: letters, spaces, hyphens, apostrophes only
    [nameFirst, nameMiddle, nameLast].forEach(el => {
        el.addEventListener("input", () => {
            el.value = el.value.replace(/[^a-zA-Z\s'-]/g, "");
        });
        el.addEventListener("keypress", (e) => { if (e.key === "Enter") runScan(); });
    });

    // Phone: digits only
    phoneNumber.addEventListener("input", () => {
        phoneNumber.value = phoneNumber.value.replace(/[^0-9]/g, "");
    });
    phoneNumber.addEventListener("keypress", (e) => { if (e.key === "Enter") runScan(); });

    // Email: restrict to characters valid in an email address
    emailInput.addEventListener("input", () => {
        emailInput.value = emailInput.value.replace(/[^a-zA-Z0-9@._%+\-]/g, "");
    });
    emailInput.addEventListener("keypress", (e) => { if (e.key === "Enter") runScan(); });

    // --- name filter attributes (college / location / company / job title) ---

    document.getElementById("filter-select").addEventListener("change", (e) => {
        const type = e.target.value;
        if (!type) return;
        addFilterTag(type);
        e.target.value = "";
    });
});

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
    if (document.querySelector(`.filter-tag[data-filter="${type}"]`)) return; // already added

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
        input.value = input.value.replace(/"/g, ""); // strip quotes — would break query syntax
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
        .map(tag => document.querySelector(`.filter-tag[data-filter="${tag.dataset.filter}"] .filter-tag-input`).value.trim())
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

    // Switching modes wipes whatever was typed elsewhere — no stale
    // cross-field values sneaking into a scan of the wrong type.
    clearAllInputs();

    // Also clear any leftover results from a previous scan of a
    // different type — a genuinely blank slate, not just blank inputs.
    document.getElementById("results-card").classList.add("hidden");
    lastScanData = null;

    document.getElementById("status").textContent = "";
}

// ---------- validation ----------

function getValidatedQuery() {
    if (scanType === "name") {
        const first = document.getElementById("name-first").value.trim();
        const middle = document.getElementById("name-middle").value.trim();
        const last = document.getElementById("name-last").value.trim();

        if (!first || !last) {
            alert("Please enter at least a first and last name.");
            return null;
        }

        const fullName = [first, middle, last].filter(Boolean).join(" ");
        const filters = getActiveFilters();

        // Each phrase quoted separately so the search engine requires all
        // of them to appear (not necessarily adjacent) — this is what
        // actually narrows down common names, unlike one giant quoted blob.
        const phrases = [`"${fullName}"`, ...filters.map(f => `"${f}"`)];
        return phrases.join(" ");
    }

    if (scanType === "phone") {
        const country = document.getElementById("phone-country").value;
        const number = document.getElementById("phone-number").value.trim();

        if (!/^[0-9]{6,14}$/.test(number)) {
            alert("Please enter numeric values only — a valid phone number (6–14 digits).");
            return null;
        }
        return country + number;
    }

    if (scanType === "email") {
        const email = document.getElementById("email-input").value.trim();
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailPattern.test(email)) {
            alert("Please enter a valid email address (must contain @ and a domain, e.g. name@example.com).");
            return null;
        }
        return email;
    }

    return null;
}

// ---------- scan ----------

async function runScan(prefillQuery) {
    let query;

    if (prefillQuery) {
        // used by history re-run — trusted, already-validated past query
        query = prefillQuery;
    } else {
        query = getValidatedQuery();
        if (query === null) return; // alert already shown
    }

    const btn = document.querySelector(".scan-btn");
    const status = document.getElementById("status");

    btn.disabled = true;
    btn.textContent = "⚡ SCANNING...";
    status.classList.remove("error");
    status.textContent = "[ TRACING DIGITAL FOOTPRINT... ]";
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
        btn.textContent = "⚡ TRACE";
        status.classList.remove("scanning");
    }
}

// ---------- render results ----------

function showResults(data) {
    const card = document.getElementById("results-card");
    const scoreNum = document.getElementById("score-number");
    const scoreLabel = document.getElementById("score-label");
    const scoreDesc = document.getElementById("score-desc");
    const grid = document.getElementById("results-grid");
    const autoSection = document.getElementById("auto-section");
    const manualGrid = document.getElementById("manual-grid");
    const manualSection = document.getElementById("manual-section");
    const ringFill = document.getElementById("score-ring-fill");
    const summaryRow = document.getElementById("summary-row");

    const score = data.score;
    const circumference = 251.2;
    const offset = circumference - (score / 100) * circumference;

    scoreNum.textContent = score + "%";
    ringFill.style.strokeDashoffset = circumference;
    requestAnimationFrame(() => {
        setTimeout(() => { ringFill.style.strokeDashoffset = offset; }, 80);
    });

    if (data.type === "email") {
        const color = score >= 50 ? "#00ff88" : "#555";
        ringFill.style.stroke = color;
        scoreNum.style.color = color;
        scoreLabel.textContent = "PUBLIC DATA FOUND";
        scoreDesc.textContent = score > 0
            ? "This email has publicly linked profile data"
            : "No public profile data found for this email";
    } else {
        ringFill.style.stroke = "#00aaff";
        scoreNum.style.color = "#00aaff";
        scoreLabel.textContent = "SEARCH COVERAGE";
        scoreDesc.textContent = data.type === "name"
            ? "Search links generated across major platforms — click through to check for real matches"
            : "Click each to search this number on that platform";
    }

    // summary chips
    summaryRow.innerHTML = "";
    if (data.summary) {
        Object.entries(data.summary).forEach(([key, value]) => {
            const chip = document.createElement("div");
            chip.className = "chip";
            chip.innerHTML = `${formatLabel(key)}: <strong>${value}</strong>`;
            summaryRow.appendChild(chip);
        });
    }

    // auto-verified results (currently only email/Gravatar produces these)
    grid.innerHTML = "";
    const autoResults = data.results.filter(r => r.type === "auto");

    if (autoResults.length > 0) {
        autoSection.classList.remove("hidden");
        autoResults.forEach(r => {
            const a = document.createElement("a");
            a.className = `result-item ${r.status}`;
            a.href = r.url || "#";
            a.target = "_blank";
            a.rel = "noopener noreferrer";
            a.innerHTML = `
                <div class="dot"></div>
                <div class="result-name">${r.icon ? r.icon + " " : ""}${escapeHtml(r.platform)}</div>
                ${r.status === "found" ? `<div class="result-arrow">→</div>` : ""}
            `;
            grid.appendChild(a);
        });
    } else {
        autoSection.classList.add("hidden");
    }

    // manual / link-only results (name, phone, and email's HIBP/Google links)
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

function formatLabel(key) {
    return key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : String(str);
    return div.innerHTML;
}

// ---------- history (local, client-side only) ----------

function getHistory() {
    try {
        return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch (e) {
        return [];
    }
}

function saveToHistory(data) {
    let history = getHistory();
    history = history.filter(h => !(h.query === data.query && h.type === data.type));
    history.unshift({
        query: data.query,
        type: data.type,
        score: data.score,
        time: Date.now()
    });
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

    if (history.length === 0) {
        wrap.classList.add("hidden");
        return;
    }

    wrap.classList.remove("hidden");
    list.innerHTML = "";

    history.forEach(h => {
        const item = document.createElement("div");
        item.className = "history-item";
        const when = timeAgo(h.time);
        item.innerHTML = `
            <span class="h-query">${escapeHtml(h.query)}</span>
            <span class="h-meta">${h.type} · ${h.score}% · ${when}</span>
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

// ---------- export report ----------

function exportReport() {
    if (!lastScanData) return;

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

    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ghosttrace_${d.type}_${d.query.replace(/[^a-z0-9]/gi, "_")}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
