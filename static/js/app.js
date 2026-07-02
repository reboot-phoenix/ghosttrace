// ==========================================================
// GhostTrace — Investigation Console
// ==========================================================

let scanType = "username";
let lastScanData = null;

const HISTORY_KEY = "ghosttrace_history";
const MAX_HISTORY = 6;

// ---------- init ----------

document.addEventListener("DOMContentLoaded", () => {
    renderHistory();

    document.getElementById("query").addEventListener("keypress", (e) => {
        if (e.key === "Enter") runScan();
    });

    document.getElementById("btn-username").addEventListener("click", () => setType("username"));
    document.getElementById("btn-phone").addEventListener("click", () => setType("phone"));
    document.querySelector(".scan-btn").addEventListener("click", () => runScan());

    const exportBtn = document.getElementById("export-btn");
    if (exportBtn) exportBtn.addEventListener("click", exportReport);

    const clearBtn = document.getElementById("clear-history-btn");
    if (clearBtn) clearBtn.addEventListener("click", clearHistory);
});

// ---------- type toggle ----------

function setType(type) {
    scanType = type;
    document.getElementById("btn-username").classList.toggle("active", type === "username");
    document.getElementById("btn-phone").classList.toggle("active", type === "phone");
    document.getElementById("query").placeholder = type === "username"
        ? "Enter username to scan..."
        : "Enter phone number with country code (e.g. +91xxxxxxxxxx)...";
}

// ---------- scan ----------

async function runScan(prefill) {
    const input = document.getElementById("query");
    if (prefill) input.value = prefill;

    const query = input.value.trim();
    if (!query) return;

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

    if (data.type === "username") {
        const color = score >= 60 ? "#ff0044" : score >= 30 ? "#ffaa00" : "#00ff88";
        ringFill.style.stroke = color;
        scoreNum.style.color = color;
        scoreLabel.textContent = "EXPOSURE SCORE";
        scoreDesc.textContent = score >= 60
            ? "High exposure — widely present across platforms"
            : score >= 30
            ? "Moderate exposure — found on several platforms"
            : "Low exposure — minimal online presence";
    } else {
        ringFill.style.stroke = "#00aaff";
        scoreNum.style.color = "#00aaff";
        scoreLabel.textContent = "LOOKUP LINKS";
        scoreDesc.textContent = "Click each to search this number on that platform";
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

    // auto-verified results
    grid.innerHTML = "";
    const autoResults = data.results.filter(r => r.type === "auto");
    const found = autoResults.filter(r => r.status === "found");
    const notFound = autoResults.filter(r => r.status !== "found");

    document.getElementById("auto-section").classList.toggle("hidden", autoResults.length === 0);

    [...found, ...notFound].forEach(r => {
        const a = document.createElement("a");
        a.className = `result-item ${r.status}`;
        a.href = r.url || "#";
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        const shortUrl = r.url ? r.url.replace(/https?:\/\//, "").split("/")[0] : "";
        a.innerHTML = `
            <div class="dot"></div>
            <div class="result-name">${escapeHtml(r.platform)}</div>
            ${r.status === "found" ? `<div class="result-url">${escapeHtml(shortUrl)}</div><div class="result-arrow">→</div>` : ""}
        `;
        grid.appendChild(a);
    });

    // manual / link results
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
