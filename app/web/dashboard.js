const API = "/api";

async function api(path) {
    try {
        const r = await fetch(API + path);
        return r.json();
    } catch (e) {
        return { error: e.message };
    }
}

function showPage(name) {
    document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
    document.getElementById("page-" + name).classList.add("active");
    document.querySelectorAll("nav button").forEach(b => b.classList.remove("active"));
    event.target.classList.add("active");
    if (name === "dashboard") loadDashboard();
    if (name === "findings") loadFindings();
    if (name === "watchlist") loadWatchlist();
    if (name === "alerts") loadAlerts();
    if (name === "crawl") loadTorHealth();
}

async function loadDashboard() {
    const data = await api("/findings?limit=1000");
    const findings = data.data || [];
    document.getElementById("stat-total-findings").textContent = findings.length;
    document.getElementById("stat-critical").textContent = findings.filter(f => f.severity === "critical").length;
    document.getElementById("stat-high").textContent = findings.filter(f => f.severity === "high").length;
    document.getElementById("stat-sources").textContent = "--";
}

async function loadFindings() {
    const sev = document.getElementById("filter-severity").value;
    const path = "/findings?limit=100" + (sev ? "&severity=" + sev : "");
    const data = await api(path);
    const tbody = document.getElementById("findings-body");
    tbody.innerHTML = "";
    for (const f of data.data || []) {
        tbody.innerHTML += `<tr>
            <td class="severity-${f.severity}">${f.severity || ""}</td>
            <td><code>${escapeHtml(f.matched_value || "")}</code></td>
            <td>${escapeHtml(f.context || "")}</td>
            <td>${f.timestamp || ""}</td>
        </tr>`;
    }
}

async function loadWatchlist() {
    const data = await api("/watchlist");
    const tbody = document.getElementById("watchlist-body");
    tbody.innerHTML = "";
    for (const w of data.data || []) {
        tbody.innerHTML += `<tr>
            <td>${escapeHtml(w.label || "")}</td>
            <td>${w.type}</td>
            <td><code>${escapeHtml(w.value || "")}</code></td>
            <td class="severity-${w.severity}">${w.severity}</td>
        </tr>`;
    }
}

async function loadAlerts() {
    const data = await api("/alerts?limit=100");
    const tbody = document.getElementById("alerts-body");
    tbody.innerHTML = "";
    for (const a of data.data || []) {
        tbody.innerHTML += `<tr>
            <td>${a.finding_id}</td>
            <td>${a.channel}</td>
            <td>${a.sent_at || ""}</td>
            <td>${a.success ? "OK" : "FAIL"}</td>
            <td>${escapeHtml(a.error || "")}</td>
        </tr>`;
    }
}

async function loadTorHealth() {
    const data = await api("/crawl/health");
    document.getElementById("tor-health").innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

async function triggerCrawl(tier) {
    const data = await api("/crawl/trigger/" + tier);
    alert("Crawl triggered: " + JSON.stringify(data));
}

document.getElementById("watchlist-form").onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const payload = Object.fromEntries(fd);
    const res = await fetch(API + "/watchlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    const result = await res.json();
    if (result.id) {
        e.target.reset();
        loadWatchlist();
    } else {
        alert("Error: " + JSON.stringify(result));
    }
};

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

loadDashboard();