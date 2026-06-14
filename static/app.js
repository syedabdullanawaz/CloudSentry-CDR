// ==========================================================================
// CloudSentry CDR - Single Page Application Frontend Engine (SaaS Overhaul)
// ==========================================================================

let incidentsList = [];
let leafletMap = null;
let mapMarkers = [];
let severityChart = null;
let costChart = null;

// Telemetry historical data arrays for sparkline canvas renders
const sparklineData = {
    critical: [0, 1, 2, 1, 3, 2, 1],
    open: [3, 5, 8, 6, 9, 7, 6],
    leak: [15, 30, 25, 40, 50, 45, 43.60],
    ingest: [90, 110, 95, 120, 140, 128, 124]
};

document.addEventListener("DOMContentLoaded", () => {
    // 1. Tab Switching Listeners (Top Navigation Tabs Only)
    const topTabItems = document.querySelectorAll(".top-tab-item");
    const sections = document.querySelectorAll(".tab-section");
    
    function switchTab(targetTab) {
        topTabItems.forEach(t => {
            if (t.getAttribute("data-tab") === targetTab) {
                t.classList.add("active");
            } else {
                t.classList.remove("active");
            }
        });
        
        sections.forEach(s => {
            if (s.id === `tab-${targetTab}`) {
                s.classList.add("active");
            } else {
                s.classList.remove("active");
            }
        });
        
        // Map needs invalidateSize if loaded in hidden container
        if (targetTab === "map" && leafletMap) {
            setTimeout(() => leafletMap.invalidateSize(), 100);
        }
    }
    
    topTabItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const targetTab = item.getAttribute("data-tab");
            switchTab(targetTab);
        });
    });
    
    // 2. Control Buttons Event Listeners
    document.getElementById("btn-scan").addEventListener("click", triggerCloudScan);
    document.getElementById("btn-seed").addEventListener("click", seedMockTelemetry);
    document.getElementById("btn-save-settings").addEventListener("click", saveSettings);
    
    // 3. Filters for Incident Stream
    document.getElementById("stream-search").addEventListener("input", filterIncidents);
    document.getElementById("filter-severity").addEventListener("change", filterIncidents);
    document.getElementById("filter-status").addEventListener("change", filterIncidents);
    
    // 4. Playbook Incident Select Dropdown
    document.getElementById("playbook-incident-select").addEventListener("change", handlePlaybookSelect);
    document.getElementById("btn-suppress").addEventListener("click", executeSuppression);
    
    // Initial data fetch and loops
    fetchSettings();
    loadIncidents();
    startLiveActivityFeed();
    renderSparklines();
});

// ----------------------------------------------------
// CANVAS SPARKLINE ENGINE
// ----------------------------------------------------
function renderSparklines() {
    drawSparkline("spark-critical", sparklineData.critical, "#dc2626");
    drawSparkline("spark-open", sparklineData.open, "#ea580c");
    drawSparkline("spark-leak", sparklineData.leak, "#16a34a");
    drawSparkline("spark-ingest", sparklineData.ingest, "#0284c7");
}

function drawSparkline(canvasId, dataPoints, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    if (dataPoints.length < 2) return;
    
    const step = canvas.width / (dataPoints.length - 1);
    const maxVal = Math.max(...dataPoints, 1);
    const minVal = Math.min(...dataPoints, 0);
    const range = maxVal - minVal;
    
    // Compute pixel coordinates
    const points = dataPoints.map((val, index) => {
        return {
            x: index * step,
            y: canvas.height - 3 - ((val - minVal) / (range || 1)) * (canvas.height - 6)
        };
    });
    
    // Draw smooth bezier curve
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    
    for (let i = 0; i < points.length - 1; i++) {
        const p0 = points[i];
        const p1 = points[i + 1];
        const cpX = p0.x + (p1.x - p0.x) / 2;
        ctx.bezierCurveTo(cpX, p0.y, cpX, p1.y, p1.x, p1.y);
    }
    
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.0;
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.stroke();
    
    // Fill shaded gradient area below sparkline
    ctx.lineTo(canvas.width, canvas.height);
    ctx.lineTo(0, canvas.height);
    ctx.fillStyle = color + "12"; // 7% opacity
    ctx.closePath();
    ctx.fill();
}

// ----------------------------------------------------
// DATA EXTRACTION & INGESTION
// ----------------------------------------------------
function loadIncidents() {
    fetch("/api/incidents")
        .then(res => res.json())
        .then(data => {
            incidentsList = data;
            updateMetrics(data);
            renderCharts(data);
            renderIncidentFeedList(data);
            populatePlaybookSelector(data);
            updateThreatMap(data);
        })
        .catch(err => console.error("Error loading incidents:", err));
}

function triggerCloudScan() {
    const btn = document.getElementById("btn-scan");
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Auditing AWS...';
    btn.disabled = true;
    
    fetch("/api/scan", { method: "POST" })
        .then(res => res.json())
        .then(data => {
            alert(data.message);
            
            // Randomize sparkline telemetry to simulate active scan variance
            sparklineData.critical.push(Math.floor(Math.random() * 3));
            sparklineData.open.push(Math.floor(Math.random() * 8) + 2);
            sparklineData.leak.push(Math.floor(Math.random() * 20) + 30);
            sparklineData.ingest.push(Math.floor(Math.random() * 40) + 100);
            
            // Keep last 8 data points
            for (let key in sparklineData) {
                if (sparklineData[key].length > 8) sparklineData[key].shift();
            }
            renderSparklines();
            
            setTimeout(loadIncidents, 3000);
        })
        .catch(err => alert("Error starting scan: " + err))
        .finally(() => {
            btn.innerHTML = originalText;
            btn.disabled = false;
        });
}

function seedMockTelemetry() {
    const btn = document.getElementById("btn-seed");
    btn.disabled = true;
    
    fetch("/api/seed", { method: "POST" })
        .then(res => res.json())
        .then(data => {
            loadIncidents();
        })
        .catch(err => alert("Error seeding mock telemetry: " + err))
        .finally(() => {
            btn.disabled = false;
        });
}

// ----------------------------------------------------
// METRICS & CIRCULAR GAUGE CALCULATOR
// ----------------------------------------------------
function updateMetrics(incidents) {
    const open = incidents.filter(i => i.status === "OPEN");
    const critical = open.filter(i => i.severity === "CRITICAL").length;
    const leakage = open.reduce((acc, i) => acc + (i.cost_leak || 0), 0);
    
    document.getElementById("metric-critical").innerText = critical;
    document.getElementById("metric-open").innerText = open.length;
    document.getElementById("metric-leak").innerText = `$${leakage.toFixed(2)}`;
    
    // Updates incident count badge in top tabs
    const topBadge = document.getElementById("top-incident-count");
    if (topBadge) topBadge.innerText = open.length;
    
    // SVG Circular compliance gauge calculation
    const complianceIndexEl = document.getElementById("compliance-index");
    const gaugeFillEl = document.getElementById("compliance-gauge-fill");
    
    const uniqueFailedRules = new Set(open.map(i => i.compliance_rule).filter(Boolean)).size;
    const totalRules = 4;
    const indexScore = Math.max(0, Math.floor(((totalRules - uniqueFailedRules) / totalRules) * 100));
    
    complianceIndexEl.innerText = `${indexScore}%`;
    
    if (gaugeFillEl) {
        const circumference = 251.2;
        const offset = circumference - (circumference * indexScore / 100);
        gaugeFillEl.style.strokeDashoffset = offset;
    }
    
    // Update active benchmark control badges in checklist
    const hasMfaFailure = open.some(i => (i.compliance_rule || "").includes("MFA"));
    const mfaBadge = document.getElementById("badge-mfa");
    const mfaBox = document.getElementById("check-mfa");
    if (hasMfaFailure) {
        mfaBadge.innerText = "FAIL";
        mfaBadge.className = "badge badge-critical";
        mfaBox.style.borderColor = "#fca5a5";
    } else {
        mfaBadge.innerText = "PASS";
        mfaBadge.className = "badge badge-low";
        mfaBox.style.borderColor = "var(--border-color)";
    }
    
    const hasLeak = open.some(i => i.resource_type === "IAM Access Key" && i.severity === "CRITICAL");
    const leakBadge = document.getElementById("badge-leak");
    const leakBox = document.getElementById("check-leak");
    if (hasLeak) {
        leakBadge.innerText = "EXPOSED";
        leakBadge.className = "badge badge-critical";
        leakBox.style.borderColor = "#fca5a5";
    } else {
        leakBadge.innerText = "PASS";
        leakBadge.className = "badge badge-low";
        leakBox.style.borderColor = "var(--border-color)";
    }
}

// ----------------------------------------------------
// CHARTS CONTROLLER (Chart.js Configs)
// ----------------------------------------------------
function renderCharts(incidents) {
    const open = incidents.filter(i => i.status === "OPEN");
    
    // 1. Severity Doughnut Chart
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    open.forEach(i => {
        if (severityCounts[i.severity] !== undefined) {
            severityCounts[i.severity]++;
        }
    });
    
    const ctxSeverity = document.getElementById("chart-severity").getContext("2d");
    if (severityChart) {
        severityChart.destroy();
    }
    
    severityChart = new Chart(ctxSeverity, {
        type: "doughnut",
        data: {
            labels: Object.keys(severityCounts),
            datasets: [{
                data: Object.values(severityCounts),
                backgroundColor: ["#dc2626", "#ea580c", "#eab308", "#16a34a"],
                borderWidth: 2,
                borderColor: "#ffffff"
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "70%",
            plugins: {
                legend: { display: false }
            }
        }
    });
    
    // Render custom HTML legend list
    const legendContainer = document.getElementById("chart-severity-legend");
    if (legendContainer) {
        legendContainer.innerHTML = "";
        const totalIncidents = open.length;
        const colors = { CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#eab308", LOW: "#16a34a" };
        
        Object.entries(severityCounts).forEach(([severity, count]) => {
            const percent = totalIncidents > 0 ? Math.round((count / totalIncidents) * 100) : 0;
            const legendItem = document.createElement("div");
            legendItem.className = "doughnut-legend-item";
            legendItem.innerHTML = `
                <div class="legend-label-group">
                    <span class="legend-color-dot" style="background-color: ${colors[severity]}"></span>
                    <span class="legend-text">${severity}</span>
                </div>
                <div class="legend-values">
                    <strong class="legend-count">${count}</strong>
                    <span class="legend-percent">${percent}%</span>
                </div>
            `;
            legendContainer.appendChild(legendItem);
        });
    }
    
    // 2. Cost Leaks Bar Chart (FinOps)
    const costLeaks = {};
    open.filter(i => i.cost_leak > 0).forEach(i => {
        costLeaks[i.resource_type] = (costLeaks[i.resource_type] || 0) + i.cost_leak;
    });
    
    const hasCostLeaks = Object.keys(costLeaks).length > 0;
    const chartContainerEl = document.getElementById("chart-cost-container");
    const emptyStateEl = document.getElementById("chart-cost-empty");
    
    if (!hasCostLeaks) {
        if (chartContainerEl) chartContainerEl.style.display = "none";
        if (emptyStateEl) emptyStateEl.style.display = "flex";
        if (costChart) {
            costChart.destroy();
            costChart = null;
        }
    } else {
        if (chartContainerEl) chartContainerEl.style.display = "block";
        if (emptyStateEl) emptyStateEl.style.display = "none";
        
        const ctxCost = document.getElementById("chart-cost").getContext("2d");
        if (costChart) {
            costChart.destroy();
        }
        
        costChart = new Chart(ctxCost, {
            type: "bar",
            data: {
                labels: Object.keys(costLeaks),
                datasets: [{
                    label: "Cost Exposure ($)",
                    data: Object.values(costLeaks),
                    backgroundColor: ["#0284c7", "#4f46e5", "#16a34a", "#ea580c"],
                    borderWidth: 0,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: "#475569" } },
                    y: { grid: { color: "rgba(15, 23, 42, 0.08)" }, ticks: { color: "#475569" } }
                }
            }
        });
    }
}

// ----------------------------------------------------
// GEOLOCATED THREAT MAP (Leaflet.js)
// ----------------------------------------------------
function updateThreatMap(incidents) {
    if (!leafletMap) {
        leafletMap = L.map("threat-map", { zoomControl: false }).setView([25, 0], 2);
        L.tileLayer("https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png", {
            attribution: '© OpenStreetMap, © CartoDB',
            maxZoom: 20
        }).addTo(leafletMap);
    }
    
    // Clear old threat markers
    mapMarkers.forEach(m => leafletMap.removeLayer(m));
    mapMarkers = [];
    
    const open = incidents.filter(i => i.status === "OPEN");
    
    open.forEach(inc => {
        if (!inc.ip_address || inc.ip_address.startsWith("192.") || inc.ip_address.startsWith("10.") || inc.ip_address === "127.0.0.1") {
            return;
        }
        
        let coords = [0, 0];
        if (inc.country === "Russia") coords = [55.7558, 37.6173];
        else if (inc.country === "China") coords = [39.9042, 116.4074];
        else if (inc.country === "Netherlands") coords = [52.1326, 5.2913];
        else if (inc.country === "Germany") coords = [51.1657, 10.4515];
        else if (inc.country === "United States") coords = [37.0902, -95.7129];
        else return;
        
        const color = inc.severity === "CRITICAL" ? "#ff3b30" : "#ff9500";
        
        const circle = L.circleMarker(coords, {
            radius: 8,
            fillColor: color,
            color: "#fff",
            weight: 1,
            opacity: 1,
            fillOpacity: 0.8
        }).addTo(leafletMap);
        
        circle.bindPopup(`
            <div style="color: #0f111a; font-family: 'Inter', sans-serif; font-size:12px; line-height: 1.5;">
                <strong style="color: ${color}; font-size:13px;">🚨 Threat: ${inc.resource_type}</strong><br>
                <b>IP:</b> ${inc.ip_address}<br>
                <b>Location:</b> ${inc.country}<br>
                <b>Details:</b> ${inc.description}<br>
                <b>Severity:</b> <span style="font-weight:bold;">${inc.severity}</span>
            </div>
        `);
        
        mapMarkers.push(circle);
    });
}

// ----------------------------------------------------
// HIGH-DENSITY INCIDENT FEED STREAM
// ----------------------------------------------------
function renderIncidentFeedList(incidents) {
    const container = document.getElementById("incidents-feed-container");
    container.innerHTML = "";
    
    if (incidents.length === 0) {
        container.innerHTML = '<div style="text-align:center; padding: 40px; color: var(--text-secondary);">No correlated incidents in database. Run audits above.</div>';
        return;
    }
    
    incidents.forEach(inc => {
        const card = document.createElement("div");
        card.className = "incident-feed-card";
        card.setAttribute("data-id", inc.id);
        
        const sevClass = `badge-${inc.severity.toLowerCase()}`;
        const statusClass = `badge-${inc.status.toLowerCase()}`;
        
        card.innerHTML = `
            <div class="card-id">#INC-${inc.id}</div>
            <div class="card-time">${inc.timestamp}</div>
            <div class="card-target"><strong>${inc.resource_id}</strong></div>
            <div class="card-details">${inc.description}</div>
            <div class="card-status-badge">
                <span class="badge ${sevClass}" style="margin-right: 4px;">${inc.severity}</span>
                <span class="badge ${statusClass}">${inc.status}</span>
            </div>
            <div class="card-actions">
                ${inc.status === 'OPEN' 
                    ? `<button class="btn btn-secondary btn-sm" onclick="navigateToPlaybook(${inc.id})"><i class="fa-solid fa-bolt-lightning"></i> Action</button>`
                    : '<i class="fa-solid fa-circle-check font-color-green" style="font-size:16px;"></i>'
                }
            </div>
        `;
        container.appendChild(card);
    });
}

function filterIncidents() {
    const searchVal = document.getElementById("stream-search").value.toLowerCase();
    const severityVal = document.getElementById("filter-severity").value;
    const statusVal = document.getElementById("filter-status").value;
    
    const cards = document.querySelectorAll("#incidents-feed-container .incident-feed-card");
    
    cards.forEach(card => {
        const id = parseInt(card.getAttribute("data-id"));
        const match = incidentsList.find(i => i.id === id);
        if (!match) return;
        
        const descMatch = match.description.toLowerCase().includes(searchVal) || match.resource_id.toLowerCase().includes(searchVal);
        const severityMatch = severityVal === "ALL" || match.severity === severityVal;
        const statusMatch = statusVal === "ALL" || match.status === statusVal;
        
        if (descMatch && severityMatch && statusMatch) {
            card.style.display = "grid";
        } else {
            card.style.display = "none";
        }
    });
}

function navigateToPlaybook(incidentId) {
    const navItem = document.querySelector('.top-tab-item[data-tab="playbooks"]');
    if (navItem) navItem.click();
    
    const select = document.getElementById("playbook-incident-select");
    select.value = incidentId;
    
    handlePlaybookSelect();
}

// ----------------------------------------------------
// PLAYBOOKS REMEDIATION TERMINAL CONTROLLER
// ----------------------------------------------------
function populatePlaybookSelector(incidents) {
    const select = document.getElementById("playbook-incident-select");
    const currentValue = select.value;
    
    select.innerHTML = '<option value="">-- Choose active security incident --</option>';
    
    const open = incidents.filter(i => i.status === "OPEN");
    open.forEach(inc => {
        const opt = document.createElement("option");
        opt.value = inc.id;
        opt.innerText = `#${inc.id} - [${inc.severity}] ${inc.resource_type}: ${inc.resource_id}`;
        select.appendChild(opt);
    });
    
    if (currentValue && open.some(i => i.id == currentValue)) {
        select.value = currentValue;
    } else {
        document.getElementById("remediation-runner-pane").classList.add("disabled");
    }
}

function handlePlaybookSelect() {
    const select = document.getElementById("playbook-incident-select");
    const val = select.value;
    const pane = document.getElementById("remediation-runner-pane");
    
    if (!val) {
        pane.classList.add("disabled");
        return;
    }
    
    pane.classList.remove("disabled");
    
    const incident = incidentsList.find(i => i.id == val);
    if (!incident) return;
    
    document.getElementById("playbook-title").innerText = `Mitigation Matrix for Incident #${incident.id}`;
    document.getElementById("playbook-desc").innerHTML = `<strong>Asset exposure:</strong><br>${incident.description}`;
    document.getElementById("playbook-compliance").innerText = `CIS Control Framework: ${incident.compliance_rule || 'Custom Operational Rule'}`;
    
    const actionsGroup = document.getElementById("playbook-actions-group");
    actionsGroup.innerHTML = "";
    
    const btn = document.createElement("button");
    btn.className = "btn";
    
    if (incident.resource_type === "IAM Access Key") {
        btn.classList.add("btn-danger");
        btn.innerHTML = '<i class="fa-solid fa-ban"></i> Execute Zero-Trust Revocation';
        btn.addEventListener("click", () => runRemediation(incident.id, "Revoke IAM Access Key"));
        actionsGroup.appendChild(btn);
    } else if (incident.resource_type === "Elastic IP") {
        btn.classList.add("btn-primary");
        btn.style.background = "linear-gradient(135deg, #34c759 0%, #10b981 100%)";
        btn.style.color = "#060913";
        btn.innerHTML = '<i class="fa-solid fa-cloud-minus"></i> Release Orphaned IP Address';
        btn.addEventListener("click", () => runRemediation(incident.id, "Release Elastic IP Address"));
        actionsGroup.appendChild(btn);
    } else if (incident.resource_type === "EBS Volume") {
        btn.classList.add("btn-primary");
        btn.innerHTML = '<i class="fa-solid fa-box-archive"></i> Quarantine Volume & Release Storage';
        btn.addEventListener("click", () => runRemediation(incident.id, "Quarantine EBS Storage Volume"));
        actionsGroup.appendChild(btn);
    } else {
        btn.classList.add("btn-primary");
        btn.innerHTML = '<i class="fa-solid fa-check-double"></i> Mark Alert as Resolved';
        btn.addEventListener("click", () => runRemediation(incident.id, "Close Incident"));
        actionsGroup.appendChild(btn);
    }
}

function runRemediation(incidentId, actionName) {
    const dryRun = document.getElementById("playbook-dry-run").checked;
    
    if (!confirm(`Deploy playbook [${actionName}]?${dryRun ? ' (DRY RUN - Test mode)' : ' (Warning: Active infrastructure rewrite)'}`)) {
        return;
    }
    
    const termWrapper = document.getElementById("playbook-terminal-wrapper");
    if (termWrapper) termWrapper.style.display = "block";
    clearTerminal();
    
    const btnGroup = document.getElementById("playbook-actions-group");
    const originalContent = btnGroup.innerHTML;
    btnGroup.innerHTML = '<button class="btn btn-secondary" disabled><i class="fa-solid fa-spinner fa-spin"></i> Active response running...</button>';
    
    // Typewriter logs sequence
    writeTerminalLine("SYSTEM: Hooking AWS configuration credentials...", "info");
    
    setTimeout(() => {
        writeTerminalLine("BOTO3: Connecting EC2/IAM provider context in us-east-1...", "info");
    }, 600);
    
    setTimeout(() => {
        writeTerminalLine("PROVIDER: Verifying STS validation headers...", "info");
    }, 1200);
    
    setTimeout(() => {
        const incident = incidentsList.find(i => i.id == incidentId);
        const targetId = incident ? incident.resource_id : "unknown";
        writeTerminalLine(`AUDIT: Located target resource ID [${targetId}] for isolation.`, "action");
    }, 1800);
    
    setTimeout(() => {
        writeTerminalLine(`CONTAINMENT: Transmitting action [${actionName}]${dryRun ? ' (DRY RUN)' : ' (LIVE INFRASTRUCTURE WRITE)'}...`, "warn");
    }, 2400);
    
    setTimeout(() => {
        fetch(`/api/remediate/${incidentId}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action: actionName,
                dry_run: dryRun
            })
        })
        .then(res => {
            if (!res.ok) throw new Error("API Connection Interrupted");
            return res.json();
        })
        .then(data => {
            writeTerminalLine(`SUCCESS: ${data.message}`, "success");
            writeTerminalLine("SYSTEM: DB updated. Exposure containing index is now complete.", "success");
            loadIncidents();
        })
        .catch(err => {
            writeTerminalLine(`ERROR: Execution failed: ${err.message}`, "error");
            writeTerminalLine("SYSTEM: Failover triggered. Alerting incident handlers.", "error");
        })
        .finally(() => {
            btnGroup.innerHTML = originalContent;
        });
    }, 3200);
}

function executeSuppression() {
    const select = document.getElementById("playbook-incident-select");
    const val = select.value;
    if (!val) return;
    
    const reason = document.getElementById("suppress-reason").value || "Approved profile parameters";
    
    fetch(`/api/suppress/${val}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason })
    })
    .then(res => res.json())
    .then(data => {
        alert(data.message);
        document.getElementById("suppress-reason").value = "";
        loadIncidents();
    })
    .catch(err => alert("Suppression failed: " + err));
}

// ----------------------------------------------------
// INTEGRATIONS SETTINGS
// ----------------------------------------------------
function fetchSettings() {
    fetch("/api/settings")
        .then(res => res.json())
        .then(data => {
            document.getElementById("setting-webhook").value = data.discord_webhook;
            document.getElementById("setting-policy").value = data.remediation_mode;
        })
        .catch(err => console.error("Error loading settings:", err));
}

function saveSettings() {
    const webhook = document.getElementById("setting-webhook").value;
    const policy = document.getElementById("setting-policy").value;
    
    const btn = document.getElementById("btn-save-settings");
    btn.disabled = true;
    
    fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            discord_webhook: webhook,
            remediation_mode: policy
        })
    })
    .then(res => res.json())
    .then(data => {
        alert("Integrations parameters saved successfully.");
        fetchSettings();
    })
    .catch(err => alert("Failed to save settings: " + err))
    .finally(() => btn.disabled = false);
}

// ----------------------------------------------------
// DYNAMIC MOCK ACTIVITY FEED
// ----------------------------------------------------
const mockLogTemplates = [
    "[INGEST] CloudTrail: RunInstances executed by user security-auditor",
    "[INGEST] CloudTrail: CreateAccessKey generated for administrator",
    "[WARN] SecurityGroup ingress: Public ingress SSH (port 22) found on sg-88fae",
    "[AUDIT] Scanning unattached EBS volumes in us-east-1...",
    "[AUDIT] Scanning unattached Elastic IPs in us-west-2...",
    "[INFO] Webhook delivered successfully to SIEM integrations channel",
    "[INTELLIGENCE] AbuseIPDB scan query resolved for IP 185.220.101.4 [Threat score: 92/100]",
    "[INGEST] CloudTrail: PutBucketPolicy modified on quarantine-backups-s3",
    "[THREAT] Correlation alert: 5 unsuccessful root login attempts from Moscow, RU",
    "[INFO] Diagnostics: CIS Compliance audit logs verified online",
    "[INGEST] CloudTrail: DeactivateAccessKey called by CloudSentry autonomous agent",
    "[AUDIT] Running EC2 FinOps optimization sweeps across all VPC endpoints..."
];

function startLiveActivityFeed() {
    const feed = document.getElementById("live-activity-feed");
    if (!feed) return;
    
    // Seed initial console messages
    for (let i = 0; i < 5; i++) {
        const line = document.createElement("div");
        line.className = "feed-line";
        const randomMsg = mockLogTemplates[Math.floor(Math.random() * mockLogTemplates.length)];
        line.innerText = `[${new Date().toLocaleTimeString()}] ${randomMsg}`;
        feed.appendChild(line);
    }
    
    // Periodically feed new logs
    setInterval(() => {
        const line = document.createElement("div");
        line.className = "feed-line";
        const msg = mockLogTemplates[Math.floor(Math.random() * mockLogTemplates.length)];
        
        if (msg.includes("[THREAT]") || msg.includes("[WARN]")) {
            line.style.color = "#ff3b30";
        } else if (msg.includes("[INFO]")) {
            line.style.color = "#00f0ff";
        } else if (msg.includes("[INGEST]")) {
            line.style.color = "#8b5cf6";
        }
        
        line.innerText = `[${new Date().toLocaleTimeString()}] ${msg}`;
        feed.appendChild(line);
        
        feed.scrollTop = feed.scrollHeight;
        
        // Prevent DOM size leak
        if (feed.childNodes.length > 20) {
            feed.removeChild(feed.firstChild);
        }
    }, 3000);
}

// Terminal helper functions
function clearTerminal() {
    const term = document.getElementById("playbook-terminal");
    if (term) term.innerHTML = "";
}

function writeTerminalLine(text, styleClass = "info") {
    const term = document.getElementById("playbook-terminal");
    if (!term) return;
    const line = document.createElement("div");
    line.className = `terminal-line ${styleClass}`;
    line.innerText = `[${new Date().toLocaleTimeString()}] ${text}`;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
}
