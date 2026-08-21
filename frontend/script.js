let lastReport = null;
let currentRisks = null;
let currentUrl = '';
let currentHeader = null;
let currentScanId = '';


const urlInput = document.getElementById("urlInput");
const submitBtn = document.getElementById("submitBtn");
const output = document.getElementById("errorText");
const errorMsg = document.getElementById("errorMsg");
const clearInputBtn = document.getElementById("clearInputBtn");
const spinner = document.getElementById("btnIcon");
const btnText = document.getElementById("btnText");
const resultsSection = document.getElementById("resultsSection");
const risksContainer = document.getElementById("risksContainer");
const risksList = document.getElementById("risksList");
const displayUrl = document.getElementById("displayUrl");
const clearResultsBtn = document.getElementById("clearResultsBtn");
const analysisForm = document.getElementById("analysisForm");
const scanId = document.getElementById('scanId');
const moduleCount = document.getElementById('moduleCount');
const scorePanel = document.getElementById('score-panel');
const findingsSummary = document.getElementById('findings-summary');
const exportButtons = ['save-json', 'save-markdown', 'save-html']
    .map(id => document.getElementById(id));


function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = String(value);
    return div.innerHTML;
}


analysisForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const url = urlInput.value.trim();
    if (!url) {
        showError("Please enter a valid URL.");
        return;
    }

    errorMsg.classList.add('hidden');
    setLoading(true);

    try {
        const response = await fetch(`http://127.0.0.1:8000/analyze?url=${encodeURIComponent(url)}`);
        if (!response.ok) {
            const errData = await response.json();
            showError(errData.detail || "Something went wrong");
            return;
        }

        const data = await response.json();
        lastReport = data;

        displayUrl.textContent = data.url;

        resultsSection.classList.remove("hidden");
        risksContainer.classList.remove("hidden");
        risksList.innerHTML = "";

        renderScore(data.score);
        renderSummary(data.summary);
        setExportEnabled(true);

        currentUrl = url;
        currentHeader = data.headers;
        currentRisks = data.analysis;

        scanId.textContent = Math.random().toString(36).substr(2, 9).toUpperCase();
        currentScanId = scanId.textContent;

        moduleCount.textContent = `${currentRisks.length} Modules Loaded`;

        if (currentRisks.length === 0) {
            risksList.innerHTML = `
                <div class="p-4 bg-green-50 border-l-4 border-l-green-500 flex items-center">
                    <i data-lucide="check-circle-2" class="w-5 h-5 text-green-600 mr-3"></i>
                    <span class="text-sm font-medium text-green-700">No significant security issues found.</span>
                </div>`;
        } else {
            currentRisks.forEach((risk) => {
                risksList.innerHTML += createRiskHtml(risk);
            });
        }

        lucide.createIcons();

        const duration = data.timing.backend_seconds.toFixed(2);
        document.getElementById("scanTime").textContent = `${duration}s`;

    } catch (error) {
        console.error("Scan error:", error);
        let msg = "An error occurred while processing your request.";

        if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
            msg = "Network Error: Could not connect to the backend server. Is it running?";
        }

        showError(msg);
        clearAll()
    } finally {
        setLoading(false);
    }
})


// --- Score Panel ---
function renderScore(score) {
    if (!score) {
        scorePanel.classList.add("hidden");
        return;
    }

    scorePanel.classList.remove("hidden");

    const gradeEl = document.getElementById("score-grade");
    const riskEl = document.getElementById("score-risk");

    document.getElementById("score-value").textContent = score.value;
    gradeEl.textContent = score.grade;
    gradeEl.className = `grade-${String(score.grade).toLowerCase()}`;
    riskEl.textContent = score.risk_level;
    riskEl.className = `risk-${String(score.risk_level).toLowerCase()}`;
    document.getElementById("score-penalty").textContent = score.penalty;
}


// --- Findings Summary ---
function renderSummary(summary) {
    if (!summary) {
        findingsSummary.classList.add("hidden");
        return;
    }

    findingsSummary.classList.remove("hidden");

    document.getElementById("total-findings").textContent = summary.total_findings;
    document.getElementById("high-findings").textContent = summary.high;
    document.getElementById("medium-findings").textContent = summary.medium;
    document.getElementById("low-findings").textContent = summary.low;
}


// --- Helper: Render Risk HTML ---
const createRiskHtml = (risk) => {
    let severityColor = '';
    let severityBg = '';
    let iconName = 'alert-circle';

    switch (risk.severity) {
        case 'HIGH':
            severityColor = 'text-red-600';
            severityBg = 'bg-red-50 border-l-4 border-l-red-500';
            break;
        case 'MEDIUM':
            severityColor = 'text-orange-600';
            severityBg = 'bg-orange-50 border-l-4 border-l-orange-500';
            iconName = 'alert-triangle';
            break;
        case 'LOW':
            severityColor = 'text-blue-600';
            severityBg = 'bg-blue-50 border-l-4 border-l-blue-500';
            iconName = 'info';
            break;
        default:
            severityColor = 'text-gray-600';
            severityBg = 'bg-gray-50';
    }

    return `
                <div class="p-4 ${severityBg} hover:bg-opacity-80 transition-colors">
                    <div class="flex items-start">
                        <div class="flex-shrink-0 mt-0.5">
                            <i data-lucide="${iconName}" class="w-5 h-5 ${severityColor}"></i>
                        </div>
                        <div class="ml-3 w-full">
                            <div class="flex items-center justify-between mb-1">
                                <h4 class="text-sm font-bold ${severityColor}">${escapeHtml(risk.issue)}</h4>
                                <span class="flex items-center gap-2">
                                    <span class="rule-id">${escapeHtml(risk.id || "N/A")}</span>
                                    <span class="px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wide bg-white border border-gray-200 ${severityColor}">
                                        ${escapeHtml(risk.severity)}
                                    </span>
                                </span>
                            </div>
                            <p class="text-sm text-gray-700 mt-1"><span class="font-semibold">Risk:</span> ${escapeHtml(risk.risk)}</p>
                            <div class="mt-2 text-sm bg-white/60 p-2 rounded border border-gray-200/50">
                                <span class="font-semibold text-gray-600">Fix:</span> <code class="text-indigo-600 font-mono text-xs break-all">${escapeHtml(risk.fix)}</code>
                            </div>
                        </div>
                    </div>
                </div>
            `;
};

const setLoading = (isLoading) => {
    urlInput.disabled = isLoading;
    submitBtn.disabled = isLoading;

    if (isLoading) {
        submitBtn.classList.add('bg-gray-400', 'cursor-not-allowed');
        submitBtn.classList.remove(
            'bg-indigo-600',
            'hover:bg-indigo-700',
            'hover:shadow-indigo-500/30'
        );

        btnIcon.classList.remove('hidden');
        btnText.textContent = 'Processing';

        glowEffect.classList.add('animate-pulse');

    } else {
        submitBtn.classList.remove('bg-gray-400', 'cursor-not-allowed');
        submitBtn.classList.add(
            'bg-indigo-600',
            'hover:bg-indigo-700',
            'hover:shadow-indigo-500/30'
        );

        btnIcon.classList.add('hidden');
        btnText.textContent = 'Analyze';

        glowEffect.classList.remove('animate-pulse');
    }
};

const setExportEnabled = (enabled) => {
    exportButtons.forEach((btn) => {
        btn.disabled = !enabled;
    });
};

// --- Client-side exports ---
function downloadFile(filename, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
}

function safeName(url) {
    return String(url)
        .replace(/^https?:\/\//, '')
        .replace(/[^\w.-]/g, '_')
        .slice(0, 60) || "scan";
}

function buildMarkdown(report) {
    const lines = [];
    lines.push("# Argus Header Security Report", "");
    lines.push("## Scan Information", "");
    lines.push(`- **Target:** \`${report.url}\``);
    lines.push(`- **Status:** \`${report.status}\``);
    lines.push(`- **Backend time:** \`${report.timing.backend_seconds}s\``);
    lines.push("");
    lines.push("## Security Score", "");
    lines.push(`**${report.score.value} / 100 — Grade ${report.score.grade}**`, "");
    lines.push(`- **Risk Level:** ${report.score.risk_level}`);
    lines.push(`- **Penalty:** ${report.score.penalty}`, "");
    lines.push("## Findings Summary", "");
    lines.push(`- **Total:** ${report.summary.total_findings}`);
    lines.push(`- **High:** ${report.summary.high}`);
    lines.push(`- **Medium:** ${report.summary.medium}`);
    lines.push(`- **Low:** ${report.summary.low}`, "");
    lines.push("## Findings", "");

    if (!report.analysis.length) {
        lines.push("✅ No significant security issues found.", "");
    } else {
        report.analysis.forEach((f) => {
            lines.push(`### [${f.severity}] ${f.issue}`, "");
            lines.push(`- **Rule ID:** \`${f.id}\``);
            lines.push(`- **Category:** ${f.category}`);
            lines.push(`- **Risk:** ${f.risk}`);
            lines.push(`- **Fix:** ${f.fix}`, "");
        });
    }

    lines.push("---", "");
    lines.push("*Generated by Argus Header Web Dashboard*", "");
    return lines.join("\n");
}

function buildStandaloneHtml(report) {
    const esc = escapeHtml;
    const findingsHtml = report.analysis.map((f) => `
        <article class="finding">
            <div class="finding-header">
                <span class="severity severity-${esc(f.severity.toLowerCase())}">${esc(f.severity)}</span>
                <span class="rule-id">${esc(f.id)}</span>
            </div>
            <h3>${esc(f.issue)}</h3>
            <p><strong>Category:</strong> ${esc(f.category)}</p>
            <p><strong>Risk:</strong> ${esc(f.risk)}</p>
            <p><strong>Fix:</strong> ${esc(f.fix)}</p>
        </article>`).join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Argus Header Security Report</title>
<style>
body{background:#0b0f14;color:#e8edf2;font-family:system-ui,sans-serif;line-height:1.6;margin:0;padding:40px}
h1{margin-top:0}.muted{color:#98a6b5}
.panel{background:#111820;border:1px solid #26313d;border-radius:12px;padding:20px;margin:16px 0;max-width:900px}
.score-number{font-size:44px;font-weight:800}
.finding{background:#111820;border:1px solid #26313d;border-radius:12px;padding:16px;margin:10px 0;max-width:900px}
.finding-header{display:flex;justify-content:space-between}
.severity{font-size:12px;font-weight:800;border-radius:999px;padding:4px 10px}
.severity-high{background:rgba(239,68,68,.15);color:#f87171}
.severity-medium{background:rgba(245,158,11,.15);color:#fbbf24}
.severity-low{background:rgba(59,130,246,.15);color:#60a5fa}
.rule-id{color:#98a6b5;font-family:monospace;font-size:12px}
table{border-collapse:collapse;width:100%;max-width:900px}
td{padding:8px;border-bottom:1px solid #26313d;word-break:break-word}
code{color:#93c5fd}
</style>
</head>
<body>
<h1>Argus Header Security Report</h1>
<p class="muted">Target: <code>${esc(report.url)}</code> &middot; Status: ${esc(report.status)}</p>
<div class="panel">
<span class="score-number">${esc(report.score.value)}/100</span>
&mdash; Grade <strong>${esc(report.score.grade)}</strong> &middot; Risk: ${esc(report.score.risk_level)} &middot; Penalty: ${esc(report.score.penalty)}
</div>
<div class="panel">Findings: ${report.summary.total_findings} (H:${report.summary.high} M:${report.summary.medium} L:${report.summary.low})</div>
${findingsHtml || '<div class="panel">✅ No significant security issues found.</div>'}
<footer class="muted" style="margin-top:24px">Generated by Argus Header Web Dashboard</footer>
</body>
</html>`;
}

document.getElementById("save-json").addEventListener("click", () => {
    if (!lastReport) return;
    downloadFile(
        `argus-${safeName(currentUrl)}.json`,
        JSON.stringify(lastReport, null, 2),
        "application/json"
    );
});

document.getElementById("save-markdown").addEventListener("click", () => {
    if (!lastReport) return;
    downloadFile(
        `argus-${safeName(currentUrl)}.md`,
        buildMarkdown(lastReport),
        "text/markdown"
    );
});

document.getElementById("save-html").addEventListener("click", () => {
    if (!lastReport) return;
    downloadFile(
        `argus-${safeName(currentUrl)}.html`,
        buildStandaloneHtml(lastReport),
        "text/html"
    );
});


// --- Event: Clear Results ---
urlInput.addEventListener("input", (e) => {
    if (e.target.value.length > 0) {
        clearInputBtn.classList.remove("hidden");
    } else {
        clearInputBtn.classList.add("hidden");
    }
});

// Clear Input
clearInputBtn.addEventListener('click', () => {
    urlInput.value = '';
    clearInputBtn.classList.add('hidden');
    clearAll();
});

clearResultsBtn.addEventListener('click', () => {
    clearAll();
});


// Clear all 
function clearAll() {
    output.textContent = "";
    resultsSection.classList.add("hidden");
    risksList.innerHTML = "";
    displayUrl.textContent = "";
    urlInput.value = '';
    clearInputBtn.classList.add('hidden');
    lastReport = null;
    setExportEnabled(false);
}

const showError = (msg) => {
    errorText.textContent = msg;
    errorMsg.classList.remove('hidden');
};

document.addEventListener("DOMContentLoaded", () => {
    lucide.createIcons();
    clearInputBtn.classList.add('hidden');
    setExportEnabled(false);

});
