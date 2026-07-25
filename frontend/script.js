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
const saveReportBtn = document.getElementById("saveReportBtn");
const analysisForm = document.getElementById("analysisForm");
const saveText = document.getElementById('saveText');
const scanId = document.getElementById('scanId');
const moduleCount = document.getElementById('moduleCount');


output.textContent = "scanning... please wait";

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
        // if (!response.ok) {
        //     showError(`Error: ${response.status} ${response.statusText} ${response.error}`);
        //     return;
        // }
        if (!response.ok) {
            const errData = await response.json();
            showError(errData.detail || "Something went wrong");
            return;
        }

        const data = await response.json();

        displayUrl.textContent = data.url;

        resultsSection.classList.remove("hidden");
        risksContainer.classList.remove("hidden");
        risksList.innerHTML = "";

        currentUrl = url;
        currentHeader = data.headers;
        currentRisks = data.analysis;


        scanId.textContent = Math.random().toString(36).substr(2, 9).toUpperCase();

        moduleCount.textContent = `${currentRisks.length} Modules Loaded`;


        currentScanId = scanId.textContent;

        currentRisks.forEach((risk) => {
            const riskHtml = createRiskHtml(risk);
            risksList.innerHTML += riskHtml;
        });

        // ⏱ Processing time

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
                                <h4 class="text-sm font-bold ${severityColor}">${risk.issue}</h4>
                                <span class="px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wide bg-white border border-gray-200 ${severityColor}">
                                    ${risk.severity}
                                </span>
                            </div>
                            <p class="text-sm text-gray-700 mt-1"><span class="font-semibold">Risk:</span> ${risk.risk}</p>
                            <div class="mt-2 text-sm bg-white/60 p-2 rounded border border-gray-200/50">
                                <span class="font-semibold text-gray-600">Fix:</span> <code class="text-indigo-600 font-mono text-xs break-all">${risk.fix}</code>
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

const setSavedState = (isSaved) => {
    if (isSaved) {
        saveReportBtn.className = "px-4 py-2 rounded-lg text-sm font-medium flex items-center space-x-2 transition-all duration-200 bg-green-100 text-green-700 border border-green-200";
        saveText.textContent = "Saved!";
        const icon = document.createElement('i');
        icon.setAttribute('data-lucide', 'check-circle');
        icon.className = "w-4 h-4";
        saveReportBtn.replaceChild(icon, saveReportBtn.firstElementChild);
        lucide.createIcons();
    } else {
        saveReportBtn.className = "px-4 py-2 rounded-lg text-sm font-medium flex items-center space-x-2 transition-all duration-200 bg-white border border-gray-300 text-gray-700 hover:bg-gray-50 hover:border-indigo-300 hover:text-indigo-600";
        saveText.textContent = "Save JSON";
        const icon = document.createElement('i');
        icon.setAttribute('data-lucide', 'download');
        icon.className = "w-4 h-4";
        saveReportBtn.replaceChild(icon, saveReportBtn.firstElementChild);
        lucide.createIcons();
    }
}

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
}

const showError = (msg) => {
    errorText.textContent = msg;
    errorMsg.classList.remove('hidden');
};

document.addEventListener("DOMContentLoaded", () => {
    lucide.createIcons();
    clearInputBtn.classList.add('hidden');

});

function downloadReport() {
    if (!Array.isArray(currentRisks) || currentRisks.length === 0) {
        return;
    }

    const safeUrl = currentUrl
        .replace(/^https?:\/\//, '')
        .replace(/[^\w.-]/g, '_');

    const exportData = {
        scan_id: currentScanId,
        url: currentUrl,
        timestamp: new Date().toISOString(),
        headers: currentHeader || {},
        security_risks: currentRisks
    };

    const fileData = JSON.stringify(exportData, null, 2);
    const blob = new Blob([fileData], { type: 'application/json' });

    const objectUrl = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = `analysis-${safeUrl}-${Date.now()}.json`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(objectUrl);

    setSavedState(true);
    setTimeout(() => setSavedState(false), 3000);
}

saveReportBtn.addEventListener('click', downloadReport);