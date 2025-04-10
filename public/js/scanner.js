// DOM Elements
const scanTarget = document.getElementById('scan-target');
const startScanBtn = document.getElementById('start-scan');
const scanResults = document.getElementById('scan-results');
const scanHistory = document.getElementById('scan-history');
const quickScanOption = document.getElementById('quick-scan');
const serviceDetectionOption = document.getElementById('service-detection');
const osDetectionOption = document.getElementById('os-detection');

// Initialize scanner functionality
export function initScanner() {
    // Add event listeners
    startScanBtn.addEventListener('click', startScan);
    
    // Load scan history when initialized
    loadScanHistory();
    
    // Add scanner icon to sidebar if it doesn't exist
    if (!document.querySelector('.sidebar-icon[data-page="scanner"]')) {
        const scannerIcon = document.createElement('i');
        scannerIcon.className = 'fas fa-search sidebar-icon';
        scannerIcon.title = 'Network Scanner';
        scannerIcon.dataset.page = 'scanner';
        document.querySelector('.sidebar').appendChild(scannerIcon);
    }
}

// Load scan history from server
async function loadScanHistory() {
    try {
        scanHistory.textContent = "Loading scan history...";
        const response = await fetch('/api/scan-history');
        const data = await response.json();
        
        if (data.success) {
            scanHistory.textContent = data.history || "No scan history available.";
        } else {
            scanHistory.textContent = "Error loading scan history.";
        }
    } catch (error) {
        console.error("Error loading scan history:", error);
        scanHistory.textContent = "Error loading scan history.";
    }
}

// Start a new scan
async function startScan() {
    const target = scanTarget.value.trim();
    if (!target) {
        alert("Please enter a target IP or hostname");
        return;
    }
    
    // Get scan options
    const options = {
        quick: quickScanOption.checked,
        service: serviceDetectionOption.checked,
        os: osDetectionOption.checked
    };
    
    scanResults.textContent = "Scanning... Please wait.";
    startScanBtn.disabled = true;
    startScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
    
    try {
        const response = await fetch(`/api/scan?target=${encodeURIComponent(target)}`);
        const data = await response.json();
        
        if (data.success) {
            scanResults.textContent = data.results;
            await loadScanHistory(); // Refresh history after new scan
        } else {
            scanResults.textContent = "Scan failed: " + (data.error || "Unknown error");
        }
    } catch (error) {
        console.error("Scan error:", error);
        scanResults.textContent = "Scan failed: " + error.message;
    } finally {
        startScanBtn.disabled = false;
        startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
    }
}

// Initialize scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', initScanner);