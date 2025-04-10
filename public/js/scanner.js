// DOM Elements
const scanTarget = document.getElementById('scan-target');
const startScanBtn = document.getElementById('start-scan');
const scanResults = document.getElementById('scan-results');
const scanHistory = document.getElementById('scan-history');
const quickScanOption = document.getElementById('quick-scan');
const serviceDetectionOption = document.getElementById('service-detection');
const osDetectionOption = document.getElementById('os-detection');

// Initialize scanner functionality
function initScanner() {
    // Set default target to AP subnet and make read-only
    scanTarget.value = '192.168.4.0/24';
    scanTarget.readOnly = true;
    
    // Add event listeners
    startScanBtn.addEventListener('click', startScan);
    
    // Load initial scan history
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
        const response = await fetch('/api/scan-history', {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('authToken')}`
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        scanHistory.textContent = data.history || "No scan history available.";
    } catch (error) {
        console.error("Error loading history:", error);
        scanHistory.textContent = "Error loading scan history. Please try again.";
        if (error.message.includes('401')) {
            // Handle unauthorized access
            window.location.href = '/';
        }
    }
}

// Start a new scan
async function startScan() {
    const scanOptions = {
        quick: quickScanOption.checked,
        service: serviceDetectionOption.checked,
        os: osDetectionOption.checked
    };
    
    scanResults.textContent = "Scanning network... This may take 2-5 minutes";
    startScanBtn.disabled = true;
    startScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
    
    try {
        const response = await fetch('/api/scan', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('authToken')}`
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error(`Invalid response: ${text.substring(0, 100)}`);
        }

        const data = await response.json();
        
        if (data.success) {
            // Format the results for better readability
            scanResults.textContent = formatScanResults(data.results);
        } else {
            scanResults.textContent = "Scan completed with issues: " + (data.error || "Unknown error");
        }
        
        // Refresh history after new scan
        await loadScanHistory();
    } catch (error) {
        console.error("Scan failed:", error);
        scanResults.textContent = `Scan failed: ${error.message}`;
        
        if (error.message.includes('401')) {
            // Handle unauthorized access
            window.location.href = '/';
        }
    } finally {
        startScanBtn.disabled = false;
        startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
    }
}

// Format raw Nmap results for display
function formatScanResults(rawResults) {
    try {
        // Try to parse as JSON first
        const jsonData = JSON.parse(rawResults);
        return formatJsonResults(jsonData);
    } catch (e) {
        // If not JSON, return raw results with basic formatting
        return rawResults
            .split('\n')
            .filter(line => line.trim())
            .map(line => {
                if (line.includes('⚠️') || line.includes('CRITICAL')) {
                    return `<span class="text-danger">${line}</span>`;
                }
                if (line.includes('Recommendation')) {
                    return `<span class="text-warning">${line}</span>`;
                }
                return line;
            })
            .join('\n');
    }
}

// Format JSON scan results
function formatJsonResults(jsonData) {
    let output = [];
    
    if (jsonData.nmaprun && jsonData.nmaprun.host) {
        const hosts = Array.isArray(jsonData.nmaprun.host) 
            ? jsonData.nmaprun.host 
            : [jsonData.nmaprun.host];
            
        hosts.forEach(host => {
            if (host.address && host.address.addr) {
                output.push(`\nDevice: ${host.address.addr}`);
                
                if (host.ports && host.ports.port) {
                    const ports = Array.isArray(host.ports.port) 
                        ? host.ports.port 
                        : [host.ports.port];
                        
                    ports.forEach(port => {
                        output.push(`  Port ${port.portid}/${port.protocol}: ${port.service.name}`);
                        
                        if (port.script) {
                            const scripts = Array.isArray(port.script) 
                                ? port.script 
                                : [port.script];
                                
                            scripts.forEach(script => {
                                output.push(`    ${script.id}: ${script.output}`);
                            });
                        }
                    });
                }
            }
        });
    }
    
    return output.join('\n');
}

// Initialize scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', initScanner);

// Add click handler for sidebar navigation
document.querySelector('.sidebar').addEventListener('click', (e) => {
    if (e.target.classList.contains('sidebar-icon')) {
        // Handle navigation to scanner page
        if (e.target.dataset.page === 'scanner') {
            loadScanHistory();
        }
    }
});