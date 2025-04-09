// Severity classification
const severityMap = {
    'DHCP Spoofing Detected': 'critical',
    'Insecure Protocol Detected': 'high',
    'SSH Traffic': 'medium',
    'ICMP Packet': 'low'
};

// Modified to fetch from Node.js API
async function loadAlertsFromLog() {
    try {
        const response = await fetch('/api/alerts');
        if (!response.ok) throw new Error("Network response was not ok");
        
        const result = await response.json();
        if (!result.success) throw new Error(result.error || "Unknown error");
        
        displayAlerts(result.alerts);
        updateDashboardCounters(result.alerts);
    } catch (error) {
        console.error("Error loading alerts:", error);
        document.getElementById('alert-list').innerHTML = `
            <tr><td colspan="5">Error: ${error.message}</td></tr>
        `;
    }
}

function parseLogFile(logText) {
    return logText.split('\n')
        .filter(line => line.trim())
        .map(line => {
            const timestamp = line.substring(0, 19);
            const message = line.substring(22);
            const ipMatch = message.match(/\d+\.\d+\.\d+\.\d+/);
            
            return {
                timestamp,
                severity: getSeverity(message),
                sourceIp: ipMatch ? ipMatch[0] : 'Unknown',
                protocol: getProtocol(message),
                description: message
            };
        });
}

function getSeverity(message) {
    for (const [pattern, severity] of Object.entries(severityMap)) {
        if (message.includes(pattern)) return severity;
    }
    return 'medium';
}

function getProtocol(message) {
    if (message.includes('HTTP')) return 'HTTP';
    if (message.includes('HTTPS')) return 'HTTPS';
    if (message.includes('FTP')) return 'FTP';
    if (message.includes('SSH')) return 'SSH';
    if (message.includes('DHCP')) return 'DHCP';
    if (message.includes('ICMP')) return 'ICMP';
    if (message.includes('TCP')) return 'TCP';
    if (message.includes('UDP')) return 'UDP';
    return 'Other';
}

function displayAlerts(alerts) {
    const alertList = document.getElementById('alert-list');
    alertList.innerHTML = alerts.map(alert => `
        <tr>
            <td>${alert.timestamp}</td>
            <td><span class="severity-${alert.severity}">${alert.severity.toUpperCase()}</span></td>
            <td>${alert.sourceIp}</td>
            <td>${alert.protocol}</td>
            <td>${alert.description}</td>
        </tr>
    `).join('');
}

function updateDashboardCounters(alerts) {
    document.getElementById('active-alerts').textContent = alerts.length;
    const dailyAlerts = alerts.filter(a => {
        const alertDate = new Date(a.timestamp);
        return (new Date() - alertDate) < 86400000; // 24 hours
    }).length;
    document.getElementById('daily-alerts').textContent = dailyAlerts;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadAlertsFromLog();
    document.getElementById('alert-severity').addEventListener('change', filterAlerts);
    document.getElementById('alert-protocol').addEventListener('change', filterAlerts);
    document.getElementById('alert-timeframe').addEventListener('change', filterAlerts);
});

function filterAlerts() {
    const severity = document.getElementById('alert-severity').value;
    const protocol = document.getElementById('alert-protocol').value;
    const timeframe = document.getElementById('alert-timeframe').value;
    const now = new Date();
    
    document.querySelectorAll('#alert-list tr').forEach(row => {
        const rowSeverity = row.querySelector('td:nth-child(2) span').className.replace('severity-', '');
        const rowProtocol = row.querySelector('td:nth-child(4)').textContent.trim().toLowerCase();
        const rowDate = new Date(row.querySelector('td:nth-child(1)').textContent);
        
        const severityMatch = severity === 'all' || rowSeverity === severity;
        const protocolMatch = protocol === 'all' || rowProtocol === protocol.toLowerCase();
        const timeframeMatch = timeframe === 'all' || 
            (timeframe === '24h' && (now - rowDate) < 86400000) ||
            (timeframe === '7d' && (now - rowDate) < 604800000);
        
        row.style.display = (severityMatch && protocolMatch && timeframeMatch) ? '' : 'none';
    });
}