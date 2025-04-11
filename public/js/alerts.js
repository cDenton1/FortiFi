// Severity classification
const severityMap = {
    'DHCP': 'low',
    'HTTP': 'high',
    'SSH Traffic': 'medium',
    'ICMP Packet': 'low',
    'HTTPS': 'low',
    'Telnet': 'low'
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
            const protocol = getProtocol(message);  // Get protocol first
            
            // Set source IP to N/A for MQTT
            const sourceIp = protocol === 'MQTT' 
                ? 'N/A' 
                : (ipMatch ? ipMatch[0] : 'Unknown');

            return {
                timestamp,
                severity: getSeverity(message),
                sourceIp,
                protocol,
                description: message
            };
        });
}

function getSeverity(message) {
    // Check for DNS or MQTT alerts and extract severity from the message
    if (message.includes('DNS') || message.includes('MQTT')) {
        const severityMatch = message.match(/\b(Critical|High|Medium|Low)\b/i);
        if (severityMatch) {
            return severityMatch[0].toLowerCase();
        } else {
            return 'medium'; // Default if no severity keyword is found
        }
    }
    
    // Existing severity mapping for other protocols
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
    if (message.includes('Deauth')) return 'Deauth';
    if (message.includes('ARP')) return 'ARP';
    if (message.includes('MQTT')) return 'MQTT';
    if (message.includes('DNS')) return 'DNS';
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