// Alert types
const alertPresets = {
    high: { color: '#ff4444', icon: 'fa-skull' },
    medium: { color: '#ffbb33', icon: 'fa-exclamation-triangle' },
    low: { color: '#00C851', icon: 'fa-info-circle' }
};

// Sample alerts data
let alerts = [
    {
        timestamp: new Date().toISOString(),
        severity: 'high',
        sourceIP: '192.168.1.15',
        protocol: 'TCP',
        description: 'Port scanning detected',
        resolved: false
    },
    // Add more sample alerts
];

function updateAlerts() {
    const tbody = document.getElementById('alert-list');
    const severityFilter = document.getElementById('alert-severity').value;
    
    tbody.innerHTML = '';
    
    alerts
    .filter(alert => severityFilter === 'all' || alert.severity === severityFilter)
    .forEach(alert => {
        const tr = document.createElement('tr');
        tr.className = `alert-severity-${alert.severity}`;
        tr.innerHTML = `
            <td>${new Date(alert.timestamp).toLocaleString()}</td>
            <td>
                <i class="fas ${alertPresets[alert.severity].icon}"></i>
                ${alert.severity.toUpperCase()}
            </td>
            <td>${alert.sourceIP}</td>
            <td>${alert.protocol}</td>
            <td>${alert.description}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Initialize alerts
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('alert-severity').addEventListener('change', updateAlerts);
    updateAlerts();
});