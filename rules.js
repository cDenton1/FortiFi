// Rule types
const rulePresets = {
    block: { color: '#ff4444', icon: 'fa-skull' },
    monitor: { color: '#ffbb33', icon: 'fa-exclamation-triangle' },
    allow: { color: '#00C851', icon: 'fa-info-circle' }
};

// Sample rule data
let rules = [
    {
        protocol: 'TCP',
        rule: 'monitor',
        description: 'Port scanning detected',
        timestamp: new Date().toISOString(),
        manage: '[replace with link maybe]',
        resolved: false
    },
    // Add more sample rules
];

function updateRules() {
    const tbody = document.getElementById('rule-list');
    const ruleFilter = document.getElementById('rule-rule').value;
    
    tbody.innerHTML = '';
    
    rules
    .filter(AR => ruleFilter === 'all' || AR.severity === ruleFilter)
    .forEach(AR => {
        const tr = document.createElement('tr');
        tr.className = `rule-rule-${AR.rule}`;
        tr.innerHTML = `
            <td>${AR.protocol}</td>
            <td>
                <i class="fas ${rulePresets[AR.rule].icon}"></i>
                ${AR.rule.toUpperCase()}
            </td>
            <td>${AR.description}</td>
            <td>${new Date(AR.timestamp).toLocaleString()}</td>
            <td>${AR.manage}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Initialize rules
document.addEventListener('DOMContentLoaded', () => {
    console.log("DOMContentLoaded - Running updateRules()");
    document.getElementById('rule-rule').addEventListener('change', updateRules);
    updateRules();
});