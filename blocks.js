// Block types
const rulePresets = {
    block: { color: '#ff4444', icon: 'fa-skull' },
    monitor: { color: '#ffbb33', icon: 'fa-exclamation-triangle' },
    allow: { color: '#00C851', icon: 'fa-info-circle' }
};

// Sample block data
let blocks = [
    {
        address: '140.276.11.5',
        class: 'IP Address',
        description: 'Port scanning detected',
        manage: '[replace with link maybe]',
        resolved: false
    },
    // Add more sample rules
];

function updateBlocks() {
    const tbody = document.getElementById('block-list');
    const blockFilter = document.getElementById('block-class').value;
    
    tbody.innerHTML = '';
    
    blocks
    .filter(block => blockFilter === 'all' || block.class === blockFilter)
    .forEach(block => {
        const tr = document.createElement('tr');
        tr.className = `rule-rule-${block.rule}`;
        tr.innerHTML = `
            <td>${block.protocol}</td>
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