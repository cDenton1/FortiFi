// Device types mapping
const deviceIcons = {
    router: 'fa-router',
    computer: 'fa-desktop',
    phone: 'fa-mobile-screen',
    camera: 'fa-video',
    unknown: 'fa-question'
};

// Device module
function updateDevices() {
    fetch('/api/devices') // Replace with your actual API endpoint
        .then(response => response.json())
        .then(devices => {
            const container = document.getElementById('device-container');
            container.innerHTML = '';
            
            devices.forEach(device => {
                const deviceCard = document.createElement('div');
                deviceCard.className = 'device-card';
                
                const icon = document.createElement('i');
                icon.className = `fas ${deviceIcons[device.type] || deviceIcons.unknown} device-icon`;
                
                const name = document.createElement('div');
                name.textContent = device.name;
                
                const status = document.createElement('div');
                status.textContent = device.active ? 'Online' : 'Offline';
                status.style.color = device.active ? '#2ecc71' : '#e74c3c';

                deviceCard.appendChild(icon);
                deviceCard.appendChild(name);
                deviceCard.appendChild(status);

                if (device.hasAlerts) {
                    const warning = document.createElement('i');
                    warning.className = 'fas fa-triangle-exclamation warning-badge';
                    deviceCard.appendChild(warning);
                }

                container.appendChild(deviceCard);
            });
        })
        .catch(error => console.error('Error updating devices:', error));
}

// Sample device data (replace with real API data)
const sampleDevices = [
    { name: 'Main Router', type: 'router', active: true, hasAlerts: false },
    { name: 'Security Cam', type: 'camera', active: true, hasAlerts: true },
    { name: 'My Phone', type: 'phone', active: false, hasAlerts: false },
    { name: 'Work Laptop', type: 'computer', active: true, hasAlerts: true }
];

// For testing without backend
function mockUpdateDevices() {
    const container = document.getElementById('device-container');
    container.innerHTML = '';
    
    sampleDevices.forEach(device => {
        const deviceCard = document.createElement('div');
        deviceCard.className = 'device-card';
        
        const icon = document.createElement('i');
        icon.className = `fas ${deviceIcons[device.type] || deviceIcons.unknown} device-icon`;
        
        const name = document.createElement('div');
        name.textContent = device.name;
        
        const status = document.createElement('div');
        status.textContent = device.active ? 'Online' : 'Offline';
        status.style.color = device.active ? '#2ecc71' : '#e74c3c';

        deviceCard.appendChild(icon);
        deviceCard.appendChild(name);
        deviceCard.appendChild(status);

        if (device.hasAlerts) {
            const warning = document.createElement('i');
            warning.className = 'fas fa-triangle-exclamation warning-badge';
            deviceCard.appendChild(warning);
        }

        container.appendChild(deviceCard);
    });
}
