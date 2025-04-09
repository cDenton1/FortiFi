const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());

// Set Content-Security-Policy headers
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
    "img-src 'self' data: http://localhost:3000; " +
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "font-src 'self' https://cdnjs.cloudflare.com;"
  );
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// API endpoint to get alerts
app.get('/api/alerts', (req, res) => {
    try {
        const logPath = path.join(__dirname, 'logs', 'alerts.log');
        const logData = fs.readFileSync(logPath, 'utf-8');
        
        const alerts = logData.split('\n')
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
        
        res.json({ success: true, alerts });
    } catch (error) {
        console.error("Error reading log file:", error);
        res.status(500).json({ 
            success: false, 
            error: "Failed to read log file" 
        });
    }
});

// Helper functions
function getSeverity(message) {
    const severityMap = {
        'DHCP Spoofing Detected': 'critical',
        'Insecure Protocol Detected': 'high',
        'SSH Traffic': 'medium',
        'ICMP Packet': 'low'
    };
    
    for (const [pattern, severity] of Object.entries(severityMap)) {
        if (message.includes(pattern)) return severity;
    }
    return 'medium';
}

function getProtocol(message) {
    if (message.includes('HTTP')) return 'HTTP';
    if (message.includes('FTP')) return 'FTP';
    if (message.includes('SSH')) return 'SSH';
    if (message.includes('DHCP')) return 'DHCP';
    if (message.includes('ICMP')) return 'ICMP';
    return 'Other';
}

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});