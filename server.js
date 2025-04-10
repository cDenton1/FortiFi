const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const cors = require('cors');
const { exec } = require('child_process');

const app = express();
const PORT = 3000;

// Configuration
const USERS_FILE = 'users.json';
const SALT_ROUNDS = 10;
const LOGS_DIR = path.join(__dirname, 'logs');
const ALERTS_LOG = path.join(LOGS_DIR, 'alerts.log');
const NMAP_LOG = path.join(LOGS_DIR, 'nmap_scans.log');
const NMAP_TEMP = path.join(LOGS_DIR, 'temp_scan.json');

// Ensure logs directory exists
if (!fs.existsSync(LOGS_DIR)) {
    fs.mkdirSync(LOGS_DIR, { recursive: true });
}

// Middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'supersecretkey',
    resave: false,
    saveUninitialized: true,
}));

// Security Headers
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
app.use('/assets', express.static('Assets'));

// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/');
}

// User Management
let users = loadUsers();

function loadUsers() {
    if (fs.existsSync(USERS_FILE)) {
        return JSON.parse(fs.readFileSync(USERS_FILE));
    }
    return {};
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Authentication Endpoints
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!users[username]) {
        return res.send("Invalid credentials. <a href='/'>Try again</a>");
    }
    bcrypt.compare(password, users[username], (err, result) => {
        if (result) {
            req.session.user = username;
            res.redirect('/dashboard');
        } else {
            res.send("Invalid credentials. <a href='/'>Try again</a>");
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// Nmap Scanning Endpoints
app.get('/api/scan', isAuthenticated, (req, res) => {
    const target = '192.168.4.0/24'; // Restricted to AP subnet
    const timestamp = new Date().toISOString();

    const command = `nmap -sn ${target} --script iot-vuln-check.nse -oJ ${NMAP_TEMP} && cat ${NMAP_TEMP}`;

    exec(command, (error, stdout, stderr) => {
        try {
            fs.appendFileSync(NMAP_LOG, `\n=== Scan ${timestamp} ===\n${stdout}\n`);

            let result;
            try {
                result = stdout ? JSON.parse(stdout) : { error: "No scan output" };
            } catch (parseError) {
                console.error("JSON parse error:", parseError);
                result = { error: "Failed to parse scan results" };
            }

            res.json({
                success: !error,
                results: stdout || "No scan results",
                scanData: result,
                timestamp
            });

            if (fs.existsSync(NMAP_TEMP)) {
                fs.unlink(NMAP_TEMP, (err) => {
                    if (err) console.error("Error deleting temp file:", err);
                });
            }
        } catch (err) {
            console.error("Scan processing error:", err);
            res.status(500).json({
                success: false,
                error: "Failed to process scan results"
            });
        }
    });
});

app.get('/api/scan-history', isAuthenticated, (req, res) => {
    try {
        const history = fs.existsSync(NMAP_LOG) 
            ? fs.readFileSync(NMAP_LOG, 'utf8') 
            : "No scan history available";
        res.json({ success: true, history });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Alerts Endpoint
app.get('/api/alerts', isAuthenticated, (req, res) => {
    try {
        const logData = fs.existsSync(ALERTS_LOG)
            ? fs.readFileSync(ALERTS_LOG, 'utf-8')
            : '';
        
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
        console.error("Error reading alerts:", error);
        res.status(500).json({ 
            success: false, 
            error: "Failed to read alerts" 
        });
    }
});

// Helper Functions
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

// Log Rotation
function rotateLogs() {
    const rotateIfNeeded = (filePath) => {
        if (fs.existsSync(filePath)) {
            const stats = fs.statSync(filePath);
            if (stats.size > 1024 * 1024) { // 1MB
                fs.renameSync(filePath, `${filePath}.${new Date().toISOString()}`);
            }
        }
    };

    rotateIfNeeded(ALERTS_LOG);
    rotateIfNeeded(NMAP_LOG);
}

// Password Reset
app.post('/reset-password', (req, res) => {
    const { username, oldPassword, newPassword } = req.body;
    resetPassword(username, oldPassword, newPassword, res);
});

function resetPassword(username, oldPassword, newPassword, res) {
    const existingHash = users[username];
    if (!existingHash) {
        return res.send("User not found.");
    }

    bcrypt.compare(oldPassword, existingHash, (err, result) => {
        if (err) {
            console.error("Bcrypt compare error:", err);
            return res.send("Error comparing passwords.");
        }

        if (!result) {
            return res.send("Old password is incorrect. <a href='/'>Try again</a>");
        }

        bcrypt.hash(newPassword, SALT_ROUNDS, (err, hash) => {
            if (err) {
                console.error("Bcrypt hash error:", err);
                return res.send("Error hashing new password.");
            }
            users[username] = hash;
            saveUsers(users);
            res.send("Password reset successful. <a href='/'>Login here</a>");
        });
    });
}

// Start Server
app.listen(PORT, () => {
    console.log(`FortiFi Dashboard running on http://localhost:${PORT}`);
    // Rotate logs daily
    setInterval(rotateLogs, 86400000);
});