const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(cors());

// Add this:
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


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


// LOGIN RELATED STUFF
const USERS_FILE = 'users.json';
const SALT_ROUNDS = 10;
app.use(express.json());

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'supersecretkey',
    resave: false,
    saveUninitialized: true,
}));
app.set('view engine', 'ejs');

// Load users from file
function loadUsers() {
    if (fs.existsSync(USERS_FILE)) {
        return JSON.parse(fs.readFileSync(USERS_FILE));
    }
    return {};
}

// Initialize with default user if empty
let users = loadUsers();

// Authentication
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/');
}

app.use('/assets', express.static('Assets'));

function resetPassword(username, oldPassword, newPassword, res) {
    // Read current users
    let users = {};
    try {
        const data = fs.readFileSync(USERS_FILE);
        users = JSON.parse(data);
    } catch (err) {
        return res.send("Error reading users file.");
    }

    const existingHash = users[username];
    if (!existingHash) {
        return res.send("User not found.");
    }

    // Compare old password with stored hash
    bcrypt.compare(oldPassword, existingHash, (err, result) => {
        if (err) {
            console.error("Bcrypt compare error:", err);
            return res.send("Error comparing passwords.");
        }

        if (!result) {
            return res.send("Old password is incorrect. <a href='/'>Try again</a>");
        }

        // Hash and save the new password
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

    function saveUsers(users) {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    }
}


app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!users[username]) {
        return res.send("Invalid credentials. <a href='/'>Try again</a>");
    }
    bcrypt.compare(password, users[username], (err, result) => {
        if (result) {
            req.session.user = username;
            res.redirect('/dashboard');  // Redirect to dashboard route
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

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

// Serve index.html for root
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve dashboard (protected)
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});