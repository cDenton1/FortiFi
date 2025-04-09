const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();
const port = 3000;

const USERS_FILE = 'users.json';
const SALT_ROUNDS = 10;


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
    // Allow API requests without authentication
    if (req.path.startsWith('/api/') || req.session.user) {
        return next();
    }
    res.redirect('/');
}

app.use('/assets', express.static('Assets'));

<<<<<<< Updated upstream
=======
<<<<<<< Updated upstream
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

=======
// Add these near your other middleware
app.use(express.json()); // For parsing JSON requests
app.use('/logs', express.static('logs')); // Serve log files

// Add the alerts API endpoint (same as in server.js)
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

// Add these helper functions (put them near your other functions)
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
>>>>>>> Stashed changes

>>>>>>> Stashed changes
app.get('/', (req, res) => {
    res.send(`
        <html>
        <head>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                    text-align: center;
                    font-weight: normal;
                }
                h3, label {
                    font-weight: normal;
                }
                #loginImage {
                    width: 700px;
                    height: auto;
                    margin: 0px 0;
                }
                form {
                    margin: 10px 0;
                }
                input {
                    margin: 5px;
                    padding: 8px;
                    width: 200px;
                }
                button {
                    padding: 8px 16px;
                    margin-top: 0px;
                }
            </style>
        </head>
        <body>
            <h3>Login</h3>
            <img id="loginImage" src="/assets/image.png">
            <form action="/login" method="POST">
                <label>Username:</label>
                <input type="text" name="username" required>
                <label>Password:</label>
                <input type="password" name="password" required>
                <button type="submit">Login</button>
            </form>
            <p>Remember to change the default password!</p>
        </body>
        </html>
    `);
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (users[username]) {
        return res.send("Username already exists. <a href='/register'>Try again</a>");
    }
    bcrypt.hash(password, SALT_ROUNDS, (err, hash) => {
        if (err) return res.send("Error creating account.");
        users[username] = hash;
        saveUsers(users);
        res.send("Registration successful. <a href='/'>Login here</a>");
    });
});
// Save users to file
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!users[username]) {
        return res.send("Invalid credentials. <a href='/'>Try again</a>");
    }
    bcrypt.compare(password, users[username], (err, result) => {
        if (result) {
            req.session.user = username;
            res.redirect('/dashboard');  // This remains the same
        } else {
            res.send("Invalid credentials. <a href='/'>Try again</a>");
        }
    });
});

// Serve the index.html page after successful login
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/index.html');  // Updated path
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});