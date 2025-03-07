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

// Save users to file
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Initialize with default user if empty
let users = loadUsers();
if (!users.admin) {
    bcrypt.hash("password", SALT_ROUNDS, (err, hash) => {
        if (!err) {
            users.admin = hash;
            saveUsers(users);
        }
    });
}

// Authentication
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/');
}

app.use('/assets', express.static('Assets'));

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
            <p>Don't have an account? <a href="/register">Register</a></p>
        </body>
        </html>
    `);
});

app.get('/register', (req, res) => {
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
            <h3>Register</h3>
            <img id="loginImage" src="/assets/image.png">
            <form action="/register" method="POST">
                <label>Username:</label>
                <input type="text" name="username" required>
                <label>Password:</label>
                <input type="password" name="password" required>
                <button type="submit">Register</button>
            </form>
            <p><a href="/">Back to login</a></p>
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

// Serve the dashboard.html page after successful login
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/dashboard.html');  // Adjust path to your dashboard.html
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