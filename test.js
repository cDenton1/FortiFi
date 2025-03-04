const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Hardcoded credentials
const USERNAME = "admin";
const PASSWORD = "password";

// Function to get current date and time
function getCurrentDateTime() {
    return new Date().toLocaleString();
}

// Routes
app.get('/', (req, res) => {
    res.send(`
        <h3>The date and time are currently: ${getCurrentDateTime()}</h3>
        <form action="/login" method="POST">
            <label>Username:</label>
            <input type="text" name="username" required>
            <label>Password:</label>
            <input type="password" name="password" required>
            <button type="submit">Login</button>
        </form>
    `);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username === USERNAME && password === PASSWORD) {
        res.redirect('/welcome');
    } else {
        res.send("Invalid credentials. <a href='/'>Try again</a>");
    }
});

app.get('/welcome', (req, res) => {
    res.send("<h3>Welcome!</h3><p>You have successfully logged in.</p>");
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
