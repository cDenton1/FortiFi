var http = require('node:http');
var fs = require('fs');
var path = require('path');

var LA = require('./mod-LogAlert');
var LT = require('./mod-LogTraffic');

http.createServer(function (req, res) {
    if (req.url === '/styles.css') {
        // Serve the CSS file
        fs.readFile(path.join(__dirname, 'styles.css'), (err, data) => {
            if (err) {
                res.writeHead(404);
                res.end("CSS file not found");
            } else {
                res.writeHead(200, { 'Content-Type': 'text/css' });
                res.end(data);
            }
        });
    } else {
        res.writeHead(200, { 'Content-Type': 'text/html' });

        let combinedOutput = '';

        // Collect data from both modules
        LT.logReader(req, (output) => {
            combinedOutput += output;
            LA.logReader(req, (output) => {
                combinedOutput += output;
                res.end(combinedOutput); // Send response only after both modules are done
            });
        });
    }
}).listen(8080);

console.log('Server running on http://localhost:8080');
