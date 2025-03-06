var http = require('node:http');
var fs = require('fs');
var path = require('path');
var LR = require('./mod-LogAlert');

http.createServer(function (req, res) {
    if (req.url === '/styles.css') {
        // Serve the CSS file
        fs.readFile(path.join(__dirname, 'styles.css'), (err, data) => {
            if (err) {
                res.writeHead(404);
                res.end("CSS file not found");
            } else {
                res.writeHead(200, {'Content-Type': 'text/css'});
                res.end(data);
            }
        });
    } else {
        // Serve the log output
        res.writeHead(200, {'Content-Type': 'text/html'});
        LR.logReader(req, res);
    }
}).listen(8080);

console.log('Server running on http://localhost:8080');
