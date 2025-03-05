var serv = require('node:http');
var LR = require('./mod-LogReader');

serv.createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/html'});
    LR.logReader(req, res); // Pass req and res to logReader
}).listen(8080);

console.log('Server running on http://localhost:8080');