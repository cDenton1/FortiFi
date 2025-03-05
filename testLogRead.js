var https = require('node:http');
var fs = require('fs');
var url = require('url')
var readline = require('readline');

https.createServer(function (req, res) {
    const fileStream = fs.createReadStream('alerts.log');
    const rl = readline.createInterface({input: fileStream});

    const parsedUrl = url.parse(req.url, true);
    const format = parsedUrl.query.format || 'Type';
    const nextFormat = format === 'Type' ? 'Date' : 'Type';

    res.writeHead(200, {'Content-Type': 'text/html'});

    let allWarnTraf = [];
    let httpTraf = [];
    let ftpTraf = [];
    let sshTraf = [];
    let dhcpTraf = [];

    rl.on('line', (line) => {
        if (line.includes('[!]')) {
            allWarnTraf.push(line);
            if (line.includes('HTTP')) httpTraf.push(line);
            if (line.includes('FTP')) ftpTraf.push(line);
            if (line.includes('SSH')) sshTraf.push(line);
            if (line.includes('DHCP')) dhcpTraf.push(line);
        }
    })

    rl.on('close', () => {
        res.write(`
            <button onclick="window.location.search='format=${nextFormat}'">
                Sort by ${nextFormat}
            </button>
            <h2>Sorting By ${format}</h2>
        `);
        
        if (format == 'Type') {
            if (httpTraf.length > 0) {
                res.write('HTTP Detected: <br>');
                httpTraf.forEach(line => res.write(line + '<br>'));
            }    
    
            if (ftpTraf.length > 0) {
                res.write('<br>FTP Detected: <br>');
                ftpTraf.forEach(line => res.write(line + '<br>'));
            }
            
            if (sshTraf.length > 0) {
                res.write('<br>SSH Detected: <br>');
                sshTraf.forEach(line => res.write(line + '<br>'));
            }
    
            if (dhcpTraf.length > 0) {
                res.write('<br>DHCP Traffic or Spoofing Detected: <br>');
                dhcpTraf.forEach(line => res.write(line + '<br>'));
            }
        }

        else if (format == 'Date') {
            allWarnTraf.forEach(line => res.write(line + '<br>'))
        }

        res.end()
    });

  }).listen(8080);

console.log('Server running on http://localhost:8080');