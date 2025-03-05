var fs = require('fs');
var url = require('url');
var readline = require('readline');

exports.logReader = function (req, res) {
    const fileStream = fs.createReadStream('alerts.log');
    const rl = readline.createInterface({ input: fileStream });

    const parsedUrl = url.parse(req.url, true);
    const format = parsedUrl.query.format || 'Type';
    const nextFormat = format === 'Type' ? 'Date' : 'Type';

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
    });

    rl.on('close', () => {
        let output = `
            <button onclick="window.location.search='format=${nextFormat}'">
                Sort by ${nextFormat}
            </button>
            <h2>Sorting By ${format}</h2>
            <button id="toggle-box" onclick="toggleBox()">Toggle Box View</button>
            
            <style>
                .log-container {
                    font-family: monospace;
                    margin: 20px;
                    padding: 10px;
                    background-color: #f4f4f4;
                    border: 1px solid #ccc;
                }

                .log-container h3 {
                    margin-bottom: 5px;
                    color: #333;
                }

                .log-container button {
                    margin: 5px;
                    padding: 5px;
                    font-size: 14px;
                    cursor: pointer;
                }

                #log-box {
                    max-height: 300px;
                    overflow-y: scroll;
                }
            </style>`;

        // If sorting by 'Type', use scrollable box
        if (format === 'Type') {
            output += `<div id="log-box" class="log-container">`;

            if (httpTraf.length > 0) {
                output += '<h3>HTTP Detected:</h3>';
                httpTraf.forEach(line => output += line + '<br>');
            }

            if (ftpTraf.length > 0) {
                output += '<h3>FTP Detected:</h3>';
                ftpTraf.forEach(line => output += line + '<br>');
            }

            if (sshTraf.length > 0) {
                output += '<h3>SSH Detected:</h3>';
                sshTraf.forEach(line => output += line + '<br>');
            }

            if (dhcpTraf.length > 0) {
                output += '<h3>DHCP Traffic or Spoofing Detected:</h3>';
                dhcpTraf.forEach(line => output += line + '<br>');
            }

            output += `</div>`;
        } else if (format === 'Date') {
            // If sorting by 'Date', show logs directly on the page
            output += `<div id="log-box" class="log-container">`;

            allWarnTraf.forEach(line => output += line + '<br>');

            output += `</div>`;
        }

        // Inject JavaScript to toggle log display (box/no box)
        output += `
            <script>
                let isBoxView = true;

                function toggleBox() {
                    const logBox = document.getElementById('log-box');
                    if (isBoxView) {
                        logBox.style.overflowY = 'unset'; // Remove scroll
                        logBox.style.maxHeight = 'unset'; // Remove max height
                    } else {
                        logBox.style.overflowY = 'scroll'; // Add scroll
                        logBox.style.maxHeight = '300px'; // Set max height
                    }
                    isBoxView = !isBoxView; // Toggle the view
                }
            </script>`;

        res.write(output);
        res.end();
    });
};
