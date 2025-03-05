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

    function highlightText(text) {
        return text
            .replace(/HTTP/g, '<span class="highlight-http">HTTP</span>')
            .replace(/FTP/g, '<span class="highlight-ftp">FTP</span>')
            .replace(/SSH/g, '<span class="highlight-ssh">SSH</span>')
            .replace(/DHCP/g, '<span class="highlight-dhcp">DHCP</span>');
    }

    rl.on('line', (line) => {
        if (line.includes('[!]')) {
            const highlightedLine = highlightText(line);
            allWarnTraf.push(highlightedLine);
            if (line.includes('HTTP')) httpTraf.push(highlightedLine);
            if (line.includes('FTP')) ftpTraf.push(highlightedLine);
            if (line.includes('SSH')) sshTraf.push(highlightedLine);
            if (line.includes('DHCP')) dhcpTraf.push(highlightedLine);
        }
    });

    rl.on('close', () => {
        let output = `
            <h2>Alerts</h2>

            <script>
                let isBoxView = true;

                function toggleBox() {
                    const logBox = document.getElementById('log-box');
                    if (isBoxView) {
                        logBox.style.overflowY = 'unset'; // Remove scroll
                        logBox.style.maxHeight = 'unset'; // Remove max height
                    } else {
                        logBox.style.overflowY = 'scroll'; // Add scroll
                        logBox.style.maxHeight = '400px'; // Set max height
                    }
                    isBoxView = !isBoxView; // Toggle the view
                }
            </script>

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
                    max-height: 400px;
                    overflow-y: scroll;
                }

                /* Highlighting styles */
                .highlight-http {
                    background-color: lightblue;
                    padding: 2px;
                    font-weight: bold;
                }

                .highlight-ftp {
                    background-color: lightgreen;
                    padding: 2px;
                    font-weight: bold;
                }

                .highlight-ssh {
                    background-color: lightcoral;
                    padding: 2px;
                    font-weight: bold;
                }

                .highlight-dhcp {
                    background-color: lightgoldenrodyellow;
                    padding: 2px;
                    font-weight: bold;
                }
            </style>

            <button id="toggle-box" onclick="toggleBox()">Toggle Box View</button>
            <button onclick="window.location.search='format=${nextFormat}'">
                Sort by ${nextFormat}
            </button>

        `;

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
            output += `<div id="log-box" class="log-container">`;
            allWarnTraf.forEach(line => output += line + '<br>');
            output += `</div>`;
        }

        res.write(output);
        res.end();
    });
};
