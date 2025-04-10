exports.logReader = function (req, callback) {
    const fs = require('fs');
    const url = require('url');
    const readline = require('readline');

    const fileStream = fs.createReadStream('alerts.log');
    const rl = readline.createInterface({ input: fileStream });

    const parsedUrl = url.parse(req.url, true);
    const formatAlert = parsedUrl.query.formatAlert || 'Type';
    const nextFormatAlert = formatAlert === 'Type' ? 'Date' : 'Type';

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
            <head>
                <link rel="stylesheet" href="./styles.css">
            </head>

            <!-- Go Back to Main Page Button -->
            <button onclick="window.location.href='/'">Go Back to Main Page</button>

            <!-- Section toggle buttons -->
            <button onclick="toggleSection('alerts')">Go to Alerts View</button>
            <button onclick="toggleSection('traffic')">Go to Traffic View</button>

            <div id="alert-section" class="section">
                <h2 id="alert-header">Alerts</h2>
                <div id="alert-buttons">
                    <button onclick="updateQueryParam('formatAlert', '${nextFormatAlert}')">Sort Alerts by ${nextFormatAlert}</button>
                </div>
                <div id="log-box" class="log-container">
        `;

        if (formatAlert === 'Type') {
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
        } else {
            allWarnTraf.forEach(line => output += line + '<br>');
        }

        output += `</div>
            </div>
            <script>
                // Toggle visibility of sections
                function toggleSection(section) {
                    const alertSection = document.getElementById('alert-section');
                    const trafficSection = document.getElementById('traffic-section');
                    const alertHeader = document.getElementById('alert-header');
                    const trafficHeader = document.getElementById('traffic-header');
                    const alertButtons = document.getElementById('alert-buttons');
                    const trafficButtons = document.getElementById('traffic-buttons');

                    // Hide both sections initially
                    alertSection.style.display = 'none';
                    trafficSection.style.display = 'none';
                    alertHeader.style.display = 'none';
                    trafficHeader.style.display = 'none';
                    alertButtons.style.display = 'none';
                    trafficButtons.style.display = 'none';

                    // Hide other section's toggle buttons when showing a section
                    if (section === 'alerts') {
                        alertSection.style.display = 'block';
                        alertHeader.style.display = 'block';
                        alertButtons.style.display = 'block';
                    } else if (section === 'traffic') {
                        trafficSection.style.display = 'block';
                        trafficHeader.style.display = 'block';
                        trafficButtons.style.display = 'block';
                    }
                }

                // Function to change URL parameters (sorting logic)
                function updateQueryParam(param, value) {
                    const currentUrl = new URL(window.location.href);
                    currentUrl.searchParams.set(param, value);
                    window.location.href = currentUrl.toString();
                }
            </script>
        `;
        callback(output);
    });
};
