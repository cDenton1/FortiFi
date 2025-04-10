local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Scans common IoT ports for security risks and attempts to detect device OS/firmware using banners.
Displays the IP addresses of the scanned devices along with their service details.
]]

author = "Tom Byles"
license = "nmap"
categories = {"default", "safe", "discovery"}

-- Scan for common IoT ports (HTTP, Telnet, etc.)
portrule = shortport.port_or_service({21, 22, 23, 80, 443, 554, 1900}, "tcp")

action = function(host, port)
    local output = {}

    -- Add IP address to the output
    table.insert(output, "📍 Device IP: " .. host.ip)

    -- Telnet warning
    if port.number == 23 then
        table.insert(output, "⚠️ Telnet (insecure, often open by default) on port 23")
    end

    -- HTTP banner/firmware detection
    if port.number == 80 or port.number == 443 then
        local socket = nmap.new_socket()
        socket:set_timeout(3000)
        local ok, err = socket:connect(host.ip, port.number)
        if ok then
            socket:send("HEAD / HTTP/1.1\r\nHost: " .. host.ip .. "\r\n\r\n")
            local response = socket:receive_lines(10)
            if response then
                for _, line in ipairs(response) do
                    if line:lower():find("server:") then
                        table.insert(output, "🌐 HTTP Server Banner: " .. line)
                        -- Basic OS guess
                        if line:lower():find("debian") then
                            table.insert(output, "🧠 Likely OS: Debian-based firmware")
                        elseif line:lower():find("openwrt") then
                            table.insert(output, "🧠 Likely OS: OpenWRT")
                        elseif line:lower():find("raspbian") then
                            table.insert(output, "🧠 Likely OS: Raspbian")
                        end
                    end
                end
            end
            socket:close()
        end
    end

    -- SSH banner
    if port.number == 22 then
        local socket = nmap.new_socket()
        socket:set_timeout(3000)
        local ok, err = socket:connect(host.ip, port.number)
        if ok then
            local banner = socket:receive_lines(1)
            if banner then
                table.insert(output, "🔐 SSH Banner: " .. banner)
                if banner:lower():find("debian") then
                    table.insert(output, "🧠 OS Detected via SSH: Debian")
                elseif banner:lower():find("ubuntu") then
                    table.insert(output, "🧠 OS Detected via SSH: Ubuntu")
                end
            end
            socket:close()
        end
    end

    -- RTSP warning
    if port.number == 554 then
        table.insert(output, "📹 RTSP stream may be open (check authentication!)")
    end

    -- If there’s no useful information, skip this result
    if #output == 1 then
        return nil
    else
        return stdnse.format_output(true, output)
    end
end
