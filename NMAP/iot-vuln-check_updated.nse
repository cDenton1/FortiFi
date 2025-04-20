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
portrule = function(host, port)
  local tcp_ports = {
    21, 22, 23, 53, 80, 443, 554, 1900,
    5000, 5353, 8000, 8080, 8443, 8888, 1883, 8883,
    49152, 49153, 49154, 49155, 49156, 49157,
    6666, 6667
  }

  local udp_ports = {
    53, 69, 123, 161, 1900, 5353
  }

  if port.protocol == "tcp" and shortport.port_in(tcp_ports)(host, port) then
    return true
  end

  if port.protocol == "udp" and shortport.port_in(udp_ports)(host, port) then
    return true
  end

  return false
end


action = function(host, port)
    local output = {}
    
    if port.protocol == "udp" then
        table.insert(output, "🔍 UDP port " .. port.number .. " detected — no specific scan logic yet.")
    elseif port.protocol == "tcp" then
        table.insert(output, "🔍 TCP port " .. port.number .. " detected")
    end


    -- Add IP address to the output
    table.insert(output, "📍 Device IP: " .. host.ip)

    -- Telnet warning
    if port.number == 23 then
        table.insert(output, "⚠️ Telnet (insecure, often open by default) on port 23")
    end

    -- FTP detection
    if port.number == 21 then
        table.insert(output, "📁 FTP service on port 21 — check for anonymous login.")
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

    -- MQTT detection
    if port.number == 1883 then
        table.insert(output, "📡 MQTT broker detected on port 1883 — check if authentication is required.")
    elseif port.number == 8883 then
        table.insert(output, "📡 MQTT over TLS (port 8883) detected — check certificate and authentication.")
    end


    -- If there’s no useful information, skip this result
    if #output == 1 then
        return nil
    else
        return stdnse.format_output(true, output)
    end
end
