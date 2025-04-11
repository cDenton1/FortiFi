description = [[
  Checks for insecure open ports on IoT devices within the 192.168.4.0/24 subnet.
  Focuses on common IoT vulnerabilities and misconfigurations.
]]

author = "FortiFi Team"
license = "Same as Nmap"
categories = {"vuln", "safe", "iot"}

-- Only run on devices in the AP subnet
hostrule = function(host)
  return host.ip:match("^192%.168%.4%.")
end

-- Run on these specific IoT-related ports
portrule = function(host, port)
  local iot_ports = {21, 22, 23, 80, 443, 554, 1900, 8080, 8888}
  for _, p in ipairs(iot_ports) do
    if port.number == p then return true end
  end
  return false
end

-- Main vulnerability check function
action = function(host, port)
  local output = {}
  local ip = host.ip
  local port_num = port.number
  
  -- Common IoT vulnerabilities checks
  if port_num == 23 then
    table.insert(output, string.format("CRITICAL: Telnet service active on %s (insecure protocol)", ip))
    table.insert(output, "Recommendation: Disable Telnet and use SSH instead")
    
  elseif port_num == 80 or port_num == 8080 or port_num == 8888 then
    table.insert(output, string.format("HTTP service found on %s:%d", ip, port_num))
    
    -- Check for common web vulnerabilities
    if port.service == "http" and port.version and port.version:match("nginx") then
      table.insert(output, "WEB SERVER: nginx detected (check for outdated versions)")
    end
    
  elseif port_num == 22 then
    table.insert(output, string.format("SSH service active on %s", ip))
    if port.version and port.version:match("OpenSSH") then
      table.insert(output, "SSH DETAILS: " .. port.version)
    end
    
  elseif port_num == 554 then
    table.insert(output, string.format("RTSP camera stream found on %s (potential security risk)", ip))
    
  elseif port_num == 1900 then
    table.insert(output, string.format("UPnP service active on %s (potential exposure risk)", ip))
  end

  -- Add device fingerprinting
  if port.service and port.service ~= "unknown" then
    table.insert(output, string.format("SERVICE: %s (%s)", port.service, port.version or "version unknown"))
  end

  return stdnse.format_output(true, output)
end
