description = [[
  Checks for insecure open ports on IoT devices and simulates firmware detection.
]]

author = "Tom Byles"
license = "nmap"
categories = {"default", "safe", "discovery"}

-- This runs for specific ports only
portrule = function(host, port)
  local iot_ports = {21, 22, 23, 80, 443, 554, 1900}
  for _, p in ipairs(iot_ports) do
    if port.number == p then return true end
  end
  return false
end

action = function(host, port)
  local output = {}

  if port.number == 23 then
    table.insert(output, "⚠️ Telnet (insecure, often open by default) on port 23")
  elseif port.number == 80 then
    table.insert(output, "🌐 HTTP (ensure secure login/authentication) on port 80")
    table.insert(output, "📦 Detected Firmware Version: 1.0.0 (latest known: 1.0.3)")  -- placeholder
  elseif port.number == 554 then
    table.insert(output, "📹 RTSP camera feed may be open (port 554)")
  end

  return stdnse.format_output(true, output)
end
