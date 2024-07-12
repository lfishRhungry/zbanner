-- Configs
---@string name of the probe.
ProbeName = "udp-example"
---@string type of the probe, could be 'tcp', 'udp' or 'state'.
ProbeType = "udp"
---@string multi-probe mode, could be 'null', 'direct', 'if_open', 'after_handle' or 'dynamic_next'.
MultiMode = "null"
---@number multi-probe number.
MultiNum  = 1
---@string description of the probe.
ProbeDesc = [[
    "This is an example lua script for udp type probe. It sends a TXT version "
    "bind request and identifies dns service."
]]


local dns_req = "\x50\xb6\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"
--[[
        /* 00 */"\x50\xb6"  /* transaction id */
        /* 02 */"\x01\x20"  /* query */
        /* 04 */"\x00\x01"  /* query = 1 */
        /* 06 */"\x00\x00\x00\x00\x00\x00"
        /* 0c */"\x07" "version"  "\x04" "bind" "\x00"
        /* 1b */"\x00\x10" /* TXT */
        /* 1d */"\x00\x03" /* CHAOS */
        /* 1f */
]]


-- To make hello data
---@param ip_them string ip of target.
---@param port_them number port of target.
---@param ip_me string ip of us.
---@param port_me number port of us.
---@param index number index of expected hello probe.
---@param cookie number suggested cookie of this target
---@return string data of hello.
function Make_payload(ip_them, port_them, ip_me, port_me, index, cookie)
    local send_req = dns_req
    send_req = string.char(cookie & 0xFF) .. send_req:sub(2)
    send_req = send_req:sub(1, 1) .. string.char(cookie >> 8 & 0xFF) .. send_req:sub(3)
    return send_req
end

-- To validate response
---@param ip_them string ip of target.
---@param port_them number port of target.
---@param ip_me string ip of us.
---@param port_me number port of us.
---@param index number index of expected hello probe.
---@param cookie number suggested cookie of this target
---@param response string reponsed data.
---@return boolean if response data is valid
function Validate_response(ip_them, port_them, ip_me, port_me, index, cookie, response)
    local a = string.pack("B", cookie & 0xFF)
    if response:sub(1, 1) ~= a then
        return false
    end

    local b = string.pack("B", cookie >> 8 & 0xFF)
    if response:sub(2, 2) ~= b then
        return false
    end

    return true
end

-- To handle reponse data
---@param ip_them string ip of target.
---@param port_them number port of target.
---@param ip_me string ip of us.
---@param port_me number port of us.
---@param index number index of expected hello probe.
---@param response string reponsed data.
---@return number positive for starting after_handle or index +1 to set next probe in dynamic_next.
---@return boolean result if a successful response.
---@return string classification of result.
---@return string reason of classification.
---@return string report of response (empty string if no report).
function Handle_response(ip_them, port_them, ip_me, port_me, index, response)
    return 0, true, "identified", "matched", "dns"
end

-- To handle reponse timeout
---@param ip_them string ip of target.
---@param port_them number port of target.
---@param ip_me string ip of us.
---@param port_me number port of us.
---@param index number index of expected hello probe.
---@return number positive for starting after_handle or index +1 to set next probe in dynamic_next.
---@return boolean result if a successful response.
---@return string classification of result.
---@return string reason of classification.
---@return string report of response (empty ret value if no report).
function Handle_timeout(ip_them, port_them, ip_me, port_me, index)
    return 0, false, "no service", "timeout", ""
end
