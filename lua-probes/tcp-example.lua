-- Configs
---@string name of the probe.
ProbeName = "tcp-example"
---@string type of the probe, could be 'tcp', 'udp' or 'state'.
ProbeType = "tcp"
---@string multi-probe mode, could be 'null', 'direct', 'if_open', 'after_handle' or 'dynamic_next'.
MultiMode = "null"
---@number multi-probe number.
MultiNum  = 1
---@string description of the probe.
ProbeDesc = [[
    "This is an example lua script for tcp type probe. It sends http simple get "
    "request and identifies http service."
]]


local hello_string = "GET / HTTP/1.0\r\n\r\n"


-- To make hello data.
---@param ip_them string ip of target.
---@param port_them number port of target.
---@param ip_me string ip of us.
---@param port_me number port of us.
---@param index number index of expected hello probe.
---@return string data of hello.
function Make_payload(ip_them, port_them, ip_me, port_me, index)
    return hello_string
end

-- To get hello data length.
---@param ip_them string ip of target.
---@param port_them number port of target.
---@param ip_me string ip of us.
---@param port_me number port of us.
---@param index number index of expected hello probe.
---@return number length of hello data.
function Get_payload_length(ip_them, port_them, ip_me, port_me, index)
    return #hello_string
end

-- To handle reponse data.
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
    if not string.find(response, "HTTPS") and
        (string.find(response, "HTTP")
            or string.find(response, "html")
            or string.find(response, "HTML")
            or string.find(response, "<h1>")) then
        return 0, true, "identified", "matched", "http service"
    end

    return 0, false, "unknown", "not matched", "not http"
end

-- To handle reponse timeout.
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
