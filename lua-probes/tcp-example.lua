--Configs
ProbeName = "tcp-example"
ProbeType = "tcp"         -- tcp, udp or state
MultiMode = "null"        -- null, direct, if_open, after_handle or dynamic_next
MultiNum  = 1
ProbeDesc = [[
    "This is an example lua script for tcp type probe. It sends http simple get "
    "request and identifies http service."
]]


local hello_string = "GET / HTTP/1.0\r\n\r\n"


--- To make hello data
-- @string ip_them ip of target
-- @int port_them port of target
-- @string ip_me ip of us
-- @int port_me port of us
-- @int index index of expected hello probe
-- @return string data of hello
function Make_payload(ip_them, port_them, ip_me, port_me, index)
    return hello_string
end


--- To get hello data length
-- @string ip_them ip of target
-- @int port_them port of target
-- @string ip_me ip of us
-- @int port_me port of us
-- @int index index of expected hello probe
-- @return int length of hello data
function Get_payload_length(ip_them, port_them, ip_me, port_me, index)
    return #hello_string
end


--- To handle reponse data
-- @string ip_them ip of target
-- @int port_them port of target
-- @string ip_me ip of us
-- @int port_me port of us
-- @int index index of expected hello probe
-- @return integer positive for starting after_handle or index +1 to set next probe in dynamic_next
-- @return boolean result if a successful response
-- @return string classification of result
-- @return string reason of classification
-- @return string report of response (empty ret value if no report)
function Handle_response(ip_them, port_them, ip_me, port_me, index, response)
    if #response==0 then
        return 0, false, "no service", "timeout", ""
    end

    if not string.find(response, "HTTPS") and
        (string.find(response, "HTTP")
        or string.find(response, "html")
        or string.find(response, "HTML")
        or string.find(response, "<h1>")) then
        return 0, true, "identified", "matched", "http service"
    end

    return 0, false, "unknown", "not matched", "not http"
end


--- To handle reponse timeout
-- @string ip_them ip of target
-- @int port_them port of target
-- @string ip_me ip of us
-- @int port_me port of us
-- @int index index of expected hello probe
-- @return integer positive for starting after_handle or index +1 to set next probe in dynamic_next
-- @return boolean result if a successful response
-- @return string classification of result
-- @return string reason of classification
-- @return string report of response (empty ret value if no report)
function Handle_timeout(ip_them, port_them, ip_me, port_me, index)
    return 0, false, "no service", "timeout", ""
end