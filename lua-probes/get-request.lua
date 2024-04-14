--Configs
ProbeName = "get-request"
ProbeType = "tcp"
MultiMode = nil
MultiNum  = 1
ProbeDesc = "This is a test lua script for tcp type probe."

function Global_init()
    print("hello lua probe")
    return true
end

function Make_payload()
end

function Get_payload_length()
end

function Handle_response()
end

function Close()
end