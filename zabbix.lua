
zabbix_protocol = Proto("Zabbix", "Zabbix Protocol")
-- for some reason the protocol name is shown in UPPERCASE in Protocol column
-- (and in Proto.name), so let's define a string to override that
local PROTOCOL_NAME = "Zabbix"

p_header = ProtoField.string("zabbix.header", "Header", base.ASCII)
p_version = ProtoField.uint8("zabbix.version", "Version", base.HEX)
p_length = ProtoField.uint32("zabbix.len", "Length", base.DEC)
p_reserved = ProtoField.uint32("zabbix.reserved", "Reserved", base.DEC)
p_uncompressed_length = ProtoField.uint32("zabbix.uncompressedlen", "Uncompressed length", base.DEC)
p_data = ProtoField.string("zabbix.data", "Data", base.ASCII)
-- zabbix.datalen is derived from data length or from uncompressed length
p_data_len = ProtoField.uint32("zabbix.datalen", "Data length", base.DEC)
p_success = ProtoField.bool("zabbix.success", "Success")
p_failed = ProtoField.bool("zabbix.failed", "Failed")
p_response = ProtoField.bool("zabbix.response", "Response")
p_version_string = ProtoField.string("zabbix.versionstring", "Version String", base.ASCII)
p_agent_name = ProtoField.string("zabbix.agent.name", "Agent Name", base.ASCII)
p_agent_checks = ProtoField.bool("zabbix.agent.checks", "Agent Active Checks")
p_agent_data = ProtoField.bool("zabbix.agent.data", "Agent Data")
p_proxy_name = ProtoField.string("zabbix.proxy.name", "Proxy Name", base.ASCII)
p_proxy_heartbeat = ProtoField.bool("zabbix.proxy.heartbeat", "Proxy Heartbeat")
p_proxy_data = ProtoField.bool("zabbix.proxy.data", "Proxy Data")
p_proxy_config = ProtoField.bool("zabbix.proxy.config", "Proxy Config")
p_proxy_response = ProtoField.bool("zabbix.proxy.response", "Proxy Response")
p_time = ProtoField.float("zabbix.time", "Time since the request was sent")

zabbix_protocol.fields = { p_header, p_version, p_length, p_reserved, p_uncompressed_length,
    p_data, p_data_len, p_success, p_failed, p_response,
    p_version_string, p_agent_name, p_agent_checks, p_agent_data,
    p_proxy_name, p_proxy_heartbeat, p_proxy_data, p_proxy_config,
    p_proxy_response, p_time }

local T_SUCCESS = 0x0001
local T_FAILED = 0x0002
local T_REQUEST = 0x0004
local T_RESPONSE = 0x0008
local T_CHECKS = 0x0010
local T_AGENT_DATA = 0x0020
local T_PROXY_HEARTBEAT = 0x0040
local T_PROXY_CONFIG = 0x0080
local T_PROXY_DATA = 0x0100
local T_PASSIVE_PROXY_RESPONSE = 0x0200

local default_settings =
{
    debug_level = DEBUG,
    ports = "10051",   -- the default TCP port for Zabbix
    reassemble = true, -- whether we try reassembly or not
    info_text = true,  -- show our own Info column data or TCP defaults
    ports_in_info = true, -- show TCP ports in Info column
}

local timestamps = {}

local function band(a, b)
    if bit.band(a, b) > 0 then return true
    else return false
    end
end


-- ###############################################################################
function doDissect(buffer, pktinfo, tree)
    local data_length = buffer(5,4):le_uint()
    local reserved = buffer(9,4):le_uint()
    local data = buffer(13):string()
    -- (note that we assumed that the full segment belongs to this same message)
    local LEN = "Len: " .. data_length
    local LEN_AND_PORTS = "Len=" .. data_length
    if default_settings.ports_in_info then
        LEN_AND_PORTS = LEN_AND_PORTS .. " (" .. pktinfo.src_port .. " → " .. pktinfo.dst_port .. ")"
    end

    -- set default values, then modify them as needed:
    local oper_type = -1 -- undefined
    local agent_name = nil
    local proxy_name = nil
    local version_string = nil
    local tree_text = "Zabbix Protocol, " .. LEN
    local info_text = "Zabbix Protocol, " .. LEN_AND_PORTS
    if string.find(data, '{"request":"active checks",') then
        -- agent requesting for active checks
        oper_type = T_CHECKS + T_REQUEST
        hostname = string.match(data, '"host":"(.-)"')
        if hostname then
            agent_name = hostname
        else
            hostname = "<unknown>"
        end
        tree_text = "Zabbix Request for active checks for \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Request for active checks for \"" .. hostname .. "\", " .. LEN_AND_PORTS
    elseif string.find(data, '{"request":"agent data",') then
        -- active agent sending data
        oper_type = T_AGENT_DATA + T_REQUEST
        hostname = string.match(data, '"data":%[{"host":"(.-)"')
        if hostname then
            agent_name = hostname
        else
            hostname = "<unknown>"
        end
        tree_text = "Zabbix Send agent data for \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Send agent data for \"" .. hostname .. "\", " .. LEN_AND_PORTS
    elseif string.find(data, '{"request":"proxy data",') then
        -- either from server to passive proxy, or from active proxy to server
        oper_type = T_PROXY_DATA + T_REQUEST
        hostname = string.match(data, '"host":"(.-)"')
        if hostname then
            proxy_name = hostname
        else
            hostname = "<unknown>"
        end
        version_string = string.match(data, '"version":"(.-)"')
        tree_text = "Zabbix Proxy data for \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Proxy data for \"" .. hostname .. "\", " .. LEN_AND_PORTS
    elseif string.find(data, '{"request":"proxy config",') then
        -- either from server to passive proxy, or from active proxy to server
        oper_type = T_PROXY_CONFIG + T_REQUEST
        hostname = string.match(data, '"host":"(.-)"')
        if hostname then
            proxy_name = hostname
        else
            hostname = "<unknown>"
        end
        version_string = string.match(data, '"version":"(.-)"')
        tree_text = "Zabbix Request proxy config for \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Request proxy config for \"" .. hostname .. "\", " .. LEN_AND_PORTS
    elseif string.find(data, '{"request":"proxy heartbeat",') then
        -- from active proxy to server
        oper_type = T_PROXY_HEARTBEAT + T_REQUEST
        hostname = string.match(data, '"host":"(.-)"')
        if hostname then
            proxy_name = hostname
        else
            hostname = "<unknown>"
        end
        version_string = string.match(data, '"version":"(.-)"')
        tree_text = "Zabbix Proxy heartbeat for \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Proxy heartbeat for \"" .. hostname .. "\", " .. LEN_AND_PORTS
    elseif string.find(data, '{"session":"') then
        -- response to "proxy data" request from passive proxy
        oper_type = T_PASSIVE_PROXY_RESPONSE + T_RESPONSE
        version_string = string.match(uncompressed_data_str, '"version":"(.-)"')
        tree_text = "Zabbix Passive Proxy Response, " .. LEN
        info_text = "Zabbix Passive Proxy Response, " .. LEN_AND_PORTS
    elseif string.find(data, '{"response":"success","data":') then
        -- response for agent's request for active checks
        oper_type = T_SUCCESS + T_CHECKS + T_RESPONSE
        tree_text = "Zabbix Response for active checks (success), " .. LEN
        info_text = "Zabbix Response for active checks (success), " .. LEN_AND_PORTS
    elseif string.find(data, '{"response":"success","info":') then
        -- response for agent data send
        oper_type = T_SUCCESS + T_AGENT_DATA + T_RESPONSE
        tree_text = "Zabbix Response for agent data (success), " .. LEN
        info_text = "Zabbix Response for agent data (success), " .. LEN_AND_PORTS
    elseif string.find(data, '{"globalmacro":') then
        -- response for active proxy config request
        oper_type = T_PROXY_CONFIG + T_RESPONSE
        tree_text = "Zabbix Response for proxy config, " .. LEN
        info_text = "Zabbix Response for proxy config, " .. LEN_AND_PORTS
    elseif string.find(data, '{"response":"success"') then
        -- response of some sort, successful
        oper_type = T_SUCCESS + T_RESPONSE
        version_string = string.match(data, '"version":"(.-)"')
        tree_text = "Zabbix Response (success), " .. LEN
        info_text = "Zabbix Response (success), " .. LEN_AND_PORTS
    elseif string.find(data, '{"response":"failed"') then
        -- response of some sort, failed
        oper_type = T_FAILED + T_RESPONSE
        version_string = string.match(data, '"version":"(.-)"')
        tree_text = "Zabbix Response (failed), " .. LEN
        info_text = "Zabbix Response (failed), " .. LEN_AND_PORTS
    end

    if default_settings.info_text then
        pktinfo.cols.info = info_text
    end

    local subtree = tree:add(zabbix_protocol, buffer(), tree_text)
    subtree:add_le(p_header, buffer(0,4))
    subtree:add_le(p_version, buffer(4,1))
    subtree:add_le(p_length, buffer(5,4))
    subtree:add_le(p_reserved, buffer(9,4))
    if agent_name then
        subtree:add(p_agent_name, agent_name)
    end
    if proxy_name then
        subtree:add(p_proxy_name, proxy_name)
    end
    if version_string then
        subtree:add(p_version_string, version_string)
    end
    if band(oper_type, T_CHECKS) then subtree:add(p_agent_checks,1):set_generated() end
    if band(oper_type, T_AGENT_DATA) then subtree:add(p_agent_data,1):set_generated() end
    if band(oper_type, T_PROXY_DATA) then subtree:add(p_proxy_data,1):set_generated() end
    if band(oper_type, T_PROXY_CONFIG) then subtree:add(p_proxy_config,1):set_generated() end
    if band(oper_type, T_PROXY_HEARTBEAT) then subtree:add(p_proxy_heartbeat,1):set_generated() end
    if band(oper_type, T_PASSIVE_PROXY_RESPONSE) then subtree:add(p_proxy_response,1):set_generated() end
    if band(oper_type, T_RESPONSE) then subtree:add(p_response,1):set_generated() end
    if band(oper_type, T_SUCCESS) then subtree:add(p_success,1):set_generated() end
    if band(oper_type, T_FAILED) then subtree:add(p_failed,1):set_generated() end
    subtree:add_le(p_data, buffer(13))
    subtree:add(p_data_len, data_length):set_generated()
    -- now save the timestamp or calculate response time
    if band(oper_type, T_REQUEST) then
        -- make hash string for the request
        local hash_string = tostring(pktinfo.src) .. ":" .. tostring(pktinfo.src_port) ..
            "-" .. tostring(pktinfo.dst) .. ":" .. tostring(pktinfo.dst_port)
        -- save the request timestamp
        timestamps[hash_string] = pktinfo.abs_ts
    elseif band(oper_type, T_RESPONSE) then
        -- make hash string for the response
        local hash_string = tostring(pktinfo.dst) .. ":" .. tostring(pktinfo.dst_port) ..
            "-" .. tostring(pktinfo.src) .. ":" .. tostring(pktinfo.src_port)
        local request_timestamp = timestamps[hash_string]
        if request_timestamp then
            local response_time = pktinfo.abs_ts - request_timestamp
            subtree:add(p_time, response_time, "Time since request:", string.format("%.6f", response_time), "seconds"):set_generated()
        end
    end
end

-- ###############################################################################
function doDissectCompressed(buffer, pktinfo, tree)
    local version = buffer(4,1):uint()
    local data_length = buffer(5,4):le_uint()
    local original_length = buffer(9,4):le_uint()
    local uncompressed_data = buffer(13):uncompress()
    local uncompressed_data_str = uncompressed_data:string()
    local LEN = "Len: " .. data_length
    local LEN_AND_PORTS = "Len=" .. data_length
    if default_settings.ports_in_info then
        LEN_AND_PORTS = LEN_AND_PORTS .. " (" .. pktinfo.src_port .. " → " .. pktinfo.dst_port .. ")"
    end

    -- set default values, then modify them as needed:
    local oper_type = -1 -- undefined
    local proxy_name = nil
    local version_string = nil
    local tree_text = "Zabbix Protocol, Version: " .. version .. ", " .. LEN
    local info_text = "Zabbix Protocol, Version=" .. version .. ", " .. LEN_AND_PORTS
    if string.find(uncompressed_data_str, '{"request":"proxy data",') then
        -- either from server to passive proxy, or from active proxy to server
        oper_type = T_PROXY_DATA
        hostname = string.match(uncompressed_data_str, '"host":"(.-)"')
        if hostname then
            proxy_name = hostname
        else
            hostname = "<unknown>"
        end
        version_string = string.match(uncompressed_data_str, '"version":"(.-)"')
        tree_text = "Zabbix Proxy data for \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Proxy data for \"" .. hostname .. "\", " .. LEN_AND_PORTS
    elseif string.find(uncompressed_data_str, '{"request":"proxy config",') then
        -- either from server to passive proxy, or from active proxy to server
        oper_type = T_PROXY_CONFIG
        hostname = string.match(uncompressed_data_str, '"host":"(.-)"')
        if hostname then
            proxy_name = hostname
        else
            hostname = "<unknown>"
        end
        version_string = string.match(uncompressed_data_str, '"version":"(.-)"')
        tree_text = "Zabbix Request proxy config for \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Request proxy config for \"" .. hostname .. "\", " .. LEN_AND_PORTS
    elseif string.find(uncompressed_data_str, '{"request":"proxy heartbeat",') then
        -- from active proxy to server
        oper_type = T_PROXY_HEARTBEAT
        hostname = string.match(uncompressed_data_str, '"host":"(.-)"')
        if hostname then
            proxy_name = hostname
        else
            hostname = "<unknown>"
        end
        version_string = string.match(uncompressed_data_str, '"version":"(.-)"')
        tree_text = "Zabbix Proxy heartbeat for \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Proxy heartbeat for \"" .. hostname .. "\", " .. LEN_AND_PORTS
    elseif string.find(uncompressed_data_str, '{"session":"') then
        -- response to "proxy data" request from passive proxy
        oper_type = T_PASSIVE_PROXY_RESPONSE
        version_string = string.match(uncompressed_data_str, '"version":"(.-)"')
        tree_text = "Zabbix Passive Proxy Response, " .. LEN
        info_text = "Zabbix Passive Proxy Response, " .. LEN_AND_PORTS
    elseif string.find(uncompressed_data_str, '{"globalmacro":') then
        -- response for active proxy config request
        oper_type = T_PROXY_CONFIG
        tree_text = "Zabbix Response for proxy config, " .. LEN
        info_text = "Zabbix Response for proxy config, " .. LEN_AND_PORTS
    elseif string.find(uncompressed_data_str, '{"response":"success"') then
        -- response of some sort, successful
        oper_type = T_SUCCESS + T_RESPONSE
        version_string = string.match(uncompressed_data_str, '"version":"(.-)"')
        tree_text = "Zabbix Response (success), " .. LEN
        info_text = "Zabbix Response (success), " .. LEN_AND_PORTS
    elseif string.find(uncompressed_data_str, '{"response":"failed"') then
        -- response of some sort, failed
        oper_type = T_FAILED + T_RESPONSE
        version_string = string.match(uncompressed_data_str, '"version":"(.-)"')
        tree_text = "Zabbix Response (failed), " .. LEN
        info_text = "Zabbix Response (failed), " .. LEN_AND_PORTS
    end

    if default_settings.info_text then
        pktinfo.cols.info = info_text
    end

    local subtree = tree:add(zabbix_protocol, buffer(), tree_text)
    subtree:add_le(p_header, buffer(0,4))
    subtree:add_le(p_version, buffer(4,1), version, nil, "[Data is compressed]")
    subtree:add_le(p_length, buffer(5,4))
    subtree:add_le(p_uncompressed_length, buffer(9,4))
    subtree:add(buffer(13),"Compressed data (" .. buffer(13):len() .. " bytes)")
    if proxy_name then
        subtree:add(p_proxy_name, proxy_name)
    end
    if version_string then
        subtree:add(p_version_string, version_string)
    end
    if band(oper_type, T_PROXY_DATA) then subtree:add(p_proxy_data,1):set_generated() end
    if band(oper_type, T_PROXY_CONFIG) then subtree:add(p_proxy_config,1):set_generated() end
    if band(oper_type, T_PROXY_HEARTBEAT) then subtree:add(p_proxy_heartbeat,1):set_generated() end
    if band(oper_type, T_PASSIVE_PROXY_RESPONSE) then subtree:add(p_proxy_response,1):set_generated() end
    if band(oper_type, T_RESPONSE) then subtree:add(p_response,1):set_generated() end
    if band(oper_type, T_SUCCESS) then subtree:add(p_success,1):set_generated() end
    if band(oper_type, T_FAILED) then subtree:add(p_failed,1):set_generated() end
    subtree:add(p_data, uncompressed_data)
    -- set zabbix.datalen to the uncompressed length
    subtree:add(p_data_len, original_length, nil, "(uncompressed length)"):set_generated()
    -- now save the timestamp or calculate response time
    if band(oper_type, T_REQUEST) then
        -- make hash string for the request
        local hash_string = tostring(pktinfo.src) .. ":" .. tostring(pktinfo.src_port) ..
            "-" .. tostring(pktinfo.dst) .. ":" .. tostring(pktinfo.dst_port)
        -- save the request timestamp
        timestamps[hash_string] = pktinfo.abs_ts
    elseif band(oper_type, T_RESPONSE) then
        -- make hash string for the response
        local hash_string = tostring(pktinfo.dst) .. ":" .. tostring(pktinfo.dst_port) ..
            "-" .. tostring(pktinfo.src) .. ":" .. tostring(pktinfo.src_port)
        local request_timestamp = timestamps[hash_string]
        if request_timestamp then
            local response_time = pktinfo.abs_ts - request_timestamp
            subtree:add(p_time, response_time, "Time since request:", string.format("%.6f", response_time), "seconds"):set_generated()
        end
    end
end

-- #######################################
-- protocol dissector function
-- #######################################
function zabbix_protocol.dissector(buffer, pktinfo, tree)
    local ZBXD_HEADER_LEN = 13
    local pktlength = buffer:len()
    if pktlength < ZBXD_HEADER_LEN or buffer(0,4):string() ~= "ZBXD" then
        -- there is no ZBXD signature
        -- maybe this is encrypted, or not Zabbix after all
        -- print("No ZBXD header")
        return 0
    end

    -- set Protocol column manually to get it in mixed case instead of all caps
    pktinfo.cols.protocol = PROTOCOL_NAME

    -- set the default text for Info column, it will be overridden later if possible
    if default_settings.info_text then
        pktinfo.cols.info = "Zabbix data"
    end

    -- get the protocol version and data length
    local version = buffer(4,1):uint()
    -- note the length field is only 4 bytes, verified from the Zabbix 4.0.0 sources, not 8 bytes
    -- the 4 next bytes are "reserved", used in version 3 (compressed) as shown later
    local data_length = buffer(5,4):le_uint()

    local bytes_needed = ZBXD_HEADER_LEN + data_length
    if bytes_needed > pktlength and default_settings.reassemble then
        -- we need more bytes than is in the current segment, try to get more
        pktinfo.desegment_offset = 0
        pktinfo.desegment_len = data_length + ZBXD_HEADER_LEN - pktlength
        -- dissect anyway to show something if the TCP setting "Allow subdissector to
        -- reassemble TCP streams" is disabled
        if version == 3 then
            doDissectCompressed(buffer, pktinfo, tree)
        else
            doDissect(buffer, pktinfo, tree)
        end
        -- set helpful text in Info column before returning
        pktinfo.cols.info = "[Partial Zabbix data, enable TCP subdissector reassembly]"
        return
    end

    -- now we have the data to dissect, let's do it
    if version == 3 then
        -- 0x01 (ZBX_TCP_PROTOCOL) + 0x02 (ZBX_TCP_COMPRESS) -> this is compressed data
        -- (see include/comms.h in Zabbix sources)
        doDissectCompressed(buffer, pktinfo, tree)
    else
        -- uncompressed (version 1) data or unknown version, just try to dissect
        doDissect(buffer, pktinfo, tree)
    end
end


function zabbix_protocol.init()
    -- empty the timestamps table
    timestamps = {}
end


local function enableDissector()
    DissectorTable.get("tcp.port"):add(default_settings.ports, zabbix_protocol)
    -- supports also TLS decryption if the session keys are configured in Wireshark
    DissectorTable.get("tls.port"):add(default_settings.ports, zabbix_protocol)
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.ports, zabbix_protocol)
    DissectorTable.get("tls.port"):remove(default_settings.ports, zabbix_protocol)
end

-- register our preferences
zabbix_protocol.prefs.reassemble = Pref.bool("Reassemble Zabbix messages spanning multiple TCP segments",
    default_settings.reassemble, "Whether the Zabbix dissector should reassemble messages " ..
    "spanning multiple TCP segments. To use this option, you must also enable \"Allow subdissectors to " ..
    "reassemble TCP streams\" in the TCP protocol settings")

zabbix_protocol.prefs.info_text = Pref.bool("Show Zabbix protocol data in Info column",
    default_settings.info_text, "Disable this to show the default TCP protocol data in the Info column")

zabbix_protocol.prefs.ports_in_info = Pref.bool("Show TCP ports in Info column",
    default_settings.ports_in_info, "Disable this to have only Zabbix data in the Info column")

zabbix_protocol.prefs.ports = Pref.range("Port(s)", default_settings.ports, "Set the TCP port(s) for Zabbix, default is 10051", 65535)

zabbix_protocol.prefs.text = Pref.statictext("This dissector is written in Lua.","")


-- the function for handling preferences being changed
function zabbix_protocol.prefs_changed()
    if default_settings.reassemble ~= zabbix_protocol.prefs.reassemble then
        default_settings.reassemble = zabbix_protocol.prefs.reassemble
        -- capture file reload needed
        reload()
    elseif default_settings.info_text ~= zabbix_protocol.prefs.info_text then
        default_settings.info_text = zabbix_protocol.prefs.info_text
        -- capture file reload needed
        reload()
    elseif default_settings.ports_in_info ~= zabbix_protocol.prefs.ports_in_info then
        default_settings.ports_in_info = zabbix_protocol.prefs.ports_in_info
        -- capture file reload needed
        reload()
    elseif default_settings.ports ~= zabbix_protocol.prefs.ports then
        disableDissector()
        default_settings.ports = zabbix_protocol.prefs.ports
        enableDissector()
    end
end
