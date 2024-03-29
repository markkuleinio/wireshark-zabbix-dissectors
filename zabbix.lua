local plugin_info = {
    version = "2023-08-06.1",
    author = "Markku Leiniö",
    repository = "https://github.com/markkuleinio/wireshark-zabbix-dissectors",
}
set_plugin_info(plugin_info)
if Dissector.get("zabbix") then
    local ignore_text = "Your Wireshark version already contains Zabbix protocol dissector compiled in. " ..
        "Therefore the Zabbix dissector in your local Lua script is ignored:\n" ..
        debug.getinfo(1, "S").source:sub(2) ..
        "\nDelete/move the script to remove this message."
    if gui_enabled() then
        local win = TextWindow.new("Note from Zabbix Lua dissector")
        win:set(ignore_text)
    else
        print(ignore_text)
    end
    return
end
local zabbix_protocol = Proto("Zabbix", "Zabbix Protocol")
-- for some reason the protocol name is shown in UPPERCASE in Protocol column
-- (and in Proto.name), so let's define a string to override that
local PROTOCOL_NAME = "Zabbix"

local p_header = ProtoField.string("zabbix.header", "Header", base.ASCII)
local p_flags = ProtoField.uint8("zabbix.flags", "Flags", base.HEX)
local yes_no_map = {[1] = "Yes", [2] = "No"}
local p_flag_zabbix = ProtoField.bool("zabbix.flags.zabbix", "Zabbix communications protocol", 8, yes_no_map, 0x01)
local p_flag_compressed = ProtoField.bool("zabbix.flags.compressed", "Compressed", 8, yes_no_map, 0x02)
local p_flag_largepacket = ProtoField.bool("zabbix.flags.largepacket", "Large packet", 8, yes_no_map, 0x04)
local p_flag_reservedbits = ProtoField.uint8("zabbix.flags.reserved", "Reserved bits", base.DEC, {[0] = "All zeros"}, 0xF8, "Reserved, should be zeros")
local p_length = ProtoField.uint32("zabbix.len", "Length", base.DEC)
local p_reserved = ProtoField.uint32("zabbix.reserved", "Reserved", base.DEC)
local p_uncompressed_length = ProtoField.uint32("zabbix.uncompressedlen", "Uncompressed length", base.DEC)
local p_large_length = ProtoField.uint64("zabbix.large.len", "Large length", base.DEC)
local p_large_reserved = ProtoField.uint64("zabbix.large.reserved", "Large reserved", base.DEC)
local p_large_uncompressed_length = ProtoField.uint64("zabbix.large.uncompressedlen", "Large uncompressed length", base.DEC)
local p_data = ProtoField.string("zabbix.data", "Data", base.ASCII)
-- zabbix.datalen is derived from data length or from uncompressed length
local p_data_len = ProtoField.uint32("zabbix.datalen", "Data length", base.DEC)
local p_success = ProtoField.bool("zabbix.success", "Success")
local p_failed = ProtoField.bool("zabbix.failed", "Failed")
local p_response = ProtoField.bool("zabbix.response", "Response")
local p_version = ProtoField.string("zabbix.version", "Version", base.ASCII)
local p_session = ProtoField.string("zabbix.session", "Session", base.ASCII)
local p_config_revision = ProtoField.uint64("zabbix.configrevision", "Config Revision", base.DEC)
local p_agent = ProtoField.bool("zabbix.agent", "Active Agent Connection")
local p_agent_name = ProtoField.string("zabbix.agent.name", "Agent Name", base.ASCII)
local p_agent_hostmetadata = ProtoField.string("zabbix.agent.hostmetadata", "Agent Host Metadata", base.ASCII)
local p_agent_hostinterface = ProtoField.string("zabbix.agent.hostinterface", "Agent Host Interface", base.ASCII)
local p_agent_listenipv4 = ProtoField.ipv4("zabbix.agent.listenipv4", "Agent Listen IPv4")
local p_agent_listenipv6 = ProtoField.ipv6("zabbix.agent.listenipv6", "Agent Listen IPv6")
local p_agent_listenport = ProtoField.uint16("zabbix.agent.listenport", "Agent Listen Port")
local p_agent_checks = ProtoField.bool("zabbix.agent.activechecks", "Agent Active Checks")
local p_agent_data = ProtoField.bool("zabbix.agent.data", "Agent Data")
local p_agent_heartbeatfreq = ProtoField.uint16("zabbix.agent.heartbeatfreq", "Agent Heartbeat Frequency")
local p_proxy = ProtoField.bool("zabbix.proxy", "Proxy Connection")
local p_proxy_name = ProtoField.string("zabbix.proxy.name", "Proxy Name", base.ASCII)
local p_proxy_heartbeat = ProtoField.bool("zabbix.proxy.heartbeat", "Proxy Heartbeat")
local p_proxy_data = ProtoField.bool("zabbix.proxy.data", "Proxy Data")
local p_proxy_config = ProtoField.bool("zabbix.proxy.config", "Proxy Config")
local p_proxy_fullsync = ProtoField.bool("zabbix.proxy.fullsync", "Proxy Full Sync")
local p_proxy_incremental_config = ProtoField.bool("zabbix.proxy.incrementalconfig", "Proxy Incremental Config")
local p_proxy_no_config_change = ProtoField.bool("zabbix.proxy.noconfigchange", "Proxy No Config Change")
local p_proxy_response = ProtoField.bool("zabbix.proxy.response", "Proxy Response")
local p_sender = ProtoField.bool("zabbix.sender", "Sender Connection")
local p_sender_data = ProtoField.bool("zabbix.sender.data", "Sender Data")
local p_time = ProtoField.float("zabbix.time", "Time since the request was sent")

zabbix_protocol.fields = {
    p_header, p_flags, p_flag_zabbix, p_flag_compressed, p_flag_largepacket, p_flag_reservedbits,
    p_length, p_reserved, p_uncompressed_length,
    p_large_length, p_large_reserved, p_large_uncompressed_length,
    p_data, p_data_len, p_success, p_failed, p_response,
    p_version, p_session, p_config_revision,
    p_agent, p_agent_name, p_agent_checks, p_agent_data, p_agent_heartbeatfreq,
    p_agent_hostmetadata, p_agent_hostinterface, p_agent_listenipv4, p_agent_listenipv6, p_agent_listenport,
    p_proxy, p_proxy_name, p_proxy_heartbeat, p_proxy_data, p_proxy_config, p_proxy_fullsync,
    p_proxy_incremental_config, p_proxy_no_config_change, p_proxy_response,
    p_sender, p_sender_data, p_time,
}

local e_unknown_use = ProtoExpert.new("zabbix.expert.unknown",
    "Could not identify as agent or proxy connection, maybe request was not captured?",
    expert.group.RESPONSE_CODE, expert.severity.NOTE)
local e_failed_response = ProtoExpert.new("zabbix.expert.failed",
    "Returned response: \"failed\"",
    expert.group.RESPONSE_CODE, expert.severity.NOTE)

zabbix_protocol.experts = {
    e_unknown_use, e_failed_response,
}

local T_SUCCESS = 0x0001
local T_FAILED = 0x0002
local T_REQUEST = 0x0004
local T_RESPONSE = 0x0008
local T_CHECKS = 0x0010
local T_AGENT_DATA = 0x0020
local T_AGENT_HEARTBEAT = 0x0040
local T_PROXY_HEARTBEAT = 0x0080
local T_PROXY_CONFIG = 0x0100
local T_PROXY_FULLSYNC = 0x0200
local T_PROXY_INCREMENTAL_CONFIG = 0x0400
local T_PROXY_NO_CONFIG_CHANGE = 0x0800
local T_PROXY_DATA = 0x1000
local T_PASSIVE_PROXY_RESPONSE = 0x2000
local T_SENDER_DATA = 0x4000

-- flags in Zabbix protocol header
local FLAG_ZABBIX_COMMUNICATIONS = 0x01
local FLAG_COMPRESSED = 0x02
local FLAG_LARGE_PACKET = 0x04

local default_settings =
{
    debug_level = DEBUG,
    ports = "10051",   -- the default TCP port for Zabbix
    reassemble = true, -- whether we try reassembly or not
    info_text = true,  -- show our own Info column data or TCP defaults
    ports_in_info = true, -- show TCP ports in Info column
}

-- tables for data saved about the sessions
local timestamps = {}
local agent_names = {}
local proxy_names = {}
local senders = {}

local function band(a, b)
    if bit.band(a, b) > 0 then return true
    else return false
    end
end

-- used for JSON output in the protocol tree
local json_dissector = Dissector.get("json")


-- ###############################################################################
local function doDissect(buffer, pktinfo, tree)
    local flags = buffer(4,1):uint()
    local IS_COMPRESSED = false
    if band(flags, FLAG_COMPRESSED) then
        IS_COMPRESSED = true
    end
    local IS_LARGE_PACKET
    local DATA_OFFSET
    local data_length
    local original_length
    if band(flags, FLAG_LARGE_PACKET) then
        -- large packet has length fields as 8 bytes instead of 4 bytes,
        -- available since 5.0.x
        IS_LARGE_PACKET = true
        DATA_OFFSET = 21
        data_length = buffer(5,8):le_uint()
        original_length = buffer(13,8):le_uint()
    else
        IS_LARGE_PACKET = false
        DATA_OFFSET = 13
        data_length = buffer(5,4):le_uint()
        original_length = buffer(9,4):le_uint()
    end
    local data_str
    local uncompressed_data
    if IS_COMPRESSED then
        uncompressed_data = buffer(DATA_OFFSET):uncompress()
        data_str = uncompressed_data:string()
    else
        data_str = buffer(DATA_OFFSET):string()
    end
    local LEN = "Len: " .. data_length
    local LEN_AND_PORTS = "Len=" .. data_length
    if default_settings.ports_in_info then
        LEN_AND_PORTS = LEN_AND_PORTS .. " (" .. pktinfo.src_port .. " → " .. pktinfo.dst_port .. ")"
    end

    -- set default values, then modify them as needed:
    local oper_type = 0 -- undefined
    local agent = false
    local proxy = false
    local sender = false
    local agent_name = nil
    local agent_hostmetadata = nil
    local agent_hostinterface = nil
    local agent_listenip = nil
    local agent_listenport = nil
    local proxy_name = nil
    local version = nil
    local session = nil
    local config_revision = nil
    local agent_heartbeat_freq = nil
    local tree_text = "Zabbix Protocol, Flags: " .. flags .. ", " .. LEN
    local info_text = "Zabbix Protocol, Flags=" .. flags .. ", " .. LEN_AND_PORTS

    if string.find(data_str, '{"request":"active checks",') then
        -- agent requesting for active checks
        agent = true
        oper_type = T_CHECKS + T_REQUEST
        local hostname = string.match(data_str, '"host":"(.-)"')
        if hostname then
            agent_name = hostname
        else
            hostname = "<unknown>"
        end
        tree_text = "Zabbix Request for active checks for \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Request for active checks for \"" .. hostname .. "\", " .. LEN_AND_PORTS
        version = string.match(data_str, '"version":"(.-)"')
        agent_hostmetadata = string.match(data_str, '"host_metadata":"(.-)"')
        agent_hostinterface = string.match(data_str, '"interface":"(.-)"')
        agent_listenip = string.match(data_str, '"ip":"(.-)"')
        agent_listenport = string.match(data_str, '"port":([0-9]*)')
        config_revision = string.match(data_str, ',"config_revision":(%d+)')
    elseif string.find(data_str, '{"request":"agent data",') then
        -- active agent sending data
        agent = true
        oper_type = T_AGENT_DATA + T_REQUEST
        -- try matching host name in legacy agent style, inside "data" array
        local hostname = string.match(data_str, '"data":%[{"host":"(.-)"')
        if hostname then
            agent_name = hostname
        else
            -- not matched, now try the agent 2 syntax ("host" is outside the "data" array)
            hostname = string.match(data_str, '"data":%[.*%].*"host":"(.-)"')
            if hostname then
                agent_name = hostname
            else
                hostname = "<unknown>"
            end
        end
        tree_text = "Zabbix Send agent data from \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Send agent data from \"" .. hostname .. "\", " .. LEN_AND_PORTS
        version = string.match(data_str, '"data":%[.*%].*"version":"(.-)"')
        session = string.match(data_str, '{"request":"agent data","session":"(.-)"')
        if not session then
            session = string.match(data_str, '"data":%[.*%].*"session":"(.-)"')
        end
    elseif string.find(data_str, '{"request":"active check heartbeat",') then
        -- active agent sending heartbeats
        agent = true
        oper_type = T_AGENT_HEARTBEAT + T_REQUEST
        local hostname = string.match(data_str, '"host":"(.-)"')
        if hostname then
            agent_name = hostname
        else
            hostname = "<unknown>"
        end
        tree_text = "Zabbix Agent heartbeat from \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Agent heartbeat from \"" .. hostname .. "\", " .. LEN_AND_PORTS
        agent_heartbeat_freq = string.match(data_str, '"heartbeat_freq":([0-9]*)')
    elseif string.find(data_str, '{"response":"success","info":') then
        -- response for active agent or sender (trapper) data send
        local retrieve_hash = tostring(pktinfo.dst) .. ":" .. tostring(pktinfo.dst_port) ..
        "-" .. tostring(pktinfo.src) .. ":" .. tostring(pktinfo.src_port)
        if senders[retrieve_hash] then
            sender = true
            oper_type = T_SUCCESS + T_SENDER_DATA + T_RESPONSE
            tree_text = "Zabbix Response for sender data (success), " .. LEN
            info_text = "Zabbix Response for sender data (success), " .. LEN_AND_PORTS
        else
            agent = true
            oper_type = T_SUCCESS + T_AGENT_DATA + T_RESPONSE
            tree_text = "Zabbix Response for agent data (success), " .. LEN
            info_text = "Zabbix Response for agent data (success), " .. LEN_AND_PORTS
        end
    elseif string.find(data_str, '{"response":"success",') then
        -- response for agent's request for active checks
        agent = true
        oper_type = T_SUCCESS + T_CHECKS + T_RESPONSE
        tree_text = "Zabbix Response for active checks (success), " .. LEN
        info_text = "Zabbix Response for active checks (success), " .. LEN_AND_PORTS
        config_revision = string.match(data_str, ',"config_revision":(%d+)')
    elseif string.find(data_str, '{"request":"proxy data",') then
        -- from active proxy to server
        proxy = true
        oper_type = T_PROXY_DATA + T_REQUEST
        local hostname = string.match(data_str, '"host":"(.-)"')
        if hostname then
            proxy_name = hostname
        else
            hostname = "<unknown>"
        end
        version = string.match(data_str, '"version":"(.-)"')
        tree_text = "Zabbix Proxy data from \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Proxy data from \"" .. hostname .. "\", " .. LEN_AND_PORTS
        session = string.match(data_str, '"session":"(.-)"')
    elseif string.find(data_str, '{"request":"proxy data"}') then
        -- from server to passive proxy
        proxy = true
        oper_type = T_PROXY_DATA + T_REQUEST
        tree_text = "Zabbix Request for passive proxy data, " .. LEN
        info_text = "Zabbix Request for passive proxy data, " .. LEN_AND_PORTS
    elseif string.find(data_str, '{"request":"proxy config"') then
        -- either from server to passive proxy, or from active proxy to server
        proxy = true
        oper_type = T_PROXY_CONFIG + T_REQUEST
        local hostname = string.match(data_str, '"host":"(.-)"')
        if hostname then
            -- this is active proxy requesting config
            proxy_name = hostname
            version = string.match(data_str, '"version":"(.-)"')
            tree_text = "Zabbix Request proxy config for \"" .. hostname .. "\", " .. LEN
            info_text = "Zabbix Request proxy config for \"" .. hostname .. "\", " .. LEN_AND_PORTS
        elseif string.find(data_str, '{"request":"proxy config"}') then
            -- this is server to passive proxy in Zabbix 6.4 starting to send config
            tree_text = "Zabbix Start send proxy config to passive proxy, " .. LEN
            info_text = "Zabbix Start send proxy config to passive proxy, " .. LEN_AND_PORTS
        else
            -- this is server sending config to passive proxy before Zabbix 6.4
            tree_text = "Zabbix Send proxy config to passive proxy, " .. LEN
            info_text = "Zabbix Send proxy config to passive proxy, " .. LEN_AND_PORTS
        end
    elseif string.find(data_str, '{"request":"proxy heartbeat",') then
        -- from active proxy to server
        proxy = true
        oper_type = T_PROXY_HEARTBEAT + T_REQUEST
        local hostname = string.match(data_str, '"host":"(.-)"')
        if hostname then
            proxy_name = hostname
        else
            hostname = "<unknown>"
        end
        version = string.match(data_str, '"version":"(.-)"')
        tree_text = "Zabbix Proxy heartbeat for \"" .. hostname .. "\", " .. LEN
        info_text = "Zabbix Proxy heartbeat for \"" .. hostname .. "\", " .. LEN_AND_PORTS
    elseif string.find(data_str, '{"globalmacro":') then
        -- response for active proxy config request before Zabbix 6.4
        proxy = true
        oper_type = T_PROXY_CONFIG + T_RESPONSE
        tree_text = "Zabbix Response for proxy config, " .. LEN
        info_text = "Zabbix Response for proxy config, " .. LEN_AND_PORTS
    elseif string.find(data_str, '{"full_sync":1,') then
        -- response for active proxy config request, or passive proxy
        -- configuration (both in Zabbix 6.4+)
        proxy = true
        local calc_hash = tostring(pktinfo.src) .. ":" .. tostring(pktinfo.src_port) ..
            "-" .. tostring(pktinfo.dst) .. ":" .. tostring(pktinfo.dst_port)
        if timestamps[calc_hash] then
            -- this session is already found, so this is a passive proxy config
            oper_type = T_PROXY_CONFIG + T_PROXY_FULLSYNC
            tree_text = "Zabbix Passive proxy config, " .. LEN
            info_text = "Zabbix Passive proxy config, " .. LEN_AND_PORTS
        else
            oper_type = T_PROXY_CONFIG + T_PROXY_FULLSYNC + T_RESPONSE
            tree_text = "Zabbix Response for proxy config, " .. LEN
            info_text = "Zabbix Response for proxy config, " .. LEN_AND_PORTS
        end
        config_revision = string.match(data_str, ',"config_revision":(%d+)')
    elseif string.find(data_str, '{"data":{},') then
        -- response for active proxy config request, or passive proxy
        -- configuration when not full sync and no config change (both in Zabbix 6.4+)
        proxy = true
        local calc_hash = tostring(pktinfo.src) .. ":" .. tostring(pktinfo.src_port) ..
            "-" .. tostring(pktinfo.dst) .. ":" .. tostring(pktinfo.dst_port)
        if timestamps[calc_hash] then
            -- this session is already found, so this is a passive proxy config
            oper_type = T_PROXY_CONFIG + T_PROXY_NO_CONFIG_CHANGE
            tree_text = "Zabbix Passive proxy config, " .. LEN
            info_text = "Zabbix Passive proxy config, " .. LEN_AND_PORTS
        else
            oper_type = T_PROXY_CONFIG + T_PROXY_NO_CONFIG_CHANGE + T_RESPONSE
            tree_text = "Zabbix Response for proxy config, " .. LEN
            info_text = "Zabbix Response for proxy config, " .. LEN_AND_PORTS
        end
        config_revision = string.match(data_str, ',"config_revision":(%d+)')
    elseif string.find(data_str, '{"data":{') then
        -- response for active proxy config request, or passive proxy
        -- configuration when not full sync and incremental config change is present
        -- (both in Zabbix 6.4+)
        proxy = true
        local calc_hash = tostring(pktinfo.src) .. ":" .. tostring(pktinfo.src_port) ..
            "-" .. tostring(pktinfo.dst) .. ":" .. tostring(pktinfo.dst_port)
        if timestamps[calc_hash] then
            -- this session is already found, so this is a passive proxy config
            oper_type = T_PROXY_CONFIG + T_PROXY_INCREMENTAL_CONFIG
            tree_text = "Zabbix Passive proxy config, " .. LEN
            info_text = "Zabbix Passive proxy config, " .. LEN_AND_PORTS
        else
            oper_type = T_PROXY_CONFIG + T_PROXY_INCREMENTAL_CONFIG + T_RESPONSE
            tree_text = "Zabbix Response for proxy config, " .. LEN
            info_text = "Zabbix Response for proxy config, " .. LEN_AND_PORTS
        end
        config_revision = string.match(data_str, ',"config_revision":(%d+)')
    elseif string.find(data_str, '{"session":"') then
        -- response to "proxy data" request from passive proxy
        proxy = true
        oper_type = T_PASSIVE_PROXY_RESPONSE + T_RESPONSE
        version = string.match(data_str, '"version":"(.-)"')
        tree_text = "Zabbix Passive Proxy Response, " .. LEN
        info_text = "Zabbix Passive Proxy Response, " .. LEN_AND_PORTS
        session = string.match(data_str, '"session":"(.-)"')
    elseif string.find(data_str, '{"globalmacro":') then
        -- response for active proxy config request
        proxy = true
        oper_type = T_PROXY_CONFIG + T_RESPONSE
        tree_text = "Zabbix Response for proxy config, " .. LEN
        info_text = "Zabbix Response for proxy config, " .. LEN_AND_PORTS
    elseif string.find(data_str, '{"version":') then
        -- response from passive proxy for config request
        proxy = true
        oper_type = T_PROXY_CONFIG + T_RESPONSE
        tree_text = "Zabbix Response for proxy config, " .. LEN
        info_text = "Zabbix Response for proxy config, " .. LEN_AND_PORTS
        version = string.match(data_str, '{"version":"(.-)"')
        session = string.match(data_str, '"session":"(.-)"')
        config_revision = string.match(data_str, ',"config_revision":(%d+)')
    elseif string.find(data_str, '{"request":"sender data","data":') then
        -- sender/trapper
        sender = true
        oper_type = T_SENDER_DATA + T_REQUEST
        tree_text = "Zabbix Sender data, " .. LEN
        info_text = "Zabbix Sender data, " .. LEN_AND_PORTS
    elseif string.find(data_str, '"response":"success"') then
        -- response of some sort, successful
        proxy = true
        oper_type = T_SUCCESS + T_RESPONSE
        version = string.match(data_str, '"version":"(.-)"')
        tree_text = "Zabbix Response (success), " .. LEN
        info_text = "Zabbix Response (success), " .. LEN_AND_PORTS
    elseif string.find(data_str, '"response":"failed"') then
        -- response of some sort, failed
        proxy = true
        oper_type = T_FAILED + T_RESPONSE
        version = string.match(data_str, '"version":"(.-)"')
        tree_text = "Zabbix Response (failed), " .. LEN
        info_text = "Zabbix Response (failed), " .. LEN_AND_PORTS
    end

    if default_settings.info_text then
        pktinfo.cols.info = info_text
    end

    -- populate the hash strings
    local retrieve_hash = nil
    if band(oper_type, T_REQUEST) then
        -- make hash string for the request
        local save_hash = tostring(pktinfo.src) .. ":" .. tostring(pktinfo.src_port) ..
            "-" .. tostring(pktinfo.dst) .. ":" .. tostring(pktinfo.dst_port)
        -- save the request timestamp
        timestamps[save_hash] = pktinfo.abs_ts
        if agent_name then
            -- agent name was detected, save it as well
            agent_names[save_hash] = agent_name
        end
        if proxy_name then
            -- proxy name was detected, save it as well
            proxy_names[save_hash] = proxy_name
        end
        if sender then
            senders[save_hash] = true
        end
    end
    local subtree = tree:add(zabbix_protocol, buffer(), tree_text)
    subtree:add_le(p_header, buffer(0,4))
    local flags_str = nil
    if IS_COMPRESSED then
        if IS_LARGE_PACKET then
            flags_str = "[Compressed, large packet]"
        else
            flags_str = "[Compressed]"
        end
    end
    local flagstree
    if flags_str then
        flagstree = subtree:add_le(p_flags, buffer(4,1), flags, nil, flags_str)
    else
        flagstree = subtree:add_le(p_flags, buffer(4,1))
    end
    flagstree:add_le(p_flag_reservedbits, buffer(4,1))
    flagstree:add_le(p_flag_largepacket, buffer(4,1))
    flagstree:add_le(p_flag_compressed, buffer(4,1))
    flagstree:add_le(p_flag_zabbix, buffer(4,1))
    if IS_LARGE_PACKET then
        subtree:add_le(p_large_length, buffer(5,8))
        if IS_COMPRESSED then
            subtree:add_le(p_large_uncompressed_length, buffer(13,8))
        else
            subtree:add_le(p_large_reserved, buffer(13,8))
        end
    else
        subtree:add_le(p_length, buffer(5,4))
        if IS_COMPRESSED then
            subtree:add_le(p_uncompressed_length, buffer(9,4))
        else
            subtree:add_le(p_reserved, buffer(9,4))
        end
    end
    if IS_COMPRESSED then
        subtree:add(buffer(DATA_OFFSET), "Compressed data (" .. buffer(DATA_OFFSET):len() .. " bytes)")
    end
    local saved_agent_name = nil
    local saved_proxy_name = nil
    if band(oper_type, T_RESPONSE) then
        -- make hash string for the response
        retrieve_hash = tostring(pktinfo.dst) .. ":" .. tostring(pktinfo.dst_port) ..
            "-" .. tostring(pktinfo.src) .. ":" .. tostring(pktinfo.src_port)
        saved_agent_name = agent_names[retrieve_hash]
        if saved_agent_name then
            agent = true -- in case it was not already detected from the response
        end
        saved_proxy_name = proxy_names[retrieve_hash]
        if saved_proxy_name then
            proxy = true -- in case it was not already detected from the response
        end
    end
    if agent then
        subtree:add(p_agent, 1, "This is an agent connection"):set_generated()
    elseif proxy then
        subtree:add(p_proxy, 1, "This is a proxy connection"):set_generated()
    elseif sender then
        subtree:add(p_sender, 1, "This is a sender connection"):set_generated()
    else
        subtree:add("Not agent or proxy"):set_generated():add_proto_expert_info(e_unknown_use)
    end
    if session then subtree:add(p_session, session) end
    if agent_name then
        subtree:add(p_agent_name, agent_name)
    elseif proxy_name then
        subtree:add(p_proxy_name, proxy_name)
    elseif saved_agent_name then
        subtree:add(p_agent_name, saved_agent_name, "Agent name from the request:", saved_agent_name):set_generated()
    elseif saved_proxy_name then
        subtree:add(p_proxy_name, saved_proxy_name, "Proxy name from the request:", saved_proxy_name):set_generated()
    end
    if version then
        subtree:add(p_version, version)
    end
    if agent_hostmetadata then
        subtree:add(p_agent_hostmetadata, agent_hostmetadata)
    end
    if agent_hostinterface then
        subtree:add(p_agent_hostinterface, agent_hostinterface)
    end
    if agent_listenip then
        if string.find(agent_listenip, ":") then
            subtree:add(p_agent_listenipv6, Address.ipv6(agent_listenip))
        else
            subtree:add(p_agent_listenipv4, Address.ipv4(agent_listenip))
        end
    end
    if agent_listenport then
        subtree:add(p_agent_listenport, agent_listenport)
    end
    if agent_heartbeat_freq then
        subtree:add(p_agent_heartbeatfreq, agent_heartbeat_freq)
    end
    if band(oper_type, T_CHECKS) then
        if band(oper_type, T_REQUEST) then subtree:add(p_agent_checks,1)
        -- response does not show "active checks", set generated flag
        else subtree:add(p_agent_checks,1):set_generated() end
    end
    if band(oper_type, T_AGENT_DATA) then
        if band(oper_type, T_REQUEST) then subtree:add(p_agent_data,1)
        -- response does not show "agent data", set generated flag
        else subtree:add(p_agent_data,1):set_generated() end
    end
    if band(oper_type, T_SENDER_DATA) then
        if band(oper_type, T_REQUEST) then subtree:add(p_sender_data,1)
        -- response is generic, set generated flag
        else subtree:add(p_sender_data,1):set_generated() end
    end
    if band(oper_type, T_PROXY_DATA) then subtree:add(p_proxy_data,1) end
    if band(oper_type, T_PROXY_CONFIG) then subtree:add(p_proxy_config,1) end
    if band(oper_type, T_PROXY_FULLSYNC) then subtree:add(p_proxy_fullsync,1) end
    if band(oper_type, T_PROXY_INCREMENTAL_CONFIG) then subtree:add(p_proxy_incremental_config,1) end
    if band(oper_type, T_PROXY_NO_CONFIG_CHANGE) then subtree:add(p_proxy_no_config_change,1) end
    if band(oper_type, T_PROXY_HEARTBEAT) then subtree:add(p_proxy_heartbeat,1) end
    if band(oper_type, T_PASSIVE_PROXY_RESPONSE) then subtree:add(p_proxy_response,1):set_generated() end
    if config_revision then subtree:add(p_config_revision, UInt64.new(config_revision)) end
    if band(oper_type, T_RESPONSE) then subtree:add(p_response,1) end
    if band(oper_type, T_SUCCESS) then subtree:add(p_success,1) end
    if band(oper_type, T_FAILED) then
        subtree:add(p_failed,1)
        if IS_COMPRESSED then
            subtree:add(p_data, uncompressed_data):add_proto_expert_info(e_failed_response)
        else
            subtree:add(p_data, buffer(DATA_OFFSET)):add_proto_expert_info(e_failed_response)
        end
    else
        if IS_COMPRESSED then
            subtree:add(p_data, uncompressed_data)
        else
            subtree:add(p_data, buffer(DATA_OFFSET))
        end
    end
    if IS_COMPRESSED then
        json_dissector(uncompressed_data:tvb(), pktinfo, subtree)
        -- set zabbix.datalen to the uncompressed length
        subtree:add(p_data_len, original_length, nil, "(uncompressed length)"):set_generated()
    else
        json_dissector(buffer(DATA_OFFSET):tvb(), pktinfo, subtree)
        subtree:add(p_data_len, data_length):set_generated()
    end
    -- calculate and output the response time
    if band(oper_type, T_RESPONSE) then
        local request_timestamp = timestamps[retrieve_hash]
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
    local pktlength = buffer:len()
    if pktlength < 13 or buffer(0,4):string() ~= "ZBXD" then
        -- there is no ZBXD signature
        -- maybe this is encrypted, or not Zabbix after all
        -- print("No ZBXD header")
        return 0
    end
    -- get the flags
    -- "0x01 - Zabbix communications protocol, 0x02 - compression, 0x04 - large packet" (as of 7/2022)
    local flags = buffer(4,1):uint()
    if not band(flags, FLAG_ZABBIX_COMMUNICATIONS) then
        -- the 0x01 flag is not set so let's stop
        return 0
    end
    local ZBXD_HEADER_LEN
    local IS_LARGE_PACKET
    if band(flags, FLAG_LARGE_PACKET) then
        IS_LARGE_PACKET = true
        -- the length fields are now 8 bytes instead of 4 bytes
        ZBXD_HEADER_LEN = 21
    else
        IS_LARGE_PACKET = false
        ZBXD_HEADER_LEN = 13
    end

    -- set Protocol column manually to get it in mixed case instead of all caps
    pktinfo.cols.protocol = PROTOCOL_NAME

    -- set the default text for Info column, it will be overridden later if possible
    if default_settings.info_text then
        pktinfo.cols.info = "Zabbix data"
    end

    local data_length
    if IS_LARGE_PACKET then
        data_length = buffer(5,8):le_uint()
    else
        data_length = buffer(5,4):le_uint()
    end

    local bytes_needed = ZBXD_HEADER_LEN + data_length
    if bytes_needed > pktlength and default_settings.reassemble then
        -- we need more bytes than is in the current segment, try to get more
        pktinfo.desegment_offset = 0
        pktinfo.desegment_len = data_length + ZBXD_HEADER_LEN - pktlength
        -- dissect anyway to show something if the TCP setting "Allow subdissector to
        -- reassemble TCP streams" is disabled
        doDissect(buffer, pktinfo, tree)
        -- set helpful text in Info column before returning
        pktinfo.cols.info = "[Partial Zabbix data, enable TCP subdissector reassembly]"
        return
    end

    -- now we have the data to dissect, let's do it
    doDissect(buffer, pktinfo, tree)
end


function zabbix_protocol.init()
    -- clear the tables
    timestamps = {}
    agent_names = {}
    proxy_names = {}
    senders = {}
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

zabbix_protocol.prefs.text = Pref.statictext("This dissector is written in Lua by Markku Leiniö. Version: " .. plugin_info.version, "")


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
