
zabbixagent_protocol = Proto("ZabbixAgent", "Zabbix Agent Protocol")
-- for some reason the protocol name is shown in UPPERCASE in Protocol column
-- (and in Proto.name), so let's define a string to override that
local PROTOCOL_NAME = "ZabbixAgent"

p_header = ProtoField.string("zabbixagent.header", "Header", base.ASCII)
p_version = ProtoField.uint8("zabbixagent.version", "Version", base.HEX)
p_data_length = ProtoField.uint32("zabbixagent.len", "Length", base.DEC)
p_reserved = ProtoField.uint32("zabbixagent.reserved", "Reserved", base.DEC)
p_request = ProtoField.string("zabbixagent.request", "Requested item", base.ASCII)
p_response = ProtoField.string("zabbixagent.response", "Response", base.ASCII)

zabbixagent_protocol.fields = {
    p_header, p_version, p_data_length, p_reserved, p_request, p_response,
}

local default_settings =
{
    debug_level = DEBUG,
    ports = "10050",   -- the default TCP port for Zabbix
    reassemble = true, -- whether we try reassembly or not
    info_text = true,  -- show our own Info column data instead of TCP defaults
    ports_in_info = true, -- show TCP ports in Info column
}


function doDissect_pre40(buffer, pktinfo, tree)
    -- dissect a pre-4.0 passive request, no header
    local pktlength = buffer:len()
    pktinfo.cols.protocol = PROTOCOL_NAME
    local PORTS = ""
    if default_settings.ports_in_info then
        PORTS = " (" .. pktinfo.src_port .. " → " .. pktinfo.dst_port .. ")"
    end
    local info_text = "Zabbix Passive Agent Request" .. PORTS
    if default_settings.info_text then
        pktinfo.cols.info = info_text
    end
    local subtree = tree:add(zabbixagent_protocol, buffer(), info_text)
    -- don't include the newline in the field
    subtree:add(p_request, buffer(0,pktlength-1))
end


function doDissect(buffer, pktinfo, tree)
    -- dissect the packet, with ZBXD header
    pktinfo.cols.protocol = PROTOCOL_NAME
    -- get the data length and reserved fields (32-bit little-endian unsigned integers)
    local data_length = buffer(5,4):le_uint()
    local reserved = buffer(9,4):le_uint()
    local LEN = "Len: " .. data_length
    local LEN_AND_PORTS = "Len=" .. data_length
    if default_settings.ports_in_info then
        LEN_AND_PORTS = LEN_AND_PORTS .. " (" .. pktinfo.src_port .. " → " .. pktinfo.dst_port .. ")"
    end
    -- default texts, overridden later if we recognize the port
    local tree_text = "Zabbix Passive Agent, " .. LEN
    local info_text = "Zabbix Passive Agent, " .. LEN_AND_PORTS
    local is_request = false
    local is_response = false
    if pktinfo.dst_port == tonumber(default_settings.ports) then
        -- this is from server to passive agent
        -- note: only matches if there is a single TCP port in the Ports setting
        is_request = true
        tree_text = "Zabbix Passive Agent Request, " .. LEN
        info_text = "Zabbix Passive Agent Request, " .. LEN_AND_PORTS
    elseif pktinfo.src_port == tonumber(default_settings.ports) then
        -- this is from passive agent to server
        -- note: only matches if there is a single TCP port in the Ports setting
        is_response = true
        tree_text = "Zabbix Passive Agent Response, " .. LEN
        info_text = "Zabbix Passive Agent Response, " .. LEN_AND_PORTS
    end
    if default_settings.info_text then
        pktinfo.cols.info = info_text
    end
    local subtree = tree:add(zabbixagent_protocol, buffer(), tree_text)
    subtree:add_le(p_header, buffer(0,4))
    subtree:add_le(p_version, buffer(4,1))
    subtree:add_le(p_data_length, buffer(5,4))
    subtree:add_le(p_reserved, buffer(9,4))
    if is_request then
        subtree:add(p_request, buffer(13))
    elseif is_response then
        subtree:add(p_response, buffer(13))
    else
        subtree:add(buffer(13), "(Request or response, port was not matched)")
    end
end


function zabbixagent_protocol.dissector(buffer, pktinfo, tree)
    local ZBXD_HEADER_LEN = 13
    local pktlength = buffer:len()
    if pktlength < 4 or buffer(0,4):string() ~= "ZBXD" then
        -- no ZBXD signature, so this is an old-style (pre-4.0) server request or a continuation,
        -- or maybe this is encrypted, or not Zabbix at all
        -- pattern should match the allowed Zabbix item key format, like eth.port[123], with
        -- a newline at the end
        local pattern = "^[%w-_.,%[%]\"/]+\n$"
        if not string.match(buffer(0):string(), pattern) then
            -- does not look like a valid pre-4.0 passive request, just return 0 to allow
            -- other dissectors to continue
            return 0
        end
        -- otherwise do the dissect with no header present
        doDissect_pre40(buffer, pktinfo, tree)
    else
        -- header was found, so this should be a Zabbix 4.0+ passive agent or
        -- a response from pre-4.0 agent

        -- get the Zabbix data length (32-bit LE integer)
        local data_length = buffer(5,4):le_uint()

        local bytes_needed = ZBXD_HEADER_LEN + data_length
        if bytes_needed > pktlength and default_settings.reassemble then
            -- we need more bytes than is in the current segment, try to get more
            pktinfo.desegment_offset = 0
            pktinfo.desegment_len = data_length + ZBXD_HEADER_LEN - pktlength
            -- dissect anyway to show something if the TCP setting "Allow subdissector to
            -- reassemble TCP streams" is disabled
            doDissect(buffer, pktinfo, tree)
            return
        end
        -- now we have the data to dissect, let's do it
        doDissect(buffer, pktinfo, tree)
    end
    return
end


local function enableDissector()
    DissectorTable.get("tcp.port"):add(default_settings.ports, zabbixagent_protocol)
    -- supports also TLS decryption if the session keys are configured in Wireshark
    DissectorTable.get("tls.port"):add(default_settings.ports, zabbixagent_protocol)
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.ports, zabbixagent_protocol)
    DissectorTable.get("tls.port"):remove(default_settings.ports, zabbixagent_protocol)
end

-- register our preferences
zabbixagent_protocol.prefs.reassemble = Pref.bool("Reassemble Zabbix Agent messages spanning multiple TCP segments",
    default_settings.reassemble, "Whether the Zabbix Agent dissector should reassemble messages " ..
    "spanning multiple TCP segments. To use this option, you must also enable \"Allow subdissectors to " ..
    "reassemble TCP streams\" in the TCP protocol settings")

zabbixagent_protocol.prefs.info_text = Pref.bool("Show Zabbix protocol data in Info column",
    default_settings.info_text, "Disable this to show the default TCP protocol data in the Info column")

zabbixagent_protocol.prefs.ports_in_info = Pref.bool("Show TCP ports in Info column",
    default_settings.ports_in_info, "Disable this to have only Zabbix data in the Info column")

zabbixagent_protocol.prefs.ports = Pref.range("Port(s)", default_settings.ports,
    "Set the TCP port(s) for Zabbix Agent, default is 10050", 65535)

zabbixagent_protocol.prefs.text = Pref.statictext("This dissector is written in Lua.","")


-- the function for handling preferences being changed
function zabbixagent_protocol.prefs_changed()
    if default_settings.reassemble ~= zabbixagent_protocol.prefs.reassemble then
        default_settings.reassemble = zabbixagent_protocol.prefs.reassemble
        -- capture file reload needed
        reload()
    elseif default_settings.info_text ~= zabbixagent_protocol.prefs.info_text then
        default_settings.info_text = zabbixagent_protocol.prefs.info_text
        -- capture file reload needed
        reload()
    elseif default_settings.ports_in_info ~= zabbixagent_protocol.prefs.ports_in_info then
        default_settings.ports_in_info = zabbixagent_protocol.prefs.ports_in_info
        -- capture file reload needed
        reload()
    elseif default_settings.ports ~= zabbixagent_protocol.prefs.ports then
        disableDissector()
        default_settings.ports = zabbixagent_protocol.prefs.ports
        enableDissector()
    end
end
