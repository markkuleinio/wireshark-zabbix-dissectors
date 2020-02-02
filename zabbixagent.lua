
zabbixagent_protocol = Proto("ZabbixAgent", "Zabbix Agent Protocol")

p_header = ProtoField.string("zabbixagent.header", "Header", base.ASCII)
p_version = ProtoField.uint8("zabbixagent.version", "Version", base.DEC)
p_data_length = ProtoField.uint32("zabbixagent.len", "Length", base.DEC)
p_reserved = ProtoField.uint32("zabbixagent.reserved", "Reserved", base.DEC)
p_data = ProtoField.string("zabbixagent.data", "Data", base.ASCII)

zabbixagent_protocol.fields = { p_header, p_version, p_data_length, p_reserved, p_data }

local default_settings =
{
    debug_level = DEBUG,
    ports = "10050",   -- the default TCP port for Zabbix
    reassemble = true, -- whether we try reassembly or not
    info_text = true,  -- show our own Info column data instead of TCP defaults
    ports_in_info = true, -- show TCP ports in Info column
}


function doDissect(buffer, pktinfo, tree)
    -- dissect the actual data from the tvb buffer

    -- get the data length and reserved fields (32-bit little-endian unsigned integers)
    local data_length = buffer(5,4):le_uint()
    local reserved = buffer(9,4):le_uint()

    local LEN = "Len: " .. data_length
    local LEN_AND_PORTS = "Len=" .. data_length
    if default_settings.ports_in_info then
        LEN_AND_PORTS = LEN_AND_PORTS .. " (" .. pktinfo.src_port .. " → " .. pktinfo.dst_port .. ")"
    end

    local tree_text = "Zabbix Passive Agent, " .. LEN
    local info_text = "Zabbix Passive Agent, " .. LEN_AND_PORTS
    if pktinfo.dst_port == tonumber(default_settings.ports) then
        -- this is from server to passive agent
        -- note: only matches if there is a single TCP port in the Ports setting
        tree_text = "Zabbix Passive Agent Request, " .. LEN
        info_text = "Zabbix Passive Agent Request, " .. LEN_AND_PORTS
    elseif pktinfo.src_port == tonumber(default_settings.ports) then
        -- this is from passive agent to server
        -- note: only matches if there is a single TCP port in the Ports setting
        tree_text = "Zabbix Passive Agent Response, " .. LEN
        info_text = "Zabbix Passive Agent Response, " .. LEN_AND_PORTS
    end

    local subtree = tree:add(zabbixagent_protocol, buffer(), tree_text)
    subtree:add_le(p_header, buffer(0,4))
    subtree:add_le(p_version, buffer(4,1))
    subtree:add_le(p_data_length, buffer(5,4))
    subtree:add_le(p_reserved, buffer(9,4))
    subtree:add_le(p_data, buffer(13))

    if default_settings.info_text then
        pktinfo.cols.info = info_text
    end
end


function zabbixagent_protocol.dissector(buffer, pktinfo, tree)

    local ZBXD_HEADER_LEN = 13
    local pktlength = buffer:len()

    if buffer(0,4):string() ~= "ZBXD" then
        -- there is no ZBXD signature
        -- maybe this is encrypted, or pre-4.0 agent protocol, or not Zabbix at all
        -- feel free to comment out the next "return 0" line to continue, then it will just continue parsing
        return 0
    end

    pktinfo.cols.protocol = "ZabbixAgent"

    if buffer(0,4):string() ~= "ZBXD" then
        -- no header, so this is an old-style (pre-4.0) server request or a continuation

        local PORTS = ""
        if default_settings.ports_in_info then
            PORTS = " (" .. pktinfo.src_port .. " → " .. pktinfo.dst_port .. ")"
        end
        -- set default text, then try to guess the direction
        local info_text = "Zabbix Passive Agent" .. PORTS
        if pktinfo.dst_port == tonumber(default_settings.ports) then
            -- this is from server to passive agent
            -- note: only matches if there is a single TCP port in the Ports setting
            info_text = "Zabbix Passive Agent Request" .. PORTS
        elseif pktinfo.src_port == tonumber(default_settings.ports) then
            -- this is from passive agent to server
            -- note: only matches if there is a single TCP port in the Ports setting
            info_text = "Zabbix Passive Agent Response" .. PORTS
        end
        if default_settings.info_text then
            pktinfo.cols.info = info_text
        end
        local subtree = tree:add(zabbixagent_protocol, buffer(), info_text)
        subtree:add(p_data, buffer(0))
        return pktlength
    else
        -- header was found, so this should be a Zabbix 4.0+ passive agent

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
    end

    -- now we have the data to dissect, let's do it

    doDissect(buffer, pktinfo, tree)

    return
end


local function enableDissector()
    DissectorTable.get("tcp.port"):add(default_settings.ports, zabbixagent_protocol)
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.ports, zabbixagent_protocol)
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
