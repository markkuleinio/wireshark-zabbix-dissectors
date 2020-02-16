# wireshark-zabbix-dissectors

Experimental Wireshark dissectors for Zabbix protocol.

Tested with various versions:
- Zabbix 4.0.0, 4.0.9, 4.0.14, 4.4.4
- Wireshark (on 64-bit Windows) 2.6.x, 3.0.2, 3.2.1
- (not in all combinations but to give you an idea)

Use at your own risk.

## Install instructions for Wireshark on Windows (64-bit)

1. Go to `%APPDATA%\Wireshark` folder
1. Create `plugins` folder if it does not exist yet, and go there
1. Copy the `.lua` files there (alternatively you can also create a subfolder and
place the files there, or clone this repo under the `plugins` folder)
1. If Wireshark is already running, use **Analyze - Reload Lua Plugins** (Ctrl-Shift-L)
1. Enable TCP setting **Allow subdissector to reassemble TCP streams**
to give you correct output when requests/responses do not fit in one
IP packet
1. Edit Zabbix protocol preferences as needed (in **Preferences - Protocols**, or
by right-clicking in Zabbix/ZabbixAgent packets in capture window)

## Filtering hints

- Passive agent connections don't offer much information for filtering, just use
agent IP address if filtering on the server/proxy side
- Use `zabbix.agent.checks == 1` to show the active agents requesting for items
to check for
- Use `zabbix.agent.data == 1` to show the active agents sending data to Zabbix server/proxy
- Try `zabbix.agent.name`
- `zabbix.datalen` always returns the uncompressed length, regardless of
compression in use or not

See the Zabbix protocol tree in captured packets to see other fields that are
available for filtering.

## Limitations

- Code assumes "compact" form of JSON (no extra spaces or line feeds)
- Not all Zabbix component combinations have been tested or implemented
- Cannot dissect TLS-encypted Zabbix communication

## Links to relevant Zabbix documentation

- https://www.zabbix.com/documentation/current/manual/appendix/items/activepassive
- https://www.zabbix.com/documentation/current/manual/appendix/protocols/header_datalen
- https://www.zabbix.com/documentation/current/manual/appendix/protocols/server_proxy
