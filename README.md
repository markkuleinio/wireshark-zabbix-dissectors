# wireshark-zabbix-dissectors

Experimental Wireshark dissectors for Zabbix protocol.

Tested with Zabbix 4.0.0 and 4.0.9 with Wireshark 2.6.x and 3.0.2.

Use at your own risk.

## Install instructions for Wireshark on Windows (64-bit)

1. Go to `%APPDATA%\Wireshark` folder
2. Create "plugins" folder if it does not exist yet, and go there
3. Create a "3.0" folder if it does not exist yet (for Wireshark version 3.0.x; for other versions, change the number accordingly)
4. Copy the .lua files there
5. If Wireshark is already running, use **Analyze - Reload Lua Plugins** (Ctrl-Shift-L)
