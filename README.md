# wireshark-zabbix-dissectors

Experimental Wireshark dissectors for Zabbix protocol.

Tested with Zabbix 4.0.0.

Use at your own risk.

# Install instructions for Wireshark on Windows (64-bit)

1. Go to %APPDATA%\Wireshark folder
2. Create "plugins" folder if it does not exist yet, and go there
3. Create a "2.6" folder if it does not exist yet (for Wireshark version 2.6.x; for other versions, change the number accordingly)
4. Copy the .lua file(s) there
5. If Wireshark is already running, use Analyze - Reload Lua Plugins (Ctrl-Shift-L) to load the plugin(s)
