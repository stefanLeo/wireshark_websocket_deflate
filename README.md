# Wireshark Websocket Deflate
Offers a LUA plugin for Wireshark that inflates compressed WebSocket payload as described in [RFC 7692](https://tools.ietf.org/html/rfc7692) based on ZLIB.
The plugin also implements the complete LZ77 sliding window - so context_takevoer is supported.
It currently won't work with websocket connections where a context takeover has been deactivated (see chapter 7.1.1. in the RFC).
The auto detection of the HTTP flags is subject to future work.

## Requirements
* The decompression is reusing lua_zlib library: [LUA_ZLIB](https://github.com/brimworks/lua-zlib)
* Currently it is tested only on Linux. It should however work on Windows as well given the correct LUA setup
* Wireshark 2.X 

## Installation & Setup on Linux (Ubuntu)
1. Install Wirshark
    sudo apt-get install wireshark
1. Install LUA & Setup LUA_ZLIB  
  Install GIT:  
    ```sudo apt-get install git```  
   Install LUA:  
    ```sudo apt-get install lua5.2-dev```  
   Setup with [LUA_ROCKS](https://luarocks.org/) and add lua_zlib:  
    ```wget https://luarocks.org/releases/luarocks-2.4.2.tar.gz
    tar tar zxpf luarocks-2.4.2.tar.gz
    cd luarocks-2.4.2
    ./configure; 
    sudo make bootstrap
    sudo luarocks install lua_zlib
    ```  
   Verify success:  
   Type in lua in commant line and the try 
    ```require "zlib"```
1. Copy the LUA plugin into the Wireshark Plugins directory  
   The Wireshark plugin directory ca be found by clicking "Help/About Wireshark".  
   In the open pop-up window select plugins and select a path similar to "usr/lib/x86../wireshark/plugins/2.2.6"  
1. Adapt the MessagePrefix variable at the top of the script.
   This part is used to separate the messages sent, which is needed in order to only show the last message per websocket stream due to the LZ77 window.
   The default value is "}{", which should fit for most JSON messages out of the box.
      
 ## License
 It is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.de.html) 
