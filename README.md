# Wireshark Websocket Deflate
Offers a LUA plugin for Wireshark that inflates compressed WebSocket payload as described in [RFC 7692](https://tools.ietf.org/html/rfc7692) based on ZLIB.
The plugin also implements the complete LZ77 sliding window - so context_takevoer is supported.
It currently won't work with websocket connections where a context takeover has been deactivated (see chapter 7.1.1. in the RFC).
The auto detection of the HTTP flags is subject to future work.

## Requirements
* The decompression is reusing lua_zlib library: [LUA_ZLIB](https://github.com/brimworks/lua-zlib)
* Currently it is tested only on Linux. It should however work on Windows as well given the correct LUA setup
* Wireshark 2.X (tested with 2.2.6 and 2.4.2 under Ubuntu)

## Features
* Supports DEFLATE Algorithm with LZ77 sliding window
* Supports multiple WebSocket connections wihtin a single Capture
* Supports TCP Re-Assambly 

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
 
 ## Customization
 The LUA script allows for 2 customization values, which should be adapted in case it does not work for you:
 1. As already mentioned the "MessagePrefix" variable, which is used for correct separation of the inflated websocket payload.
The default now is "}{", which should fit all JSON messages. For XML based messages it is most likely "><".
1. The "bucketSize". This value defines the CPU/Memory tradeoff, this plugin has to deal with. 
The plugin has to keep state of ALL messages per websocket connection - otherwise the deflate algorithm fails. 
The LZ77 window cannot be applied to the LUA script, as this breaks the inflation.
The bucketSize defines the number of messages after which the script stores a snapshot of the concatenated websocket payloads.
The lower the value is, the more memory Wireshark will need and the faster the script will execute. And of course vice versa.

CPU or Time / Memory Tradeoff Examples:
Test Example with Wireshark 2.4.2 on Ubuntu 16.04 with 2 cores (i5 4210U) and 10GB RAM.

| BucketSize                | Memory used by Wireshark  | Time needed for loading   |
| ------------------------- |:-------------------------:| -------------------------:|
| 1 = keep all in mem       | 2,4 GB                    | 0:38.212                  |
| 10                        | 490 MB                    | 0:41.412                  |
| 100                       | 210 MB                    | 1:4.249                   |
| 500                       | 190 MB                    | 3:10.221                  |
| No Buckets                | 175 MB                    | 16:0.586                  |

The default has been set to 10 for now and should be adopted depending on your specific needs (size of the captured packets).
The reason for the CPU focus being that slow is that the amount of time the script takes to process a new messages becomes expontially slower with every new message in case no buckets are used.
The same accounts for the BucketSize of 1 where the amount of RAM utilized is extremely high.

 ## License
 It is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.de.html) 
