--[[
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

--[[
	Copyright (C) 2017 stefanLeo - All Rights Reserved
	You may use, distribute and modify this code under the
	terms of the GNU General Public License v3, which unfortunately won't be
	written for another century.
	You should have received a copy of the GNU General Public License v3 license with
	this file. If not, please visit :
	Github: https://github.com/stefanLeo/wireshark_websocket_deflate
--]]

zlib = require "zlib"
pktState = {}
pktNoArray = {}
zlibPrefixLowCompression = "\x78\x01"
zlibBestCompression =  "\x78\xDA"
--Zlib Default Compression
zlibPrefix = "\x78\x9C"
-- As required by RFC7692
deflatePostfix = "\x00\x00\xff\xff"
-- THIS NEEDS TO BE CHANGED PER USE-CASE!! SHOULD WORK FOR MOST JSON USE-CASES
messagePrefix = "}{"

tcp_stream = Field.new("tcp.stream")
websocket_payld = Field.new("websocket.payload")

socketio_proto = Proto("socketio", "WebSocket permessage-deflate postdissector")
type_F = ProtoField.string("socketio.type", "Text")
socketio_proto.fields = {type_F}

local streams

function socketio_proto.init()
	streams = {}
	pktState = {}
	pktNoArray = {}
	messagePrefix = messagePrefix:reverse()
end

-- create a function to "postdissect" each frame
function socketio_proto.dissector(buffer, pinfo, tree)
    -- obtain the current values the protocol fields
    local websocket_payload = websocket_payld()
            
    -- get the paket number from wireshark UI
    local pktNo = pinfo.number

    if websocket_payload then
	local data = tostring(websocket_payload.range:bytes():raw())
	
	-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	--     keep state for LZ77 window
	-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	local srcSocket = tostring(pinfo.src)..":"
	srcSocket = srcSocket..pinfo.src_port        

	--message("srcsocket: "..srcSocket)
	local currentStream = pktState[srcSocket]	
	local currentPaket  = nil
	
	-- Keeping pkt state	
	if currentStream ~= nil then
	    -- stream already processed
	    currentPaket = currentStream[pktNo]
	    if currentPaket == nil then
		-- add new paket to current stream
	    	currentStream[pktNo] = data
		-- message("Added new packet to existing stream")
		table.insert(pktNoArray[srcSocket], pktNo)
	    end
    	else
	    -- stream not yet processed - create it
	    local pktArray  = {}
	    pktArray[pktNo] = data
	    pktState[srcSocket] = pktArray
	    currentStream = pktState[srcSocket]
	    pktNoArray[srcSocket] = {pktNo}
	    -- message("Created new stream with initial packet")
    	end	
   
	-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	--       build decompression data
	-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
     	local inflated = "PARSING_ERROR"
	local deflatedStream = zlibPrefix
	
	-- build up the complete packet history of the current channel	
	for i, pktID in ipairs(pktNoArray[srcSocket]) do
		if pktID <= pktNo then		
			deflatedStream = deflatedStream..currentStream[pktID]
			deflatedStream = deflatedStream..deflatePostfix	
		end			
	end
	
	-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	--       start decompression
	-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	if deflatedStream ~= zlibPrefix then
		local inflateStream = zlib.inflate()
		inflated = inflateStream(deflatedStream)

		-- Filter out just the last message by the common message prefix	
		local reverseInflated = inflated:reverse()
		local index = reverseInflated:find(messagePrefix)
		
		if index ~= nil then	
			message("INDEX="..index)
			local length = inflated:len()
			index = length-index+1
			inflated = string.sub(inflated, index)
		end
	end
        
	local subtree = tree:add(socketio_proto, "Inflated payload")
        subtree:add(type_F, inflated)
    end
end

register_postdissector(socketio_proto)
