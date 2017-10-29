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

--[[
	PLS. CUSTOMIZE THE BUCKETSIZE AND/OR THE MESSAGEPREFXIX 
	in case the script does NOT what you expect.
--]]

zlib = require "zlib"
pktState = {}
httpStart = {}
pktNoArray = {}
zlibPrefixLowCompression = "\x78\x01"
zlibBestCompression =  "\x78\xDA"
--Zlib Default Compression
zlibPrefix = "\x78\x9C"
-- As required by RFC7692
deflatePostfix = "\x00\x00\xff\xff"
deflatedText = {}
--sumTime = 0

-- THIS NEEDS TO BE CHANGED PER USE-CASE!! SHOULD WORK FOR MOST JSON USE-CASES
messagePrefix = "}{"
bucketSize = 10

-- REGISTER FOR WEBSOCKET PAYLOAD
websocket_payld = Field.new("websocket.payload")
http_get = Field.new("http.sec_websocket_key")

socketio_proto = Proto("socketio", "WebSocket permessage-deflate postdissector")
type_F = ProtoField.string("socketio.type", "Text")
socketio_proto.fields = {type_F}

local streams

function socketio_proto.init()
	streams = {}
	pktState = {}
	httpStart = {}
	pktNoArray = {}
	deflatedText = {}
	messagePrefix = messagePrefix:reverse()
--	sumTime = 0
end

-- create a function to "postdissect" each frame
function socketio_proto.dissector(buffer, pinfo, tree)
    
	-- obtain the current values the protocol fields
	-- TCP REASSAMBLY is handled via a table as return value for websocket payload
    local websocket_payload_table = {websocket_payld()}
	local httpWebSocketHeader = http_get()
	
    local srcSocket = tostring(pinfo.src)..":"
	local dstSocket = tostring(pinfo.dst)..":"
	srcSocket = srcSocket..pinfo.src_port   	
	dstSocket = dstSocket..pinfo.dst_port   		
	
	local srcPktNoList = httpStart[srcSocket]
	local dstPktNoList = httpStart[dstSocket]
	
	local pktNo = pinfo.number
	
	-- iterate over the TCP reassambly packets
	for counter, websocket_payload in ipairs(websocket_payload_table) do
		if websocket_payload and srcPktNoList then
			--local startTime = os.clock()
			-- get the paket number from wireshark UI + add counter for tcp reassambly handling
			local pktNoCounter = tonumber(pktNo..counter)
			local data = tostring(websocket_payload.range:bytes():raw())
			
			-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
			--     Get the start packet for the http upgrade 
			--     This is needed if the same client (socket) connects multiple times in the same capture
			--     New connection = new LZ77 sliding window
			-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX     

			local upgradePktNo = nil 
			for index, value in ipairs(srcPktNoList) do
					if value < pktNo  then
						upgradePktNo = value
					else
						break
					end
			end
			--message(string.format("PktNo %s: My http upgrade paketNumber was %s", pktNo, upgradePktNo))
			
			packetKey = upgradePktNo..srcSocket
			--message("packetKey: "..packetKey)
			
			
			-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
			--     keep state for LZ77 window
			-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX		     
			local currentStream = pktState[packetKey]	
			local currentPaket  = nil
			
			-- Keeping pkt state	
			if currentStream ~= nil then
				-- stream already processed
				currentPaket = currentStream[pktNoCounter]
				if currentPaket == nil then
					-- add new paket to current stream
					currentStream[pktNoCounter] = data
					-- message("Added new packet to existing stream")
					table.insert(pktNoArray[packetKey], pktNoCounter)
				end
			else
				-- stream not yet processed - create it
				local pktArray  = {}
				pktArray[pktNoCounter] = data
				pktState[packetKey] = pktArray
				deflatedText[packetKey] = {}
				currentStream = pktState[packetKey]
				pktNoArray[packetKey] = {pktNoCounter}
				-- message("Created new stream with initial packet")
			end	
		   
			-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
			--       build decompression data
			-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
			local inflatedFinal = "PARSING_ERROR"
			local deflatedStream = zlibPrefix
			
			local srcDeflatedText = deflatedText[packetKey]
			if srcDeflatedText ~= nil then
				if srcDeflatedText[pktNoCounter] ~= nil then
					deflatedStream = deflatedText[packetKey][pktNoCounter]
				else
					local prevPktNo = 0
					local pktCount = 0
					for i, pktID in ipairs(pktNoArray[packetKey]) do
						pktCount = i
						if pktID < pktNoCounter then
							prevPktNo = pktID
						else
							break
						end
					end
					
					-- CALCULATE THE BUCKETS HERE 
					local moduloResult = pktCount % bucketSize
					local bucketValue = pktCount - moduloResult
					if bucketValue < 0 then
						bucketValue = bucketValue + bucketSize
					end
					
					if prevPktNo ~= 0 then
						--message(string.format("START DEF - key %s packet %s moduloResult %s bucketValue %s", packetKey, pktNo, moduloResult, bucketValue));
						-- Take already stored assembled packages of this stream
						if bucketValue > 0 and moduloResult ~= 0 then
							-- No bucket size values (module !=0)
							deflatedStream = srcDeflatedText[bucketValue]
							--message(string.format("DEFLATEDSTREAM for value %s SET to %s", bucketValue, deflatedStream))
						else if bucketValue > 0 and moduloResult == 0 and bucketValue ~= bucketSize then
							-- In case this is a multiple of the bucketsize, but not the initial bucket, take i.e. value stored at 10 for bucketValue 20.
							deflatedStream = srcDeflatedText[bucketValue-bucketSize]
							--message(string.format("DEFLATEDSTREAM for value %s SET to %s", bucketValue, deflatedStream))
						end
						end
						-- work with buckets here...
						for i, pktID in ipairs(pktNoArray[packetKey]) do 
							if pktID <= pktNoCounter then
								if (moduloResult ~= 0 and i > bucketValue) or (moduloResult == 0 and i > bucketValue-bucketSize) then
									--message(string.format("DEFLATING - packet %s i=%s bucketValue=%s", pktNo, i ,bucketValue));
									deflatedStream = deflatedStream..currentStream[pktID]
									deflatedStream = deflatedStream..deflatePostfix
								end
							else
							    break
							end
						end 
					else
						-- first package in this stream
						deflatedStream = zlibPrefix..data
						deflatedStream = deflatedStream..deflatePostfix
					end
					-- STORE THE BUCKET HERE IF IT IS A BUCKET VALUE (i.e. 10, 20, 30, ...)
					if moduloResult == 0 and srcDeflatedText[bucketValue] == nil  then
						--message(string.format("STORING BUCKET - key %s packet %s bucketValue %s stream %s", packetKey, pktNo, bucketValue, deflatedStream));
						srcDeflatedText[bucketValue] = deflatedStream
					end
				end
			end 	
			
			-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
			--       start decompression
			-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
			if deflatedStream ~= zlibPrefix then
				local inflateStream = zlib.inflate()
				local inflated = inflateStream(deflatedStream)

				-- Filter out just the last message by the common message prefix	
				local reverseInflated = inflated:reverse()
				local index = reverseInflated:find(messagePrefix)
				
				if index ~= nil then	
					-- message("INDEX="..index)
					local length = inflated:len()
					index = length-index+1
					inflatedFinal = string.sub(inflated, index)
				else 
					inflatedFinal = inflated
				end
			end
				
			local subtree = tree:add(socketio_proto, "Inflated payload")
			subtree:add(type_F, inflatedFinal)
			
			--sumTime = sumTime + (os.clock() - startTime)
			--message(string.format("elapsed time: %.9f\n",sumTime))
		end
	end

	
	-- WEBSOCKET HTTP UPGRADE PARSING - DST/SRC is needed for both directions!
	-- TODO: Make more readable/maintainable by making this a LUA function...
	if httpWebSocketHeader then
		--message("WEBSOCKET HTTP START HEADER DETECTED")
		-- This is an HTTP GET websocket upgrade request --
		if srcPktNoList ~= nil then
			-- add pktNo to the end if not already contained
			local alreadyAdded = false
			for index, value in ipairs(srcPktNoList) do
				if value == pktNo then
					alreadyAdded = true
					break
				end
			end
			--message (string.format("already added %s %s %s", alreadyAdded, pktNo, srcSocket))
			if alreadyAdded == false then
				--message (string.format("Adding pkt %s to srcsocket %s", pktNo, srcSocket))
				table.insert(httpStart[srcSocket], pktNo)
			end
		else
			-- create new entry with pktNo
			--message (string.format("Adding first pkt %s to srcsocket %s", pktNo, srcSocket))
			httpStart[srcSocket] = {pktNo}
		end
		if dstPktNoList ~= nil then
			-- add pktNo to the end if not already contained
			local alreadyAdded = false
			for index, value in ipairs(dstPktNoList) do
				if value == pktNo then
					alreadyAdded = true
					break
				end
			end
			--message (string.format("already added %s %s %s", alreadyAdded, pktNo, dstSocket))
			if alreadyAdded == false then
				--message (string.format("Adding pkt %s to dstsocket %s", pktNo, dstSocket))
				table.insert(httpStart[dstSocket], pktNo)
			end
		else
			-- create new entry with pktNo
			--message (string.format("Adding first pkt %s to dstsocket %s", pktNo, dstSocket))
			httpStart[dstSocket] = {pktNo}
		end
	end
end

register_postdissector(socketio_proto)
