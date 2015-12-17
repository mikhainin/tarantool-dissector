
local msgpack = require 'MessagePack'

-- declare the protocol
tarantool_proto = Proto("tarantool","Tarantool")
--[[
local tnt_field_sync = ProtoField.new('tnt.sync', 'tnt.sync', ftypes.UINT32)

tarantool_proto.fields = {
    tnt_field_sync
}
]]

function binary_string(buffer)
	result = {}
	for i=0,buffer:len() - 1 do
		table.insert(result, string.char(buffer(i, 1):le_uint()))
	end
	return table.concat(result, '')
end


local function map(tbl, callback)
    local result = {}
    for k,v in pairs(tbl) do
        result[k] = callback(v)
    end
    return result
end

local function table_kv_concat(tbl, sep)
    local result = {}
    local used_keys = {}
    for i, v in ipairs(tbl) do
        used_keys[i] = true
        table.insert(result, v)
    end
    for k, v in pairs(tbl) do
        if not used_keys[i] then
            table.insert(result, k .. ' = ' .. v)
        end
    end
    return table.concat(result, sep)
end

local function escape_call_arg(a)
    if type(a) == 'number' then
        return a
    elseif type(a) == 'string' then
        return '"' .. a .. '"'
    elseif type(a) == 'table' then
        return '{' .. table_kv_concat(map(a, escape_call_arg), ', ') .. '}'
    else
        return a
    end
end

local function parse_call(tbl, buffer, subtree)
    local name = tbl[0x22]
    local tuple = tbl[0x21]
    
    local argument_string = table.concat(map(tuple, escape_call_arg), ', ')
    
    local descr = string.format('%s(%s)', name, argument_string)
    subtree:add(buffer, descr)
end

-- TODO: why do we need "tuple" in `eval' command?
local function parse_eval(tbl, buffer, subtree)
    local expression = tbl[0x27]
    local tuple = tbl[0x21]
    
    local argument_string = table.concat(map(tuple, escape_call_arg), ', ')

    local descr = string.format('%s(%s)', name, argument_string)
    subtree:add(buffer, descr)
end

local function parse_select(tbl, buffer, subtree)
    local space_id = tbl[0x10] -- int
    local index_id = tbl[0x11] -- int
    local limit    = tbl[0x12] -- int
    local offset   = tbl[0x13] -- int
    local iterator = tbl[0x14] -- int
    local key      = tbl[0x14] -- array
    
    local argument_string = table.concat(map(key, escape_call_arg), ', ')
    
    local descr = string.format('SELECT FROM space %d %s(%s) WHERE index(%d)', name, argument_string)
    subtree:add(buffer, descr)
end


local function response(tbl, buffer, subtree)
    local data = tbl[0x30]
    if not data then
        subtree:add(buffer, '(empty response body)')
    else
        local value = map(data, escape_call_arg)
        local arguments_tree = subtree:add(buffer, 'tuple')
        for k, v in pairs(value) do
            arguments_tree:add(buffer, v)
        end
    end
    
end

function parser_not_implemented(tbl, buffer, subtree)
	subtree:add(buffer, 'parser not yet implemented (or unknown packet?)')
end

function code_to_command(code)

	local codes = {
		[0x01] = {name = 'select', decoder = parser_not_implemented},
		[0x02] = {name = 'insert', decoder = parser_not_implemented},
		[0x03] = {name = 'replace', decoder = parser_not_implemented},
		[0x04] = {name = 'update', decoder = parser_not_implemented},
		[0x05] = {name = 'delete', decoder = parser_not_implemented},
		[0x06] = {name = 'call', decoder = parse_call},
		[0x07] = {name = 'auth', decoder = parser_not_implemented},
		[0x08] = {name = 'eval', decoder = parse_eval},
		[0x09] = {name = 'upsert', decoder = parser_not_implemented},
		
		-- Admin command codes
		[0x40] = {name = 'ping', decoder = parser_not_implemented},
		
		-- Value for <code> key in response can be:
		[0x00]   = {name = 'OK', is_response = true},
		--[0x8XXX] = {name = 'ERROR', is_response = true},
	};
	if code >= 0x8000 then
		return {name = 'ERROR', is_response = true}
	end

	local unknown_code = {name = 'UNKNOWN'}
	
	return (codes[code] or unknown_code)
end


-- create a function to dissect it
function tarantool_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Tarantool"

    if buffer(0, 9):string() == "Tarantool" then
        pinfo.cols.info = 'Greeting packet. ' .. tostring(pinfo.cols.info)
        
        local subtree = tree:add(tarantool_proto, buffer(),"Tarantool greeting packet")
        subtree:add(buffer(0, 64), "Server version: " .. buffer(0, 64):string())
        subtree:add(buffer(64, 44), "Salt" .. buffer(64, 44):string())
        subtree:add(buffer(108), "Reserved")
        return buffer(0, 9):len()
    end
    
	local packet_length = msgpack.unpack(binary_string(buffer(0,5)))
	request_length = packet_length + 5
	
	-- TODO: check bytes available
	
    if (buffer:len() < request_length) then
        -- debug('reassemble required: ' .. (request_length - buffer:len()) )
        pinfo.desegment_len = request_length - buffer:len()
        pinfo.desegment_offset = 0
        return 0
    end

	local packet_buffer = buffer(5)
	local header_data, bytes_used = msgpack.unpack(binary_string(packet_buffer))
	
	local command = code_to_command(header_data[0])
	
    local body_buffer = packet_buffer(bytes_used)


	if not command.is_response then
	    local subtree = tree:add(tarantool_proto, buffer(),"Tarantool protocol data")
	    -- subtree:add(tnt_field_sync, header_data[0x01])
	    local header_descr = string.format('code: 0x%02x (%s), sync: 0x%04x', header_data[0x00], command.name, header_data[0x01])
		subtree:add(packet_buffer(0, bytes_used), header_descr)
		
        local body_data, bytes_used = msgpack.unpack(binary_string(body_buffer))
        
        local decoder = command.decoder or parser_not_implemented
        
        decoder(body_data, body_buffer, subtree)
        
        pinfo.cols.info = command.name .. ' request. ' .. tostring(pinfo.cols.info)
        --[[print(body_data, bytes_used)
        for k,v in pairs(body_data) do
        	print(k,v)
        end]]
        -- subtree:add( buffer(0,4),"Request Type: " .. buffer(0,4):le_uint() .. ' ' .. requestName(buffer(0,4):le_uint()) )
        --        request(buffer, subtree)
	else
        local subtree = tree:add(tarantool_proto,buffer(),"Tarantool protocol data (response)")
	    local header_descr = string.format('code: 0x%02x (%s), sync: 0x%04x', header_data[0], command.name, header_data[1])
		subtree:add(packet_buffer(0, bytes_used), header_descr)
        local body_data, bytes_used = msgpack.unpack(binary_string(packet_buffer(bytes_used)))
        response(body_data, body_buffer, subtree)
        pinfo.cols.info = 'response. ' .. tostring(pinfo.cols.info)
	end
    
    return request_length
    
end

-- load the udp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 14888
-- tcp_table:add(14888,tarantool_proto)
tcp_table:add(3301,tarantool_proto)

