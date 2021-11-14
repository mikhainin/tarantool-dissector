
local msgpack = require 'MessagePack'

-- constants
-- common
local GREETING_SIZE          = 128
local GREETING_SALT_OFFSET   = 64
local GREETING_SALT_SIZE     = 44

-- packet codes
local OK         = 0x00
local SELECT     = 0x01
local INSERT     = 0x02
local REPLACE    = 0x03
local UPDATE     = 0x04
local DELETE     = 0x05
local CALL       = 0x06
local AUTH       = 0x07
local EVAL       = 0x08
local UPSERT     = 0x09
local PING       = 0x40

-- packet keys
local TYPE          = 0x00
local SYNC          = 0x01
local SPACE_ID      = 0x10
local INDEX_ID      = 0x11
local LIMIT         = 0x12
local OFFSET        = 0x13
local ITERATOR      = 0x14
local KEY           = 0x20
local TUPLE         = 0x21
local FUNCTION_NAME = 0x22
local USER_NAME     = 0x23
local EXPRESSION    = 0x27
local DATA          = 0x30
local ERROR         = 0x31

-- declare the protocol
tarantool_proto = Proto("tarantool","Tarantool")
--[[
local tnt_field_sync = ProtoField.new('tnt.sync', 'tnt.sync', ftypes.UINT32)

tarantool_proto.fields = {
    tnt_field_sync
}
]]

-- extracts bytes from the buffer
function binary_string(buffer)
    local result = {}
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
        if not used_keys[k] then
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
    local name = tbl[FUNCTION_NAME]
    local tuple = tbl[TUPLE]

    local argument_string = table.concat(map(tuple, escape_call_arg), ', ')

    local descr = string.format('%s(%s)', name, argument_string)
    subtree:add(buffer, descr)
end

-- TODO: why do we need "tuple" in `eval' command?
local function parse_eval(tbl, buffer, subtree)
    local expression = tbl[EXPRESSION]
    local tuple = tbl[TUPLE]

    local argument_string = table.concat(map(tuple, escape_call_arg), ', ')

    local descr = string.format('%s(%s)', name, argument_string)
    subtree:add(buffer, descr)
end

local function parse_select(tbl, buffer, subtree)
    local space_id = tbl[SPACE_ID] -- int
    local index_id = tbl[INDEX_ID] -- int
    local limit    = tbl[LIMIT]    -- int
    local offset   = tbl[OFFSET]   -- int
    local iterator = tbl[ITERATOR] -- int
    local key      = tbl[KEY]      -- array

    local key_string = table.concat(map(key, escape_call_arg), ', ')

    local descr = string.format(
        'SELECT FROM space %d WHERE index(%d) = (%s) LIMIT %d OFFSET %d ITERATOR %s',
        space_id,
        index_id,
        key_string,
        limit,
        offset,
        iterator or ('null')
    )
    subtree:add(buffer, descr)
end

local function parse_insert(tbl, buffer, subtree)
    local tuple    = tbl[TUPLE]
    local space_id = tbl[SPACE_ID]

    subtree:add(buffer, 'space_id: ' .. space_id)
    local tuple_tree = subtree:add(buffer, 'tuple')
    local tuple_str = table.concat(map(tuple, escape_call_arg), ', ')

    tuple_tree:add(buffer, tuple_str)
end

local function parse_delete(tbl, buffer, subtree)
    local key      = tbl[KEY]
    local space_id = tbl[SPACE_ID]
    local index_id = tbl[INDEX_ID]

    local key_string = table.concat(map(key, escape_call_arg), ', ')

    local descr = string.format(
        'DELETE FROM space(%d) WHERE index(%d) = (%s)',
        space_id,
        index_id,
        key_string
    )
    subtree:add(buffer, descr)
end


local function parse_error_response(tbl, buffer, subtree)
    local data = tbl[ERROR]
    if not data then
        subtree:add(buffer, '(empty response body)')
    else
        subtree:add(buffer, data)
    end
end

local function parse_response(tbl, buffer, subtree)
    local data = tbl[DATA]
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

local function parser_not_implemented(tbl, buffer, subtree)
    subtree:add(buffer, 'parser not yet implemented (or unknown packet?)')
end

local function code_to_command(code)

    local codes = {
        [SELECT]  = {name = 'select', decoder = parse_select},
        [INSERT]  = {name = 'insert', decoder = parse_insert},
        [REPLACE] = {name = 'replace', decoder = parse_insert},
        [UPDATE]  = {name = 'update', decoder = parser_not_implemented},
        [DELETE]  = {name = 'delete', decoder = parse_delete},
        [CALL]    = {name = 'call', decoder = parse_call},
        [AUTH]    = {name = 'auth', decoder = parser_not_implemented},
        [EVAL]    = {name = 'eval', decoder = parse_eval},
        [UPSERT]  = {name = 'upsert', decoder = parser_not_implemented},

        -- Admin command codes
        [PING] = {name = 'ping', decoder = parser_not_implemented},

        -- Value for <code> key in response can be:
        [OK]   = {name = 'OK', is_response = true, decoder = parse_response},
        --[0x8XXX] = {name = 'ERROR', is_response = true},
    };
    if code >= 0x8000 then
        return {name = 'ERROR', is_response = true, decoder = parse_error_response}
    end

    local unknown_code = {name = 'UNKNOWN', decoder = parser_not_implemented}

    return (codes[code] or unknown_code)
end


-- create a function to dissect it
function tarantool_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Tarantool"

    if buffer(0, 9):string() == "Tarantool" then
        pinfo.cols.info = 'Greeting packet. ' .. tostring(pinfo.cols.info)

        local subtree = tree:add(tarantool_proto, buffer(),"Tarantool greeting packet")
        subtree:add(buffer(0, 64), "Server version: " .. buffer(0, 64):string())
        subtree:add(buffer(64, 44), "Salt: " .. buffer(64, 44):string())
        subtree:add(buffer(108), "Reserved space")
        return buffer(0, 9):len()
    end

    local iterator = msgpack.unpacker(binary_string(buffer))
    local _, packet_length = iterator()

    -- TODO: check bytes available

    local size_length, header_data = iterator()
    size_length = size_length - 1;

    local packet_buffer = buffer(size_length)

    local request_length = packet_length + size_length

    if (buffer:len() < request_length) then
        -- debug('reassemble required: ' .. (request_length - buffer:len()) )
        pinfo.desegment_len = request_length - buffer:len()
        pinfo.desegment_offset = 0
        return DESEGMENT_ONE_MORE_SEGMENT
    end

    local command = code_to_command(header_data[TYPE])

    local header_length, body_data = iterator()
    header_length = header_length - size_length - 1
    local body_buffer = packet_buffer(size_length + header_length)


    if not command.is_response then
        local subtree = tree:add(tarantool_proto, buffer(),"Tarantool protocol data")
        -- subtree:add(tnt_field_sync, header_data[0x01])
        local header_descr = string.format('code: 0x%02x (%s), sync: 0x%04x', header_data[TYPE], command.name, header_data[SYNC])
        subtree:add(packet_buffer(0, header_length), header_descr)

        local decoder = command.decoder or parser_not_implemented

        decoder(body_data, body_buffer, subtree)

        pinfo.cols.info = command.name:gsub("^%l", string.upper) .. ' request. ' .. tostring(pinfo.cols.info)
        --[[print(body_data, bytes_used)
        for k,v in pairs(body_data) do
            print(k,v)
        end]]
        -- subtree:add( buffer(0,4),"Request Type: " .. buffer(0,4):le_uint() .. ' ' .. requestName(buffer(0,4):le_uint()) )
        --        request(buffer, subtree)
    else
        local subtree = tree:add(tarantool_proto,buffer(),"Tarantool protocol data (response)")
        local header_descr = string.format('code: 0x%02x (%s), sync: 0x%04x', header_data[TYPE], command.name, header_data[SYNC])
        subtree:add(packet_buffer(0, header_length), header_descr)
        command.decoder(body_data, body_buffer, subtree)
        pinfo.cols.info = 'Response. ' .. tostring(pinfo.cols.info)
    end

    return request_length

end

-- load the udp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 14888
-- tcp_table:add(14888,tarantool_proto)
tcp_table:add(3301,tarantool_proto)

