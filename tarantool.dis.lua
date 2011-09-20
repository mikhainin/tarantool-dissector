-- declare the protocol
tarantool_proto = Proto("tarantool","Tarantool")

function leb128Unpack(buffer, offset)
-- see http://en.wikipedia.org/wiki/LEB128#Decode_unsigned_integer
    
    local result = 0
    local shift = 0
    local used = 1
    while true do
        local byte = buffer(offset, 1):le_uint();
        local bit7 = buffer(offset, 1):bitfield(0, 1)
        offset = offset + 1
        local tmp = (bit7 == 0) and byte or (byte - 256)
        result = result + ( tmp * (2 ^ shift) ) -- result |= (low order 7 bits of byte << shift);
        
        if ( bit7 == 0) then
            break
        end
        shift = shift + 7
        used = used + 1
    end
    return result, used
end



function add_one_tulpe(buffer, subtree)
    --[[
        <tuple> ::= <cardinality><field>+
        <cardinality> ::= <int32>
        <field> ::= <int32_varint><data>
        <data> ::= <int8>+
        <int32_varint> ::= <int8>+
    ]]
    local data_length = 4 -- for cardinality
    local cardinality = buffer(0,4):le_uint()
    
    local array = {}
    
    for i=1,cardinality do
        debug('offset:'.. data_length)
        local field_length, used = leb128Unpack(buffer, data_length)
        debug('f,u:'.. field_length .. ' '..used)
        array[i] = {
                ['start']  = data_length + used,
                ['length'] = field_length,
                ['title']  = "Data (length: " .. field_length .. ')'
            }
         
        data_length = data_length + field_length + used
    end
    
    local tree =  subtree:add( tarantool_proto, buffer(0, data_length),"Tuple (cardinality: "..cardinality..')')
    for i,v in ipairs(array) do
        tree:add(buffer(v.start, v.length), v.title)
    end
    
    return data_length
    
end

function add_tulpes(buffer, subtree, name, count)
    -- local count  = count_buffer(0,4):le_uint()
    local tuples = subtree:add( tarantool_proto, buffer(), "Tuples")
    
    -- tuples:add( count_buffer(0,4), "Count: " .. count )
    
    local offset = 0
    for i=1,count do
        offset = offset + add_one_tulpe( buffer(offset), tuples )
    end
    
end

function select_request_body(buffer, subtree)
    --[[ 
        <select_request_body> ::= <namespace_no><index_no>
                              <offset><limit><count><tuple>+
    ]]

    local tree =  subtree:add( tarantool_proto, buffer(),"Select body")
    
    local namespace_no = buffer(0,4):le_uint()
    local index_no = buffer(4, 4):le_uint()
    local offset   = buffer(8, 4):le_uint()
    local limit    = buffer(12,4):le_uint()
    local count    = buffer(16,4):le_uint()
    if (limit == 4294967295) then
        limit = limit .. ' (no limit)'
    end
    tree:add( buffer(0, 4), "Namespace # " .. namespace_no )
    tree:add( buffer(4, 4), "Index # " .. index_no )
    tree:add( buffer(8, 4), "Offset # " .. offset )
    tree:add( buffer(12,4), "Limit # " .. limit )
    
    tree:add( buffer(16,4), "Tuples count: " .. count )
    add_tulpes(buffer(20, buffer:len() - 20), tree, 'tuple', count)
    
end

function requestName(reqid)
    local requests = {
            [13] = "INSERT",
            [17] = "SELECT",
            [19] = "UPDATE",
            [20] = "DELETE(obsolete)",
            [21] = "DELETE",
            [22] = "CALL",
            [65280] = "PING",
    }
    return requests[reqid] or 'UNKNOWN'
end

function insert_request_body(buffer, subtree)
    --[[
        <insert_request_body> ::= <space_no><flags><tuple>
    ]]
    local tree =  subtree:add( tarantool_proto, buffer(),"Insert body")
    -- subtree:add( buffer,"Insert data" )
    local namespace_no = buffer(0,4):le_uint()
    local flags    = buffer(4, 4):le_uint()
    tree:add( buffer(0, 4), "Namespace # " .. namespace_no )
    tree:add( buffer(4, 4), "Flags # " .. flags )
    
    add_one_tulpe(buffer(8), tree)

    
end

function update_request_body(buffer, subtree)
    subtree:add( buffer,"Update data" )
end

function deletev13_request_body(buffer, subtree)
    --[[
        <delete_request_body> ::= <namespace_no><tuple>
    ]]
    local tree =  subtree:add( tarantool_proto, buffer(),"Delete body (v1.3)")
    
    local namespace_no = buffer(0,4):le_uint()
    tree:add( buffer(0, 4), "Namespace # " .. namespace_no )
    
    add_one_tulpe(buffer(4), tree)
    
end
function delete_request_body(buffer, subtree)
    subtree:add( buffer,"Delete data" )
end
function call_request_body(buffer, subtree)
    subtree:add( buffer,"Call data" )
end
function ping_request_body(buffer, subtree)
    subtree:add( buffer,"ping data" )
end
function unknown_request_body(buffer, subtree)
    subtree:add( buffer,"Unknown command data" )
end

function requestfunction(reqid)
    local requests = {
            [13] = insert_request_body,
            [17] = select_request_body,
            [19] = update_request_body,
            [20] = deletev13_request_body, -- old delete
            [21] = delete_request_body,
            [22] = call_request_body,
            [65280] = ping_request_body,
    }
    if (requests[reqid] == nil) then
        return unknown_request_body
    else
        return requests[reqid]
    end
    
end

function readHeader(buffer, subtree)
    --[[
        <header> ::= <type><body_length><request_id>
    ]]
    local req_type = buffer(0,4):le_uint()
    local length   = buffer(4,4):le_uint()
    local req_id   = buffer(8,4):le_uint()
    
    local header =  subtree:add( tarantool_proto, buffer(),"Header")
    header:add( buffer(0,4),"Request Type: " .. req_type .. ' (' .. requestName(req_type) .. ')' )
    header:add( buffer(4,4),"Body length: " .. length )
    header:add( buffer(8,4),"Request ID: " .. req_id )

    return buffer(12, buffer:len() - 12)
end

function request(buffer, subtree)
    --[[
    <request> ::= <header><request_body>
    ]]
    
    local req_type = buffer(0,4):le_uint()
    
    buffer = readHeader(buffer, subtree)
    
    local requestfunction = requestfunction(req_type)
    requestfunction(buffer, subtree)
end

function response(buffer, subtree)
    --[[
    <response> ::= <header><return_code>{<response_body>
    ]]
    
    buffer = readHeader(buffer, subtree)
    if ( buffer:len() > 0 ) then
        local code = buffer(0,4):le_uint()
        
        subtree:add( buffer(0,4),"Return code: " .. code )
        subtree:add( buffer(4),"Data" )
    end

end

-- create a function to dissect it
function tarantool_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "TARANTOOL"
    
    local body_length    = buffer(4,4):le_uint()
    local request_length = body_length + 12 -- 12 - header length
    
    if (pinfo.src_port == 33013) then
        -- answer, should have a response code
        -- request_length = request_length + 4
    end
    
    -- debug('buffer: ' .. buffer:len())
    -- debug('length: ' .. body_length)
    if (buffer:len() < request_length) then
        -- debug('reassemble required: ' .. (request_length - buffer:len()) )
        pinfo.desegment_len = request_length - buffer:len()
        pinfo.desegment_offset = 0
        return 0
    end
    if (pinfo.src_port ~= 33013) then
        -- debug('parsing')
        local subtree = tree:add(tarantool_proto,buffer(),"Tarantool protocol data")
        
        -- subtree:add( buffer(0,4),"Request Type: " .. buffer(0,4):le_uint() .. ' ' .. requestName(buffer(0,4):le_uint()) )
        request(buffer, subtree)
    else
        local subtree = tree:add(tarantool_proto,buffer(),"Tarantool protocol data (response)")
        response(buffer, subtree)
    end
    
    return request_length
    
end

-- load the udp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle udp port 7777
tcp_table:add(33013,tarantool_proto)


--[[
do
        local p_multi = Proto("multi","Tarantool");

        local vs_protos = {
                [2] = "mtp2",
                [3] = "mtp3",
                [4] = "alcap",
                [5] = "h248",
                [6] = "ranap",
                [7] = "rnsap",
                [8] = "nbap"
        }

        local f_proto = ProtoField.uint8("multi.protocol","Protocol",base.DEC,vs_protos)
        local f_dir = ProtoField.uint8("multi.direction","Direction",base.DEC,{ [1] = "incoming", [0] = "outgoing"})
        local f_text = ProtoField.string("multi.text","Text")

	p_multi.fields = { f_proto, f_dir, f_text }

        local data_dis = Dissector.get("data")

        local protos = {
                [2] = Dissector.get("mtp2"),
                [3] = Dissector.get("mtp3"),
                [4] = Dissector.get("alcap"),
                [5] = Dissector.get("h248"),
                [6] = Dissector.get("ranap"),
                [7] = Dissector.get("rnsap"),
                [8] = Dissector.get("nbap"),
                [9] = Dissector.get("rrc"),
                [10] = DissectorTable.get("sctp.ppi"):get_dissector(3), -- m3ua
                [11] = DissectorTable.get("ip.proto"):get_dissector(132), -- sctp
        }

        function p_multi.dissector(buf,pkt,root) 

                local t = root:add(p_multi,buf(0,2))
                t:add(f_proto,buf(0,1))
                t:add(f_dir,buf(1,1))

                local proto_id = buf(0,1):uint()

                local dissector = protos[proto_id]

                if dissector ~= nil then
                        dissector:call(buf(2):tvb(),pkt,root)
                elseif proto_id < 2 then
                        t:add(f_text,buf(2))
                        -- pkt.cols.info:set(buf(2,buf:len() - 3):string())
                else
                        data_dis:call(buf(2):tvb(),pkt,root)
                end 

        end

        local wtap_encap_table = DissectorTable.get("wtap_encap")
        local udp_encap_table = DissectorTable.get("udp.port")

        wtap_encap_table:add(wtap.USER15,p_multi)
        wtap_encap_table:add(wtap.USER12,p_multi)
        udp_encap_table:add(7555,p_multi)
end
	]]