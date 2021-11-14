#!/usr/bin/env tarantool

-- TODO:
--     PREPARE
--     CONFIRM
--     ROLLBACK
--     JOIN
--     VOTE
--     VOTE_DEPRECATED
--     SUBSCRIBE
--     FETCH_SNAPSHOT
--     REGISTER
-- https://gist.github.com/sergos/c2dae39bf1ac47519356de23601ea7f4

local netbox = require('net.box')

local addr = '127.0.0.1:3301'
local space_name = 'testspace'
local user = 'admin'
local passwd = 'admin'
local uri = user .. ':' .. passwd .. '@' .. addr

box.cfg{
    listen = addr
}
local s = box.schema.space.create(space_name, {
    if_not_exists = true
})
s:create_index('pk', {
    type = 'hash',
    parts = {1, 'unsigned'},
    if_not_exists = true,
})
--box.schema.user.grant('guest', 'read, write, execute', 'universe')
box.schema.user.passwd(user, passwd)

local conn = netbox.connect(uri)
conn:ping()
local space = conn.space[space_name]

space:insert({1, 10})
space:insert({2, 20})
space:insert({3, 30})

space:get(1)

space:select()

space:replace({5, 6, 7, 8})

space:update({1}, {{'=', 2, 5}})

space:upsert({12, 'c'}, {{'=', 3, 'a'}, {'=', 4, 'b'}})

space:delete({1})
space:delete({2})
space:delete({3})

conn:eval('function f5() return 5+5 end; return f5();')
conn:eval('return ...', {1, 2, {3, 'x'}})

conn:eval('function f1() return 5 + 5 end;')
conn:call('f1')

conn:eval('function f2(x, y) return x, y end;')
conn:call('f2', {1, 'B'})

conn:close()

os.exit(0)
