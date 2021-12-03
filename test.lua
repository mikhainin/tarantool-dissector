#!/usr/bin/env tarantool

-- Lua script that uses Tarantool Lua API and produce
-- IProto network packets for testing Wireshark dissector.
--
-- IProto protocol description:
-- https://www.tarantool.io/en/doc/latest/dev_guide/internals/box_protocol/
--
-- How to run: tarantool test.lua

local netbox = require('net.box')
local popen = require('popen')
local fiber = require('fiber')
local log = require('log')

local addr = '127.0.0.1:3301'
local space_name = 'testspace'
local test_dir = './test.data'
local test_dir_replica = './test.data/replica'

os.execute('rm -rf ' .. test_dir)
os.execute('rm -rf replica')
os.execute('mkdir ' .. test_dir)

box.cfg{
    listen = addr,
    log_level = 6,
    read_only = false,
    replication = 'replicator:password@localhost:3301',
    work_dir = test_dir,
    replication_synchro_quorum = 1,
}

local s = box.schema.space.create(space_name, {
    if_not_exists = true,
    is_sync = true,
})

box.ctl.promote()

s:create_index('pk', {
    type = 'hash',
    parts = {1, 'unsigned'},
    if_not_exists = true,
})

box.schema.user.grant('guest', 'read, write, execute', 'universe')
box.schema.user.create('replicator', {
    password = 'password'
})
box.schema.user.grant('replicator', 'replication')

os.execute('mkdir -p ' .. test_dir_replica)
local cmd = {
    arg[-1],
    '-e',
    [[
    box.cfg {
        read_only = true,
        log_level = 6,
        replication = 'replicator:password@localhost:3301',
        listen = 3302,]] ..
        'work_dir = \'' .. test_dir_replica .. '\'' ..
    '}'
}

local replica, err = popen.new(cmd, {
    stdin = 'devnull',
    stdout = 'devnull',
    stderr = 'devnull',
})

if not replica then
    os.exit()
end

-- Wait for replica to connect.
while #box.info.replication < 2 do
    fiber.sleep(0.1)
end

local conn = netbox.connect(addr)
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

conn:eval('function f5() return 5 + 5 end; return f5();')
conn:eval('return ...', {1, 2, {3, 'x'}})

conn:eval('function f1() return 5 + 5 end;')
conn:call('f1')

conn:eval('function f2(x, y) return x, y end;')
conn:call('f2', {1, 'B'})

conn:close()

-- Teardown replica.
replica:kill()
replica:wait()

log.info("That's all")

os.exit(0)
