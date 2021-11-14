## Tarantool protocol dissector

[Tarantool](https://www.tarantool.io/en/) is an in-memory computing platform.
It uses binary protocol named IProto for communicating. See protocol
description in [documentation][box-protocol].

In Wireshark the user can control how protocols are dissected. Each protocol
has its own dissector and user may add his own dissectors written in Lua. This
dissector implemented for Tarantool binary protocol.

![Wireshark][screenshot]

### How to use

- Setup Wireshark. See chapter [Building and Installing
  Wireshark][building-and-installing-wireshark] in documentation.
- Put a Lua file with dissector and `MessagePack.lua` to a directory with
  plugins for Wireshark, directory depends on operating system, please refer to
  chapter [Plugin folders][plugin-folders].
  Note that Wireshark requires root privileges, make sure you are using plugin
  directory for a user that is used for running Wireshark. It possible to run
  Wireshark in terminal and pass Lua extension explicitly: `wireshark -X
  lua_script:tarantool.dissector.lua` or `tshark -X
  lua_script:tarantool.dissector.lua -V`.
- If for some reason you still use Tarantool <= 1.5, use `tarantool15.dissector.lua`
- Run Wireshark. By default Tarantool protocol dissector decodes TCP packets
  with port 3301. However one can change a port for dissector in Wireshark
  settings, see chapter [Control Protocol dissection][control-protocol-dissection].

### How to test

There is a script `test.lua` that uses Tarantool instance remotely via network
and covers most part of IProto commands. For testing one can run Wireshark on
local interface `lo0` with filtering by port 3301 and run script with command
`tarantool test.lua`.

[box-protocol]: https://www.tarantool.io/en/doc/latest/dev_guide/internals/box_protocol/
[screenshot]: screenshot.png
[building-and-installing-wireshark]: https://www.wireshark.org/docs/wsug_html_chunked/ChapterBuildInstall.html
[plugin-folders]: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html
[control-protocol-dissection]: https://www.wireshark.org/docs/wsug_html_chunked/ChCustProtocolDissectionSection.html
