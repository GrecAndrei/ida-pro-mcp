# Address Parsing

All tools accept addresses in any of these formats:

- Hex: `0x401000`, `401000h`
- Decimal: `4198400`
- Symbol: `main`, `_printf`, `std::string::clear`
- Expression: `main+0x20`, `0x401000+512`

Most tools expect **Virtual Addresses**. Use `calc(action="resolve")` to convert file offsets to VAs.

If an address is not mapped in the IDB, the tool returns `ADDRESS_INVALID`.

## Address arithmetic

Never compute addresses mentally. Use:
```json
{"name":"calc","arguments":{"action":"offset","addr":"0x401000","target":"0x401050"}}
{"name":"calc","arguments":{"action":"deref","addr":"0x401000"}}
{"name":"calc","arguments":{"action":"chain","addr":"0x401000","offsets":[0,8,0x10]}}
```

`calc` and `memory` results are auto-captured to the blackboard.
