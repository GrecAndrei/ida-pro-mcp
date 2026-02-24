# DATA_OPS Tool Manual

## What It Does
Data creation: make_data, make_array, make_string, undefine, make_code

## Actions
- `make_data`: Create typed data item at an address.
- `make_array`: Create an array data item.
- `make_string`: Create a string item.
- `undefine`: Undefine item(s) at an address.
- `make_code`: Convert bytes to instruction(s).

## Key Parameters
- `action` (required): Operation selector.
- `addr` (required): Target address or function start (hex string).
- `size` (default `None`): Byte size / read length / data width, action-dependent.
- `count` (default `None`): Item count or array length.
- `str_type` (default `0`): IDA string type selector.

## Examples (JSON call snippets)
```json
{
  "tool": "data_ops",
  "args": {
    "action": "make_data",
    "addr": "0x404000",
    "size": 4
  }
}
```
```json
{
  "tool": "data_ops",
  "args": {
    "action": "make_array",
    "addr": "0x404100",
    "size": 1,
    "count": 64
  }
}
```

## Failure Modes
- `IDA_ERROR`: `Failed to create data`
- `INVALID_ARGS`: `count required`
- `IDA_ERROR`: `Failed to create array`
- `IDA_ERROR`: `Failed to create string`
- `IDA_ERROR`: `Failed to undefine`
- `IDA_ERROR`: `Failed to create instruction`
- `INVALID_ARGS`: `Unknown action: {action}`
