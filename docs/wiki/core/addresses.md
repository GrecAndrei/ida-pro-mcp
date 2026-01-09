# Address Parsing in IDA MCP

The MCP uses a robust parser for all address inputs. You never need to worry about the base or format.

## Supported Formats
*   **Hex strings**: `0x401000`, `401000h`, `0X401000`
*   **Decimal**: `4198400`
*   **Symbolic**: `main`, `_printf`, `std::string::clear`
*   **Expressions**: `main + 0x20`, `0x401000 + 512`

## Offsets vs VAs
When using the `calc` tool, you can convert between File Offsets and Virtual Addresses (VAs). 
Most tools expect **Virtual Addresses**.

## Error Handling
If an address is invalid (not mapped in the IDB), the tool will return an `ADDRESS_INVALID` error code.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
