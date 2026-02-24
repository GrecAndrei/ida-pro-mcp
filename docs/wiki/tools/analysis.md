# ANALYSIS Tool Manual

## What It Does
Control analysis options and reanalysis behavior.

## Actions
- `get_options`: Read current analysis and architecture settings.
- `set_options`: Update analysis options using an options dictionary.
- `set_processor`: Change processor type for the current database.
- `set_loader_options`: Apply loader-specific options (version-dependent).
- `set_architecture`: Adjust processor/bitness/endian settings.
- `reanalyze`: Trigger auto-analysis on a range or whole image.

## Key Parameters
- `action` (required): Operation selector.
- `options` (default `None`): Dictionary of analysis options to set.
- `processor` (default `None`): Processor/module name.
- `flags` (default `None`): Processor flag string or value, action-dependent.
- `loader` (default `None`): Loader name/options target.
- `value` (default `None`): Generic value parameter (setting, conversion, register write).
- `bitness` (default `None`): Target architecture bitness (`16`, `32`, or `64`) when supported.
- `endian` (default `None`): Target endianness (`le`/`be`) when supported.
- `start` (default `None`): Start address for range-based operations.
- `end` (default `None`): End address for range-based operations.

## Examples (JSON call snippets)
```json
{
  "tool": "analysis",
  "args": {
    "action": "get_options"
  }
}
```
```json
{
  "tool": "analysis",
  "args": {
    "action": "set_architecture",
    "bitness": 64,
    "endian": "le"
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `options dict required`
- `INVALID_ARGS`: `processor required`
- `INVALID_ARGS`: `value required`
- `INVALID_ARGS`: `loader required (could not determine current loader)`
- `NOT_IMPLEMENTED`: `set_loader_options not supported in this IDA version`
- `INVALID_ARGS`: `processor, bitness, or endian required`
- `INVALID_ARGS`: `bitness must be 16, 32, or 64`
- `NOT_IMPLEMENTED`: `inf_set_app_bitness not supported in this IDA version`
