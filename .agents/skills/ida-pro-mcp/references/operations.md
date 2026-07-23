# IDA MCP Agent Operations
<!-- GENERATED: scripts/generate_tool_skills.py -->

Generated from `host.agent_operations.AGENT_OPERATIONS`.

## `ida_open_binary`

Open a binary in a new or existing IDA analysis session.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "binary_path": {
      "type": "string",
      "description": "Absolute path to the binary to analyze."
    },
    "force_new": {
      "type": "boolean",
      "description": "Create a new session even if the binary is already open."
    },
    "notes": {
      "type": "string",
      "description": "Optional session notes."
    }
  },
  "required": [
    "binary_path"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_open_binary",
  "arguments": {
    "binary_path": "/samples/target.exe"
  }
}
```

## `ida_session_state`

Get the current binary, analysis progress, and next useful actions.

Input schema:
```json
{
  "type": "object",
  "properties": {},
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_session_state",
  "arguments": {}
}
```

## `ida_session_status`

Check whether IDA analysis is ready without starting more work.

Input schema:
```json
{
  "type": "object",
  "properties": {},
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_session_status",
  "arguments": {}
}
```

## `ida_close_session`

Close the active IDA analysis session and release its runtime.

Input schema:
```json
{
  "type": "object",
  "properties": {},
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_close_session",
  "arguments": {}
}
```

## `ida_batch`

Execute several deterministic analysis operations sequentially in one request.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "calls": {
      "type": "array",
      "description": "Public ida_* calls as {name, arguments} objects; omit arguments for a parameterless call.",
      "items": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "arguments": {
            "type": "object"
          }
        },
        "required": [
          "name"
        ],
        "additionalProperties": false
      }
    },
    "continue_on_error": {
      "type": "boolean",
      "description": "Continue later calls after an error."
    }
  },
  "required": [
    "calls"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_batch",
  "arguments": {
    "calls": [
      {
        "name": "ida_overview",
        "arguments": {}
      },
      {
        "name": "ida_list_functions",
        "arguments": {
          "limit": 20
        }
      }
    ]
  }
}
```

## `ida_overview`

Get binary metadata, architecture, entry points, and high-level analysis context.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_overview",
  "arguments": {}
}
```

## `ida_find`

Find names, strings, imports, comments, and references matching text.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Text, symbol, API, or IOC to find."
    },
    "limit": {
      "type": "integer",
      "description": "Maximum result items to return."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "query"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_find",
  "arguments": {
    "query": "recv",
    "limit": 20
  }
}
```

## `ida_semantic_search`

Find functions by behavior or natural-language intent after indexing the binary.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Behavior to find, such as 'function that decrypts strings'."
    },
    "mode": {
      "type": "string",
      "enum": [
        "quick",
        "expand"
      ],
      "description": "quick is faster; expand adds behavior-driven matches."
    },
    "limit": {
      "type": "integer",
      "description": "Maximum result items to return."
    },
    "min_score": {
      "type": "number",
      "description": "Minimum semantic or hybrid rank score."
    },
    "start": {
      "type": "string",
      "description": "Inclusive start address for result filtering."
    },
    "end": {
      "type": "string",
      "description": "Exclusive end address for result filtering."
    },
    "address": {
      "type": "string",
      "description": "Center address or function for radius filtering."
    },
    "radius": {
      "type": "integer",
      "description": "Byte radius around address for result filtering."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "query"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_semantic_search",
  "arguments": {
    "query": "function that decrypts strings",
    "mode": "quick",
    "limit": 20
  }
}
```

## `ida_index_functions`

Build a scoped semantic function index in responsive background slices.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "quality": {
      "type": "string",
      "enum": [
        "fast",
        "full"
      ],
      "description": "fast scans metadata and disassembly; full adds Hex-Rays decompilation for better retrieval quality."
    },
    "limit": {
      "type": "integer",
      "description": "Maximum functions for the whole job; omit to index every matching function."
    },
    "cursor": {
      "type": "string",
      "description": "Start after this hexadecimal function address."
    },
    "start": {
      "type": "string",
      "description": "Inclusive start address for one index range."
    },
    "end": {
      "type": "string",
      "description": "Exclusive end address for one index range."
    },
    "address": {
      "type": "string",
      "description": "Center function or address for radius-based indexing."
    },
    "radius": {
      "type": "integer",
      "description": "Byte radius around address; indexes overlapping functions."
    },
    "ranges": {
      "type": "array",
      "description": "Multiple address ranges to index.",
      "items": {
        "type": "object",
        "properties": {
          "start": {
            "type": "string"
          },
          "end": {
            "type": "string"
          }
        },
        "required": [
          "start",
          "end"
        ],
        "additionalProperties": false
      }
    },
    "query": {
      "type": "string",
      "description": "Optional function-name filter; glob and regex forms are supported."
    },
    "min_size": {
      "type": "integer",
      "description": "Minimum function size in bytes."
    },
    "max_size": {
      "type": "integer",
      "description": "Maximum function size in bytes."
    },
    "slice_size": {
      "type": "integer",
      "description": "Functions processed per IDA RPC slice; smaller values improve interactive responsiveness."
    },
    "background": {
      "type": "boolean",
      "description": "Run non-blocking and return a task ID; defaults to true."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_index_functions",
  "arguments": {
    "quality": "full"
  }
}
```

## `ida_index_status`

Check progress or retrieve the result of a background semantic-index job started by this client.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "task_id": {
      "type": "string",
      "description": "Task ID returned by ida_index_functions."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_index_status",
  "arguments": {}
}
```

## `ida_cancel_index`

Cancel a queued or running semantic-index job started by this client after its current slice.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "task_id": {
      "type": "string",
      "description": "Task ID returned by ida_index_functions."
    }
  },
  "required": [
    "task_id"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_cancel_index",
  "arguments": {
    "task_id": "abc123def456"
  }
}
```

## `ida_list_functions`

List functions, optionally filtering by name.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Optional function-name filter."
    },
    "limit": {
      "type": "integer",
      "description": "Maximum result items to return."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_list_functions",
  "arguments": {
    "limit": 50
  }
}
```

## `ida_create_function`

Define a function at an address, optionally naming it and setting an explicit end boundary.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "end": {
      "type": "string",
      "description": "Optional exclusive end address."
    },
    "name": {
      "type": "string",
      "description": "Optional function name."
    },
    "flags": {
      "type": "integer",
      "description": "Optional IDA function flags to add."
    },
    "force": {
      "type": "boolean",
      "description": "Delete overlapping definitions before creating the function."
    },
    "risk_ack": {
      "type": "boolean",
      "description": "Set true only after verifying this IDB mutation is intended."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_create_function",
  "arguments": {
    "address": "0x401000",
    "risk_ack": true
  }
}
```

## `ida_change_function`

Change a function's end boundary, equivalent to IDA's Set function end command.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "end": {
      "type": "string",
      "description": "New exclusive function end address, like the GUI cursor position."
    },
    "risk_ack": {
      "type": "boolean",
      "description": "Set true only after verifying this IDB mutation is intended."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address",
    "end"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_change_function",
  "arguments": {
    "address": "0x401000",
    "end": "0x401080",
    "risk_ack": true
  }
}
```

## `ida_calc_eval`

Evaluate a safe arithmetic or bitwise expression involving addresses and symbols.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "expr": {
      "type": "string",
      "description": "Expression such as 0x401000 + 0x20."
    },
    "query": {
      "type": "string"
    },
    "intent": {
      "type": "string"
    },
    "persist": {
      "type": "boolean",
      "description": "Save the calculation result to the analysis notebook."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "expr"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_calc_eval",
  "arguments": {
    "expr": "0x401000 + 0x20"
  }
}
```

## `ida_calc_offset`

Calculate the signed and absolute distance between two addresses or symbols.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "target": {
      "type": "string",
      "description": "Numeric value, hexadecimal address, or symbol accepted by the calculation backend."
    },
    "intent": {
      "type": "string"
    },
    "persist": {
      "type": "boolean",
      "description": "Save the calculation result to the analysis notebook."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address",
    "target"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_calc_offset",
  "arguments": {
    "address": "0x401000",
    "target": "0x401050"
  }
}
```

## `ida_calc_convert`

Convert an integer or address into hexadecimal, decimal, binary, octal, byte, and ASCII forms.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "value": {
      "type": "string",
      "description": "Numeric value, hexadecimal address, or symbol accepted by the calculation backend."
    },
    "persist": {
      "type": "boolean",
      "description": "Save the calculation result to the analysis notebook."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "value"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_calc_convert",
  "arguments": {
    "value": "1234"
  }
}
```

## `ida_calc_resolve`

Translate an IDA virtual address or file offset using the binary's segment mapping.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Numeric value, hexadecimal address, or symbol accepted by the calculation backend."
    },
    "value": {
      "type": "string",
      "description": "Numeric value, hexadecimal address, or symbol accepted by the calculation backend."
    },
    "to_va": {
      "type": "boolean"
    },
    "from_file": {
      "type": "boolean"
    },
    "intent": {
      "type": "string"
    },
    "persist": {
      "type": "boolean",
      "description": "Save the calculation result to the analysis notebook."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_calc_resolve",
  "arguments": {
    "address": "0x401000"
  }
}
```

## `ida_calc_deref`

Read a typed value or pointer from an address, optionally following multiple pointer hops.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "type": {
      "type": "string",
      "enum": [
        "bytes",
        "u8",
        "u16",
        "u32",
        "u64",
        "s8",
        "s16",
        "s32",
        "s64",
        "f32",
        "f64",
        "ptr",
        "string"
      ]
    },
    "size": {
      "type": "integer"
    },
    "deref_depth": {
      "type": "integer"
    },
    "intent": {
      "type": "string"
    },
    "persist": {
      "type": "boolean",
      "description": "Save the calculation result to the analysis notebook."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_calc_deref",
  "arguments": {
    "address": "0x401000",
    "type": "u32"
  }
}
```

## `ida_calc_chain`

Follow a pointer chain from an address using explicit offsets.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "offsets": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Ordered pointer-chain offsets."
    },
    "size": {
      "type": "integer"
    },
    "intent": {
      "type": "string"
    },
    "persist": {
      "type": "boolean",
      "description": "Save the calculation result to the analysis notebook."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address",
    "offsets"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_calc_chain",
  "arguments": {
    "address": "0x601020",
    "offsets": [
      "0x10",
      "0x20"
    ]
  }
}
```

## `ida_calc_align`

Align a value or address down, up, and to the nearest requested boundary.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "value": {
      "type": "string",
      "description": "Numeric value, hexadecimal address, or symbol accepted by the calculation backend."
    },
    "address": {
      "type": "string",
      "description": "Numeric value, hexadecimal address, or symbol accepted by the calculation backend."
    },
    "expr": {
      "type": "string"
    },
    "size": {
      "type": "integer"
    },
    "intent": {
      "type": "string"
    },
    "persist": {
      "type": "boolean",
      "description": "Save the calculation result to the analysis notebook."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "size"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_calc_align",
  "arguments": {
    "value": "0x401003",
    "size": 16
  }
}
```

## `ida_calc_bitops`

Apply a bitwise and, or, xor, not, shift-left, or shift-right operation to integer values.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "value": {
      "type": "string",
      "description": "Numeric value, hexadecimal address, or symbol accepted by the calculation backend."
    },
    "target": {
      "type": "string",
      "description": "Numeric value, hexadecimal address, or symbol accepted by the calculation backend."
    },
    "bit_op": {
      "type": "string",
      "enum": [
        "and",
        "or",
        "xor",
        "not",
        "shl",
        "shr"
      ]
    },
    "op": {
      "type": "string",
      "enum": [
        "and",
        "or",
        "xor",
        "not",
        "shl",
        "shr"
      ]
    },
    "intent": {
      "type": "string"
    },
    "persist": {
      "type": "boolean",
      "description": "Save the calculation result to the analysis notebook."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "value"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_calc_bitops",
  "arguments": {
    "value": "0xff",
    "target": "0x0f",
    "bit_op": "xor"
  }
}
```

## `ida_list_strings`

List strings in the current binary, optionally filtered by text.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Optional string filter."
    },
    "limit": {
      "type": "integer",
      "description": "Maximum result items to return."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_list_strings",
  "arguments": {
    "query": "http",
    "limit": 50
  }
}
```

## `ida_list_imports`

List imported APIs in the current binary.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "limit": {
      "type": "integer",
      "description": "Maximum result items to return."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_list_imports",
  "arguments": {
    "limit": 100
  }
}
```

## `ida_decompile`

Decompile one function with bounded CFG and ctree-derived structural evidence.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_decompile",
  "arguments": {
    "address": "0x401000"
  }
}
```

## `ida_disassemble`

Disassemble one function or address range with compact CFG and call-target evidence when available.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "end": {
      "type": "string",
      "description": "Optional end address for a range."
    },
    "style": {
      "type": "string",
      "enum": [
        "csmini",
        "classic",
        "annotated"
      ],
      "description": "Assembly output style."
    },
    "limit": {
      "type": "integer",
      "description": "Maximum result items to return."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_disassemble",
  "arguments": {
    "address": "0x401000",
    "limit": 80
  }
}
```

## `ida_xrefs_to`

List cross-references to a function, data item, or address.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_xrefs_to",
  "arguments": {
    "address": "0x401000"
  }
}
```

## `ida_callers`

List functions that call a target function.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_callers",
  "arguments": {
    "address": "recv"
  }
}
```

## `ida_callees`

List functions called by a target function.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_callees",
  "arguments": {
    "address": "0x401000"
  }
}
```

## `ida_rename`

Rename a function or symbol in the IDB.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "name": {
      "type": "string",
      "description": "New symbol name."
    },
    "risk_ack": {
      "type": "boolean",
      "description": "Set true only after verifying this IDB mutation is intended."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address",
    "name"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_rename",
  "arguments": {
    "address": "0x401000",
    "name": "handle_recv",
    "risk_ack": true
  }
}
```

## `ida_comment`

Add or replace a comment at an address in the IDB.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "comment": {
      "type": "string",
      "description": "Comment text."
    },
    "risk_ack": {
      "type": "boolean",
      "description": "Set true only after verifying this IDB mutation is intended."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client."
    }
  },
  "required": [
    "address",
    "comment"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_comment",
  "arguments": {
    "address": "0x401000",
    "comment": "handles inbound packets",
    "risk_ack": true
  }
}
```

## `ida_write_finding`

Record or merge a typed claim, question, task, or decision with its evidence.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "title": {
      "type": "string",
      "description": "Short, stable statement of the insight."
    },
    "content": {
      "type": "string",
      "description": "Reasoning, implications, or next verification step."
    },
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "category": {
      "type": "string",
      "description": "Finding category."
    },
    "confidence": {
      "type": "number",
      "description": "Confidence from 0 to 1."
    },
    "priority": {
      "type": "number",
      "description": "Investigation priority from 0 to 1."
    },
    "kind": {
      "type": "string",
      "enum": [
        "finding",
        "hypothesis",
        "question",
        "task",
        "decision"
      ],
      "description": "Role this item plays in the investigation."
    },
    "status": {
      "type": "string",
      "enum": [
        "open",
        "confirmed",
        "resolved",
        "rejected"
      ],
      "description": "Current lifecycle state."
    },
    "tags": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Optional tags."
    },
    "evidence": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "type": {
            "type": "string"
          },
          "value": {
            "type": "string"
          },
          "address": {
            "type": "string"
          },
          "weight": {
            "type": "number"
          }
        },
        "required": [
          "type",
          "value"
        ],
        "additionalProperties": false
      },
      "description": "Concrete observations supporting the item."
    }
  },
  "required": [
    "title"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_write_finding",
  "arguments": {
    "title": "recv handler parses framed input",
    "content": "Length is read before dispatch.",
    "address": "0x401000",
    "kind": "finding",
    "status": "confirmed",
    "confidence": 0.8,
    "priority": 0.7,
    "evidence": [
      {
        "type": "call",
        "value": "recv",
        "address": "0x401024"
      }
    ]
  }
}
```

## `ida_list_findings`

List investigation items with lifecycle and type filters.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "kind": {
      "type": "string",
      "enum": [
        "finding",
        "hypothesis",
        "question",
        "task",
        "decision"
      ]
    },
    "status": {
      "type": "string",
      "enum": [
        "open",
        "confirmed",
        "resolved",
        "rejected"
      ]
    },
    "category": {
      "type": "string"
    },
    "address": {
      "type": "string",
      "description": "Function name or hexadecimal address, for example 0x401000."
    },
    "tag": {
      "type": "string"
    },
    "min_confidence": {
      "type": "number"
    },
    "include_resolved": {
      "type": "boolean"
    },
    "include_contradicted": {
      "type": "boolean"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum result items to return."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_list_findings",
  "arguments": {
    "status": "open",
    "limit": 20
  }
}
```

## `ida_search_findings`

Search investigation memory by meaning or keywords.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Concept, behavior, or keyword to recall."
    },
    "category": {
      "type": "string"
    },
    "include_resolved": {
      "type": "boolean"
    },
    "include_contradicted": {
      "type": "boolean"
    },
    "threshold": {
      "type": "number"
    },
    "limit": {
      "type": "integer",
      "description": "Maximum result items to return."
    }
  },
  "required": [
    "query"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_search_findings",
  "arguments": {
    "query": "unchecked packet length",
    "limit": 10
  }
}
```

## `ida_update_finding`

Revise an investigation item or transition its lifecycle state.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "entry_id": {
      "type": "string",
      "description": "Finding identifier."
    },
    "status": {
      "type": "string",
      "enum": [
        "open",
        "confirmed",
        "resolved",
        "rejected"
      ]
    },
    "reason": {
      "type": "string",
      "description": "Reason for the transition, especially rejection."
    },
    "content": {
      "type": "string"
    },
    "confidence": {
      "type": "number"
    },
    "priority": {
      "type": "number"
    },
    "tags": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  },
  "required": [
    "entry_id"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_update_finding",
  "arguments": {
    "entry_id": "a1b2c3d4",
    "status": "resolved",
    "reason": "Verified in callers."
  }
}
```

## `ida_analysis_brief`

Summarize confirmed knowledge, open questions, conflicts, and current focus.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "limit": {
      "type": "integer",
      "description": "Maximum result items to return."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_analysis_brief",
  "arguments": {
    "limit": 8
  }
}
```

## `ida_next_target`

Get the highest-priority next analysis target from the notebook frontier.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Optional investigation theme."
    },
    "limit": {
      "type": "integer",
      "description": "Maximum result items to return."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_next_target",
  "arguments": {
    "query": "input validation",
    "limit": 10
  }
}
```

## `ida_python`

Execute a Python expression or script in the active IDA process.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "code": {
      "type": "string",
      "description": "Python expression or script to execute in IDA context."
    },
    "risk_ack": {
      "type": "boolean",
      "description": "Set true only after verifying this code execution is authorized and intended."
    }
  },
  "required": [
    "code"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_python",
  "arguments": {
    "code": "print(idaapi.get_imagebase())",
    "risk_ack": true
  }
}
```

## `ida_continue`

Continue a truncated result; pass field when the response lists more than one truncated field.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "token": {
      "type": "string",
      "description": "Continuation token from the response's _continue.token field."
    },
    "field": {
      "type": "string",
      "description": "Exact field name from _continue.fields, required when more than one field is truncated (for example code or annotated_code)."
    },
    "offset": {
      "type": "integer",
      "description": "Optional item/character offset within the selected field."
    },
    "count": {
      "type": "integer",
      "description": "Optional number of items/characters to return."
    }
  },
  "required": [
    "token"
  ],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_continue",
  "arguments": {
    "token": "ABC123",
    "field": "code"
  }
}
```

## `ida_help`

Get the exact contract and example for an IDA operation, or search the operation catalog.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "topic": {
      "type": "string",
      "description": "Exact operation name, such as ida_decompile."
    },
    "query": {
      "type": "string",
      "description": "Words to search across operation names and descriptions."
    }
  },
  "required": [],
  "additionalProperties": false
}
```

Example:
```json
{
  "name": "ida_help",
  "arguments": {
    "topic": "ida_decompile"
  }
}
```
