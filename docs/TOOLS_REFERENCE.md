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

## `ida_overview`

Get binary metadata, architecture, entry points, and high-level analysis context.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path."
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
      "description": "Optional session ID, IDB path, or binary path."
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
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path."
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

Build the function index for semantic search, using fast metadata or full Hex-Rays decompilation.

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
      "description": "fast scans metadata and disassembly; full decompiles functions in resumable passes for best retrieval quality."
    },
    "limit": {
      "type": "integer",
      "description": "Optional functions to process in this pass; full mode otherwise chooses an adaptive pass size."
    },
    "cursor": {
      "type": "string",
      "description": "Resume after the next_cursor returned by a limited indexing pass."
    },
    "idb": {
      "type": "string",
      "description": "Optional session ID, IDB path, or binary path."
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
      "description": "Optional session ID, IDB path, or binary path."
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
      "description": "Optional session ID, IDB path, or binary path."
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
      "description": "Optional session ID, IDB path, or binary path."
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

Decompile one function to pseudocode.

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
      "description": "Optional session ID, IDB path, or binary path."
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

Disassemble one function or address range.

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
      "description": "Optional session ID, IDB path, or binary path."
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
      "description": "Optional session ID, IDB path, or binary path."
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
      "description": "Optional session ID, IDB path, or binary path."
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
      "description": "Optional session ID, IDB path, or binary path."
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
      "description": "Optional session ID, IDB path, or binary path."
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
      "description": "Optional session ID, IDB path, or binary path."
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

Save an analysis finding to the durable session notebook.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "title": {
      "type": "string",
      "description": "Short finding title."
    },
    "content": {
      "type": "string",
      "description": "Evidence and reasoning."
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
    "tags": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Optional tags."
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
    "title": "recv handler",
    "content": "Receives and parses inbound packets.",
    "address": "0x401000",
    "confidence": 0.8
  }
}
```

## `ida_list_findings`

List durable findings from the current analysis session.

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
  "name": "ida_list_findings",
  "arguments": {
    "limit": 20
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
    "limit": 10
  }
}
```

## `ida_continue`

Continue a truncated result using the continuation token returned by a previous call.

Input schema:
```json
{
  "type": "object",
  "properties": {
    "token": {
      "type": "string",
      "description": "Continuation token from a truncated response."
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
    "token": "ABC123"
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
