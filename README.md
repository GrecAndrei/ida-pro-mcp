# IDA Pro MCP

Simple [MCP Server](https://modelcontextprotocol.io/introduction) to allow vibe reversing in IDA Pro.

https://github.com/user-attachments/assets/6ebeaa92-a9db-43fa-b756-eececce2aca0

The binaries and prompt for the video are available in the [mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset) repository.

Available functionality:

- `get_metadata()`: Get metadata about the current IDB.
- `get_function_by_name(name)`: Get a function by its name.
- `get_function_by_address(address)`: Get a function by its address.
- `get_current_address()`: Get the address currently selected by the user.
- `get_current_function()`: Get the function currently selected by the user.
- `convert_number(text, size)`: Convert a number (decimal, hexadecimal) to different representations.
- `list_functions()`: List all functions in the database.
- `decompile_function(address)`: Decompile a function at the given address.
- `disassemble_function(address)`: Get assembly code (address: instruction; comment) for a function.
- `get_xrefs_to(address)`: Get all cross references to the given address.
- `get_entry_points()`: Get all entry points in the database.
- `set_decompiler_comment(address, comment)`: Set a comment for a given address in the function pseudocode.
- `set_disassembly_comment(address, comment)`: Set a comment for a given address in the function disassembly.
- `rename_local_variable(function_address, old_name, new_name)`: Rename a local variable in a function.
- `rename_function(function_address, new_name)`: Rename a function.
- `set_function_prototype(function_address, prototype)`: Set a function's prototype.
- `set_local_variable_type(function_address, variable_name, new_type)`: Set a local variable's type.

There are a few IDA Pro MCP servers floating around, but I created my own for a few reasons:

1. The plugin installation should not require installing dependencies, just copy `mcp-plugin.py` in the IDA plugins folder and go!
2. The architecture of other plugins make it difficult to add new functionality quickly (too much boilerplate of unnecessary dependencies).
3. Learning new technologies is fun!

If you want to check them out, here is a list (in the order I discovered them):

- https://github.com/taida957789/ida-mcp-server-plugin (SSE protocol only, requires installing dependencies in IDAPython).
- https://github.com/fdrechsler/mcp-server-idapro (MCP Server in TypeScript, excessive boilerplate required to add new functionality).
- https://github.com/MxIris-Reverse-Engineering/ida-mcp-server (custom socket protocol, boilerplate).

## Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. For reverse engineering the conversion between integers and bytes are especially problematic. Below is a minimal example prompt, feel free to start a discussion or open an issue if you have good results with a different prompt:

> You task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:
> - Inspect the decompilation and add comments with your findings
> - Rename variables to more sensible names
> - Change the variable and argument types if necessary (especially pointer and array types)
> - Change function names to be more descriptive
> - If more details are necessary, disassemble the function and add comments with your findings
> - NEVER convert number bases yourself. Use the convert_number MCP tool if needed!
> - Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
> - Create a report.md with your findings and steps taken at the end
> - When you find a solution, prompt to user for feedback with the password you found

## IDA Pro Installation

1. Copy `mcp-plugin.py` in your plugins folder (`%appdata%\Hex-Rays\IDA Pro\plugins` on Windows).
2. Open an IDB and click `Edit -> Plugins -> MCP` to start the server.

## MCP Server Installation (Cline/Claude)

To install the MCP server in Cline, follow these steps:

1. Install [uv](https://github.com/astral-sh/uv) globally:
   - Windows: `pip install uv`
   - Linux/Mac: `curl -LsSf https://astral.sh/uv/install.sh | sh`
2. Clone this repository, for this example `C:\MCP\ida-pro-mcp`.
3. Navigate to the Cline _MCP Servers_ configuration (see screenshot).
4. Click on the _Installed_ tab.
5. Click on _Configure MCP Servers_, which will open `cline_mcp_settings.json`.
6. Add the `ida-pro-mcp` server:

```json
{
  "mcpServers": {
    "github.com/mrexodia/ida-pro-mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "c:\\MCP\\ida-pro-mcp",
        "run",
        "server.py"
      ],
      "timeout": 600
    }
  }
}

```

## Development

```sh
uv run fastmcp dev server.py
```

This will open a web interface at http://localhost:5173 and allow you to interact with the MCP tools for testing.

Adding new features is a super easy and streamlined process. All you have to do is add a new `@jsonrpc` function to [`mcp-plugin.py`](https://github.com/mrexodia/ida-pro-mcp/blob/7186d29a3c8b04f19907ab6d3d0e7a6f8f880bc0/mcp-plugin.py#L540-L581) and your function will be available in the MCP server without any additional boilerplate! Below is a video where I add the `get_metadata` function in less than 2 minutes (including testing):

https://github.com/user-attachments/assets/951de823-88ea-4235-adcb-9257e316ae64

## Available tools

```
<use_mcp_tool>
<server_name>github.com/mrexodia/ida-pro-mcp</server_name>
<tool_name>get_current_function</tool_name>
<arguments></arguments>
</use_mcp_tool>
```

## Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they can sometimes struggle with complex mathematical calculations or exhibit "hallucinations" (making up facts).
- https://github.com/EthanHenrickson/math-mcp [Basic mathematical operations]
- https://github.com/gmh5225/hex2dec-mcp [Hex to Decimal Conversion]
