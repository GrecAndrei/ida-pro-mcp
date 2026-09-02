# IDA Pro MCP v1.0.0a1

The first alpha release of **IDA Pro MCP** connects AI coding agents directly to Hex-Rays IDA Pro for deterministic reverse engineering, decompilation, and binary analysis.

### Highlights
- **107 Public Agent Operations (`ida_*`)**: Action-specific, strict-schema capabilities covering Hex-Rays decompilation, cross-references, type management, and firmware analysis.
- **Dual-Engine Isolation**: Headless multi-process `idat` engine with automatic crash recovery, alongside an in-process `idalib` kernel for IDA 9.3+.
- **22+ Supported Agent Environments**: Built-in configuration for Cursor, Claude Code, OpenClaw, Pi Coding Agent, Hermes Agent, Prime Agent, VS Code, Codex, ZCode, Kimi Code, and MiniMax Code.
- **Progressive Disclosure Skills**: Standardized `.agents/skills/ida-pro-mcp/` specification minimizing context window bloat.
- **Automated Installer**: Single-command setup with `--auto` and clean uninstallation with `--uninstall`.

### Quick Install

From the extracted release bundle or repository:

```bash
python install.py --auto
```

### Links
- 📖 [Official Wiki & Guides](https://github.com/GrecAndrei/ida-pro-mcp/wiki)
- 📋 [Operations Reference](docs/TOOLS_REFERENCE.md)
- 🔒 [Safety & Mutation Policy](docs/guide/safety-model.md)
