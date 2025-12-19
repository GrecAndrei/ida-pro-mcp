#!/usr/bin/env python3
"""
IDA Pro MCP Installer for Google Antigravity IDE

This script:
1. Detects IDA Pro installation
2. Updates Antigravity's mcp_config.json with IDA MCP server entry
3. Creates startup scripts if needed

Usage:
    python install_antigravity.py
    python install_antigravity.py --ida-dir "C:/Program Files/IDA Pro 9.2"
"""

import json
import os
import sys
import argparse
from pathlib import Path


def find_ida_dir() -> str:
    """Find IDA Pro installation directory."""
    # Check environment variable first
    if os.environ.get("IDADIR"):
        return os.environ["IDADIR"]
    
    # Common Windows paths
    candidates = [
        r"C:\Program Files\IDA Professional 9.2",
        r"C:\Program Files\IDA Pro 9.2",
        r"C:\Program Files\IDA Professional 9.0",
        r"C:\Program Files\IDA Pro 9.0",
        r"C:\Program Files (x86)\IDA Pro",
    ]
    
    for path in candidates:
        if os.path.exists(path):
            # Verify idat.exe exists
            if os.path.exists(os.path.join(path, "idat.exe")) or \
               os.path.exists(os.path.join(path, "idat64.exe")):
                return path
    
    return ""


def find_antigravity_config() -> Path:
    """Find Antigravity's mcp_config.json."""
    home = Path.home()
    
    # Standard location for Antigravity
    config_path = home / ".gemini" / "antigravity" / "mcp_config.json"
    
    if config_path.exists():
        return config_path
    
    # Check if .gemini/antigravity directory exists
    config_dir = home / ".gemini" / "antigravity"
    if config_dir.exists():
        # Create empty config if it doesn't exist
        return config_path
    
    return config_path  # Return expected path anyway


def get_mcp_entry(script_path: str, ida_dir: str) -> dict:
    """Generate MCP server entry for IDA Pro."""
    return {
        "type": "stdio",
        "command": "python",
        "args": [script_path],
        "env": {
            "IDADIR": ida_dir
        }
    }


def install():
    """Main installation function."""
    parser = argparse.ArgumentParser(description="Install IDA Pro MCP for Antigravity IDE")
    parser.add_argument("--ida-dir", help="Path to IDA Pro installation")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    args = parser.parse_args()
    
    print("=" * 60)
    print("IDA Pro MCP Installer for Google Antigravity IDE")
    print("=" * 60)
    print()
    
    # Find IDA directory
    ida_dir = args.ida_dir or find_ida_dir()
    
    if not ida_dir:
        print("ERROR: Could not find IDA Pro installation.")
        print("Please specify with --ida-dir or set IDADIR environment variable.")
        print()
        print("Example:")
        print('  python install_antigravity.py --ida-dir "C:\\Program Files\\IDA Professional 9.2"')
        return False
    
    print(f"✓ IDA Pro found: {ida_dir}")
    
    # Get script path
    script_dir = Path(__file__).parent.absolute()
    stdio_script = script_dir / "ida_mcp_stdio.py"
    
    if not stdio_script.exists():
        print(f"ERROR: Could not find {stdio_script}")
        return False
    
    print(f"✓ MCP server script: {stdio_script}")
    
    # Find Antigravity config
    config_path = find_antigravity_config()
    print(f"✓ Antigravity config: {config_path}")
    
    # Load existing config or create new one
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except json.JSONDecodeError:
            print("WARNING: Existing config is invalid, creating new one")
            config = {}
    else:
        config = {}
    
    # Ensure mcpServers exists
    if "mcpServers" not in config:
        config["mcpServers"] = {}
    
    # Add IDA Pro MCP entry
    ida_entry = get_mcp_entry(str(stdio_script), ida_dir)
    
    # Check if already exists
    if "ida-pro-mcp" in config["mcpServers"]:
        existing = config["mcpServers"]["ida-pro-mcp"]
        if existing == ida_entry:
            print("✓ IDA Pro MCP already configured correctly")
        else:
            print("⚠ Updating existing IDA Pro MCP configuration")
            config["mcpServers"]["ida-pro-mcp"] = ida_entry
    else:
        print("→ Adding IDA Pro MCP to configuration")
        config["mcpServers"]["ida-pro-mcp"] = ida_entry
    
    # Preview changes
    print()
    print("Configuration to be written:")
    print("-" * 40)
    print(json.dumps({"ida-pro-mcp": ida_entry}, indent=2))
    print("-" * 40)
    print()
    
    if args.dry_run:
        print("DRY RUN: No changes made")
        return True
    
    # Ensure directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write config
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✓ Configuration written to {config_path}")
    except Exception as e:
        print(f"ERROR: Failed to write config: {e}")
        return False
    
    # Create cache directory
    cache_dir = Path.home() / ".ida_mcp_cache"
    cache_dir.mkdir(exist_ok=True)
    print(f"✓ Cache directory: {cache_dir}")
    
    print()
    print("=" * 60)
    print("Installation complete!")
    print("=" * 60)
    print()
    print("The IDA Pro MCP server is now available in Antigravity IDE.")
    print()
    print("Usage example:")
    print('  Use the "idb" tool with action="meta" to get IDB info')
    print('  Use the "code" tool with action="decompile" to decompile functions')
    print('  Use the "data" tool with action="functions" to list functions')
    print()
    print("Available tools:")
    print("  idb, code, data, search, types, memory, modify, misc,")
    print("  funcs, segments, files, plugins, trace, fixups, data_ops,")
    print("  agent, microcode, graph, bulk")
    print()
    
    return True


if __name__ == "__main__":
    success = install()
    sys.exit(0 if success else 1)
