#!/usr/bin/env python3
"""
IDA Pro MCP - Installer v3.0
Unified installer for all MCP clients with uv support.
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
from pathlib import Path

# ============================================================================
# Windows ANSI Color Support
# ============================================================================

def enable_ansi():
    """Enable ANSI escape codes on Windows"""
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass

enable_ansi()

# ============================================================================
# Colors
# ============================================================================

class C:
    if sys.stdout.isatty():
        RESET = "\033[0m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        BLUE = "\033[94m"
        MAGENTA = "\033[95m"
        CYAN = "\033[96m"
        WHITE = "\033[97m"
    else:
        RESET = BOLD = DIM = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""

# ============================================================================
# Simple Text Logo
# ============================================================================

LOGO = f"""
{C.CYAN}================================================================================{C.RESET}

                         {C.MAGENTA}{C.BOLD}IDA Pro MCP{C.RESET}

              {C.WHITE}AI-Powered Reverse Engineering for IDA Pro{C.RESET}

{C.CYAN}================================================================================{C.RESET}
"""

# ============================================================================
# Helpers
# ============================================================================

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def step(num, total, msg):
    print(f"\n{C.CYAN}[{num}/{total}]{C.RESET} {msg}")

def success(msg):
    print(f"       {C.GREEN}OK{C.RESET} {msg}")

def warning(msg):
    print(f"       {C.YELLOW}!!{C.RESET} {msg}")

def error(msg):
    print(f"       {C.RED}ERR{C.RESET} {msg}")

def dim(msg):
    print(f"       {C.DIM}{msg}{C.RESET}")

def get_script_dir():
    return Path(__file__).parent.absolute()

def check_uv_installed():
    """Check if uv is installed and available in PATH."""
    try:
        subprocess.run(["uv", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

# ============================================================================
# MCP Client Configuration
# ============================================================================

def get_mcp_server_config():
    """Get the MCP server configuration dict for the STDIO-based headless server."""
    script_dir = get_script_dir()
    
    # Always use ida_mcp_stdio.py - the headless STDIO server with session support
    server_script = script_dir / "ida_mcp_stdio.py"
    
    return {
        "command": sys.executable,
        "args": [str(server_script)],
        "env": {
            "IDADIR": os.environ.get("IDADIR", "")
        },
        "description": "IDA Pro reverse engineering tools: decompile, disassemble, search, types, debug"
    }

def get_mcp_config_paths():
    """Get all known MCP client config file paths"""
    home = Path.home()
    appdata = Path(os.environ.get('APPDATA', home / 'AppData' / 'Roaming'))
    localappdata = Path(os.environ.get('LOCALAPPDATA', home / 'AppData' / 'Local'))
    
    configs = {
        # --- Priority Clients ---
        "Gemini CLI": home / ".gemini" / "settings.json",
        "Antigravity": home / ".gemini" / "antigravity" / "mcp_config.json",
        "Claude Code": home / ".claude.json",
        "Codex": home / ".codex" / "config.toml", # TOML!
        "Copilot CLI": home / ".copilot" / "mcp-config.json",  # NEW: Uses 'servers' key
        
        # --- Other Clients ---
        "Claude Desktop": appdata / "Claude" / "claude_desktop_config.json",
        "Cursor": appdata / "Cursor" / "User" / "globalStorage" / "cursor.mcp" / "config.json",
        "VS Code": appdata / "Code" / "User" / "globalStorage" / "github.copilot" / "mcp.json",
        "Windsurf": home / ".windsurf" / "mcp_config.json",
        "Cline": appdata / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
        "Roo Code": appdata / "Code" / "User" / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
    }
    
    # Linux/Mac adjustments
    if os.name != 'nt':
        xdg_config = Path(os.environ.get('XDG_CONFIG_HOME', home / '.config'))
        if "Claude Desktop" in configs:
            configs["Claude Desktop"] = xdg_config / "Claude" / "claude_desktop_config.json"

        # VS Code on Linux usually ~/.config/Code/...
        configs["VS Code"] = xdg_config / "Code" / "User" / "globalStorage" / "github.copilot" / "mcp.json"

    return configs

def update_json_config(config_path: Path, server_name: str = "ida-pro-mcp", client_name: str = "") -> bool:
    """Add/Update server in a JSON config file."""
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                try:
                    config = json.load(f)
                except json.JSONDecodeError:
                    config = {}
        else:
            config = {}
        
        # Get server config
        server_config = get_mcp_server_config()
        
        # GitHub Copilot CLI uses "mcpServers" with type: stdio
        if client_name == "Copilot CLI":
            # Remove stale "servers" entry if exists
            if "servers" in config and server_name in config["servers"]:
                del config["servers"][server_name]
            if "servers" in config and not config["servers"]:
                del config["servers"]
            
            if "mcpServers" not in config:
                config["mcpServers"] = {}
            # Copilot CLI format: type "local", tools required
            copilot_config = {
                "type": "local",
                "command": server_config["command"],
                "args": server_config["args"],
                "env": server_config["env"],
                "tools": ["*"]  # Required by Copilot CLI, "*" means all tools
            }
            config["mcpServers"][server_name] = copilot_config
        else:
            # Standard clients use "mcpServers" without type field
            if "mcpServers" not in config:
                config["mcpServers"] = {}
            config["mcpServers"][server_name] = server_config
        
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        return True
    except Exception as e:
        # dim(f"Failed to update {config_path}: {e}")
        return False

def update_toml_config(config_path: Path, server_name: str = "ida-pro-mcp") -> bool:
    """Add/Update server in a TOML config file (for Codex)."""
    try:
        import tomli_w
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib # Fallback for older python if installed

        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        config = {}
        if config_path.exists():
            with open(config_path, "rb") as f:
                try:
                    config = tomllib.load(f)
                except:
                    pass
        
        # Codex structure: [mcp_servers.ida-pro-mcp] ...
        if "mcp_servers" not in config:
            config["mcp_servers"] = {}

        config["mcp_servers"][server_name] = get_mcp_server_config()
        
        with open(config_path, "wb") as f:
            tomli_w.dump(config, f)

        return True
    except ImportError:
        warning(f"tomli-w not found. Skipping TOML config for {config_path}")
        return False
    except Exception as e:
        # dim(f"Failed to update {config_path}: {e}")
        return False

def configure_client(client_name: str, config_path: Path) -> bool:
    """Configure a specific client."""
    if config_path.suffix == '.toml':
        return update_toml_config(config_path)
    else:
        return update_json_config(config_path, client_name=client_name)

# ============================================================================
# Install
# ============================================================================

def do_install():
    clear()
    print(LOGO)
    print(f"   {C.DIM}Version 3.0  |  Unified Installer{C.RESET}\n")
    
    total_steps = 4
    
    # Step 1: Check Python & UV
    step(1, total_steps, "Checking environment...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 11):
        error(f"Python 3.11+ required, found {version.major}.{version.minor}")
        return False
    success(f"Python {version.major}.{version.minor}.{version.micro}")
    
    if check_uv_installed():
        success("uv detected (will be used for execution)")
    else:
        warning("uv not found (falling back to python)")

    # Step 2: Install package
    step(2, total_steps, "Installing IDA Pro MCP package...")
    dim("This may take a moment...")
    
    script_dir = get_script_dir()
    try:
        # Always install dependencies including tomli-w
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", str(script_dir)],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            success("Package installed")
        else:
            warning("Trying with --user flag...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-e", str(script_dir), "--user"],
                capture_output=True
            )
            success("Package installed (user)")
    except Exception as e:
        error(f"Installation failed: {e}")
        return False
    
    # Step 3: Configure MCP Clients
    step(3, total_steps, "Configuring MCP clients...")
    configs = get_mcp_config_paths()
    configured = []
    
    # Priority clients to always try creating config for
    priority_clients = ["Gemini CLI", "Antigravity", "Claude Code", "Claude Desktop", "Copilot CLI"]

    for client, config_path in configs.items():
        should_try = (
            config_path.exists() or 
            config_path.parent.exists() or 
            client in priority_clients
        )
        
        if should_try:
            if configure_client(client, config_path):
                configured.append(client)
                success(f"{client}")
            else:
                dim(f"Skipped {client} (not found/write error)")

    # Step 4: Verify
    step(4, total_steps, "Verifying installation...")
    server_script = script_dir / "ida_mcp_stdio.py"
    if server_script.exists():
        success(f"ida_mcp_stdio.py found at {server_script}")
    else:
        error(f"Server script not found: {server_script}")
    
    # Summary
    print(f"""
{C.GREEN}================================================================================{C.RESET}

   {C.GREEN}Installation Complete!{C.RESET}

   {C.WHITE}Configured MCP Clients:{C.RESET}
""")
    if configured:
        for client in configured:
            print(f"      - {client}")
    else:
        print(f"      {C.DIM}(none configured){C.RESET}")

    print(f"""
   {C.WHITE}Next Steps:{C.RESET}
      1. Restart your IDE / MCP Client.
      2. Ensure IDADIR environment variable is set if IDA is not found automatically.
         (Current IDADIR: {os.environ.get('IDADIR', 'Not Set')})

{C.GREEN}================================================================================{C.RESET}
""")
    return True

# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="IDA Pro MCP Installer")
    parser.add_argument('--uninstall', '-u', action='store_true', help='Uninstall IDA Pro MCP')
    args = parser.parse_args()
    
    try:
        if args.uninstall:
            print("Uninstall not fully implemented in this version. Please verify config files manually.")
        else:
            do_install()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(1)

if __name__ == "__main__":
    main()
