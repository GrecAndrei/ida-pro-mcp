#!/usr/bin/env python3
"""
IDA Pro MCP - Installer v2.2
Full-featured installer with auto-configuration and uninstall support
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
# Simple Text Logo (no Unicode issues)
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

# ============================================================================
# MCP Client Configuration
# ============================================================================

def get_mcp_server_config():
    """Get the MCP server configuration dict"""
    return {
        "command": "uv",
        "args": ["run", "--directory", str(get_script_dir()), "ida-pro-mcp"],
    }

def get_mcp_config_paths():
    """Get all known MCP client config file paths"""
    home = Path.home()
    appdata = Path(os.environ.get('APPDATA', home / 'AppData' / 'Roaming'))
    localappdata = Path(os.environ.get('LOCALAPPDATA', home / 'AppData' / 'Local'))
    
    # All use standard mcpServers format
    configs = {
        # Google Antigravity - PRIORITY
        "Antigravity": home / ".gemini" / "antigravity" / "mcp_config.json",
        
        # Claude Desktop
        "Claude": appdata / "Claude" / "claude_desktop_config.json",
        
        # Cursor
        "Cursor": appdata / "Cursor" / "User" / "globalStorage" / "cursor.mcp" / "config.json",
        
        # VS Code (Copilot MCP extension)
        "VS Code": appdata / "Code" / "User" / "globalStorage" / "github.copilot" / "mcp.json",
        
        # Windsurf
        "Windsurf": home / ".windsurf" / "mcp_config.json",
        
        # Cline
        "Cline": appdata / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
        
        # Roo Code
        "Roo Code": appdata / "Code" / "User" / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
    }
    
    # Linux paths
    if os.name != 'nt':
        xdg_config = Path(os.environ.get('XDG_CONFIG_HOME', home / '.config'))
        configs["Claude (Linux)"] = xdg_config / "Claude" / "claude_desktop_config.json"
    
    return configs

def add_to_mcp_config(config_path: Path, server_name: str = "ida-pro-mcp") -> bool:
    """Add IDA Pro MCP to an MCP client config file, cleaning up duplicates"""
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing config or create new
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                try:
                    config = json.load(f)
                except json.JSONDecodeError:
                    config = {}
        else:
            config = {}
        
        # Clean up: Remove from "servers" if exists (wrong location)
        if "servers" in config and server_name in config["servers"]:
            del config["servers"][server_name]
            # Remove empty servers dict
            if not config["servers"]:
                del config["servers"]
        
        # Ensure mcpServers section exists
        if "mcpServers" not in config:
            config["mcpServers"] = {}
        
        # Add/update our server in correct location
        config["mcpServers"][server_name] = get_mcp_server_config()
        
        # Write back with proper formatting
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        return True
    except Exception as e:
        return False

def remove_from_mcp_config(config_path: Path, server_name: str = "ida-pro-mcp") -> bool:
    """Remove IDA Pro MCP from an MCP client config file"""
    try:
        if not config_path.exists():
            return True
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        modified = False
        
        # Remove from mcpServers
        if "mcpServers" in config and server_name in config["mcpServers"]:
            del config["mcpServers"][server_name]
            modified = True
        
        # Also clean up from "servers" if it was there
        if "servers" in config and server_name in config["servers"]:
            del config["servers"][server_name]
            if not config["servers"]:
                del config["servers"]
            modified = True
        
        if modified:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
        
        return True
    except Exception as e:
        return False

# ============================================================================
# IDA Plugin Installation
# ============================================================================

def get_ida_plugin_paths():
    """Get common IDA plugin directory paths"""
    home = Path.home()
    appdata = Path(os.environ.get('APPDATA', ''))
    programfiles = Path(os.environ.get('PROGRAMFILES', ''))
    
    paths = []
    
    if os.name == 'nt':
        paths = [
            appdata / "Hex-Rays" / "IDA Pro" / "plugins",
            programfiles / "IDA Pro 9.0" / "plugins",
            programfiles / "IDA Pro 8.4" / "plugins", 
            programfiles / "IDA Pro 8.3" / "plugins",
            home / "ida" / "plugins",
        ]
    else:
        paths = [
            home / ".idapro" / "plugins",
            home / "ida" / "plugins",
            Path("/opt/ida/plugins"),
            Path("/opt/idapro/plugins"),
        ]
    
    return paths

def install_ida_plugin():
    """Install the IDA plugin (loader + module folder)"""
    script_dir = get_script_dir()
    plugin_loader = script_dir / "src" / "ida_pro_mcp" / "ida_mcp.py"
    plugin_module = script_dir / "src" / "ida_pro_mcp" / "ida_mcp"  # The folder
    
    if not plugin_loader.exists():
        return None, f"Plugin loader not found: {plugin_loader}"
    
    if not plugin_module.exists():
        return None, f"Plugin module not found: {plugin_module}"
    
    installed_paths = []
    
    for ida_dir in get_ida_plugin_paths():
        if ida_dir.exists():
            try:
                # Copy the loader file
                shutil.copy(plugin_loader, ida_dir / "ida_mcp.py")
                
                # Copy the module folder (remove old one first)
                dest_module = ida_dir / "ida_mcp"
                if dest_module.exists():
                    shutil.rmtree(dest_module)
                shutil.copytree(plugin_module, dest_module)
                
                installed_paths.append(str(ida_dir))
            except Exception as e:
                pass
    
    if installed_paths:
        return installed_paths, None
    else:
        return None, "No writable IDA plugins folder found"

def uninstall_ida_plugin():
    """Remove the IDA plugin (loader + module folder)"""
    removed = []
    
    for ida_dir in get_ida_plugin_paths():
        plugin_loader = ida_dir / "ida_mcp.py"
        plugin_module = ida_dir / "ida_mcp"
        
        removed_any = False
        
        if plugin_loader.exists():
            try:
                plugin_loader.unlink()
                removed_any = True
            except:
                pass
        
        if plugin_module.exists():
            try:
                shutil.rmtree(plugin_module)
                removed_any = True
            except:
                pass
        
        if removed_any:
            removed.append(str(ida_dir))
    
    return removed

# ============================================================================
# Install
# ============================================================================

def do_install():
    clear()
    print(LOGO)
    print(f"   {C.DIM}Version 2.2  |  Installer{C.RESET}\n")
    
    total_steps = 5
    
    # Step 1: Check Python
    step(1, total_steps, "Checking Python installation...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 11):
        error(f"Python 3.11+ required, found {version.major}.{version.minor}")
        return False
    success(f"Python {version.major}.{version.minor}.{version.micro}")
    
    # Step 2: Install package
    step(2, total_steps, "Installing IDA Pro MCP package...")
    dim("This may take a moment...")
    
    script_dir = get_script_dir()
    try:
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
    
    # Step 3: Install IDA Plugin
    step(3, total_steps, "Installing IDA Plugin...")
    paths, err = install_ida_plugin()
    if paths:
        for p in paths:
            success(f"Installed to {p}")
    else:
        warning(err)
        dim("Copy src/ida_pro_mcp/ida_mcp.py to your IDA plugins folder manually")
    
    # Step 4: Configure MCP Clients
    step(4, total_steps, "Configuring MCP clients...")
    configs = get_mcp_config_paths()
    configured = []
    
    for client, config_path in configs.items():
        # Configure if file exists OR parent exists OR it's priority client
        should_try = (
            config_path.exists() or 
            config_path.parent.exists() or 
            client in ["Claude", "Antigravity"]
        )
        
        if should_try:
            if add_to_mcp_config(config_path):
                configured.append(client)
                success(f"{client}")
    
    if not configured:
        warning("No MCP clients detected")
        dim("Run 'ida-pro-mcp --config' to get manual config")
    
    # Step 5: Verify
    step(5, total_steps, "Verifying installation...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "ida_pro_mcp", "--help"],
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            success("ida-pro-mcp command available")
        else:
            warning("Command may need PATH update")
    except:
        warning("Could not verify command")
    
    # Success message
    print(f"""
{C.GREEN}================================================================================{C.RESET}

   {C.GREEN}Installation Complete!{C.RESET}

   {C.WHITE}Configured MCP Clients:{C.RESET}
""")
    
    if configured:
        for client in configured:
            print(f"      - {client}")
    else:
        print(f"      {C.DIM}(none auto-detected){C.RESET}")
    
    print(f"""
   {C.WHITE}Next Steps:{C.RESET}

      1. Restart IDA Pro and your MCP client
      2. Load a binary in IDA
      3. Edit > Plugins > MCP (or Ctrl+Alt+M)
      4. Start reversing with AI!

   {C.WHITE}Uninstall:{C.RESET} python install.py --uninstall

{C.GREEN}================================================================================{C.RESET}
""")
    return True

# ============================================================================
# Uninstall
# ============================================================================

def do_uninstall():
    clear()
    print(LOGO)
    print(f"   {C.DIM}Version 2.2  |  Uninstaller{C.RESET}\n")
    
    total_steps = 3
    
    # Step 1: Remove from MCP configs
    step(1, total_steps, "Removing from MCP client configurations...")
    configs = get_mcp_config_paths()
    removed_configs = []
    
    for client, config_path in configs.items():
        if config_path.exists():
            if remove_from_mcp_config(config_path):
                removed_configs.append(client)
                success(f"Removed from {client}")
    
    if not removed_configs:
        dim("No MCP configurations found")
    
    # Step 2: Remove IDA plugin
    step(2, total_steps, "Removing IDA plugin...")
    removed_plugins = uninstall_ida_plugin()
    
    if removed_plugins:
        for p in removed_plugins:
            success(f"Removed from {p}")
    else:
        dim("No IDA plugins found to remove")
    
    # Step 3: Uninstall package
    step(3, total_steps, "Uninstalling Python package...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "uninstall", "ida-pro-mcp", "-y"],
            capture_output=True
        )
        success("Package uninstalled")
    except:
        warning("Could not uninstall package (may not be installed)")
    
    print(f"""
{C.GREEN}================================================================================{C.RESET}

   {C.GREEN}Uninstall Complete!{C.RESET}

   IDA Pro MCP has been removed from your system.
   Thanks for using IDA Pro MCP!

{C.GREEN}================================================================================{C.RESET}
""")
    return True

# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="IDA Pro MCP Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--uninstall', '-u',
        action='store_true',
        help='Uninstall IDA Pro MCP'
    )
    
    args = parser.parse_args()
    
    try:
        if args.uninstall:
            result = do_uninstall()
        else:
            result = do_install()
        
        input("\nPress Enter to exit...")
        sys.exit(0 if result else 1)
        
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}Cancelled by user.{C.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{C.RED}Error: {e}{C.RESET}")
        input("\nPress Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    main()
