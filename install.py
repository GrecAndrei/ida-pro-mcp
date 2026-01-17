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

def _ps_quote(s: str) -> str:
    return s.replace("'", "''")

def kill_processes_for_paths(paths, kill_ida=True):
    targets = [str(p) for p in paths if p]
    if sys.platform == "win32":
        for p in targets:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                f"$p='{_ps_quote(p)}'; Get-Process | Where-Object {{$_.Path -and ($_.Path -ieq $p)}} | Stop-Process -Force -ErrorAction SilentlyContinue",
            ]
            subprocess.run(cmd, capture_output=True)
        if kill_ida:
            for name in ["idat.exe", "idat64.exe", "ida.exe", "ida64.exe"]:
                subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True)
    else:
        for p in targets:
            subprocess.run(["pkill", "-f", p], capture_output=True)
        if kill_ida:
            for name in ["idat", "idat64", "ida", "ida64"]:
                subprocess.run(["pkill", "-f", name], capture_output=True)

def get_permanent_dir():
    """Get a professional permanent directory for the MCP server."""
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ida-pro-mcp"
    else:
        return Path.home() / ".local" / "share" / "ida-pro-mcp"

def get_ida_plugin_dir():
    """Find the IDA Pro plugins directory."""
    if sys.platform == "win32":
        ida_folder = Path(os.environ.get("APPDATA", "")) / "Hex-Rays" / "IDA Pro"
    else:
        ida_folder = Path.home() / ".idapro"
    return ida_folder / "plugins"

def relocate_self(dest_dir: Path):
    """Copy or upgrade the project in a permanent location."""
    src_dir = get_script_dir()
    if src_dir == dest_dir:
        return True
    
    is_upgrade = dest_dir.exists()
    action_str = "Upgrading" if is_upgrade else "Migrating"
    print(f"       {C.CYAN}>>{C.RESET} {action_str} to: {C.WHITE}{dest_dir}{C.RESET}")
    
    try:
        # Create destination if it doesn't exist
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. CORE CODE (Always replace to ensure upgrade)
        core_items = ["src", "ida_mcp_stdio.py", "pyproject.toml"]
        for item in core_items:
            s = src_dir / item
            d = dest_dir / item
            if not s.exists(): continue
            
            if s.is_dir():
                if d.exists(): shutil.rmtree(d)
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)
        
        # 2. DOCUMENTATION (Replace)
        for item in ["README.md", "LICENSE"]:
            if (src_dir / item).exists():
                shutil.copy2(src_dir / item, dest_dir / item)

        # 3. USER DATA (Preserve existing if upgrading)
        # Note: bookmarks.json and cache should stay
        if not is_upgrade:
            # First time install, setup basic folders
            (dest_dir / "ida_mcp_cache").mkdir(exist_ok=True)
        
        success(f"{action_str} successful")
        return True
    except Exception as e:
        error(f"{action_str} failed: {e}")
        return False

def check_uv_installed():
    """Check if uv is installed."""
    try:
        subprocess.run(["uv", "--version"], capture_output=True, check=True)
        return True
    except:
        return False

def get_mcp_server_config(install_path: Path):
    """Get the MCP server configuration pointing to the permanent venv python."""
    if sys.platform == "win32":
        python_exe = install_path / ".venv" / "Scripts" / "python.exe"
    else:
        python_exe = install_path / ".venv" / "bin" / "python"
    
    server_script = install_path / "ida_mcp_stdio.py"
    
    return {
        "command": str(python_exe),
        "args": ["-u", str(server_script)],
        "env": {
            "IDADIR": os.environ.get("IDADIR", "")
        },
        "description": "IDA Pro Forensic Intelligence Engine"
    }

def setup_virtualenv(install_path: Path):
    """Create a high-performance virtual environment at the destination."""     
    print(f"       {C.CYAN}>>{C.RESET} Setting up optimized environment...")
    venv_dir = install_path / ".venv"
    venv_python = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    try:
        # Force clean start to avoid interactive prompts
        if venv_dir.exists():
            try:
                shutil.rmtree(venv_dir)
            except Exception:
                kill_processes_for_paths([venv_python], kill_ida=False)
                shutil.rmtree(venv_dir)

        if check_uv_installed():
            subprocess.run(["uv", "venv", ".venv"], cwd=install_path, capture_output=True, check=True)
            # Install core dependencies into the permanent venv
            subprocess.run(["uv", "pip", "install", "idapro", "yara-python", "requests", "tomli-w", "-e", "."], 
                           cwd=install_path, capture_output=True, check=True)
        else:
            subprocess.run([sys.executable, "-m", "venv", ".venv"], cwd=install_path, capture_output=True, check=True)
            pip_exe = install_path / (".venv/Scripts/pip.exe" if sys.platform == "win32" else ".venv/bin/pip")
            subprocess.run([str(pip_exe), "install", "idapro", "yara-python", "requests", "tomli-w", "-e", "."], 
                           cwd=install_path, capture_output=True, check=True)
        success("Environment optimized")
        return True
    except Exception as e:
        error(f"Environment setup failed: {e}")
        return False

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
        "Copilot CLI": home / ".copilot" / "mcp-config.json",
        "OpenCode": home / ".config" / "opencode" / "opencode.json", # JSONC format
        
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

def update_json_config(config_path: Path, server_name: str = "ida-pro-mcp", client_name: str = "", install_path: Path = None) -> bool:
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
        server_config = get_mcp_server_config(install_path)
        
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

def update_toml_config(config_path: Path, server_name: str = "ida-pro-mcp", install_path: Path = None) -> bool:
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

        config["mcp_servers"][server_name] = get_mcp_server_config(install_path)
        
        with open(config_path, "wb") as f:
            tomli_w.dump(config, f)

        return True
    except ImportError:
        warning(f"tomli-w not found. Skipping TOML config for {config_path}")
        return False
    except Exception as e:
        # dim(f"Failed to update {config_path}: {e}")
        return False

def update_opencode_config(config_path: Path, server_name: str = "ida-pro-mcp", install_path: Path = None) -> bool:
    """Add/Update server in OpenCode config file (uses MCP schema)."""
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Strip comments for parsing (JSONC support)
                import re
                # Remove single-line comments
                content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
                # Remove multi-line comments
                content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
                try:
                    config = json.loads(content)
                except json.JSONDecodeError:
                    config = {}
        else:
            config = {}
        
        # OpenCode schema: "mcp": { "server-name": { "type": "local", "command": [...], "enabled": true } }
        if "mcp" not in config:
            config["mcp"] = {}
        
        server_config = get_mcp_server_config(install_path)
        
        # Transform to OpenCode's local MCP format
        opencode_config = {
            "type": "local",
            "command": [server_config["command"]] + server_config["args"],
            "enabled": True,
            "environment": server_config.get("env", {})
        }
        
        config["mcp"][server_name] = opencode_config
        
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        return True
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
    print(f"   {C.DIM}Version 3.1  |  Professional Migration Edition{C.RESET}\n")
    
    total_steps = 6
    script_dir = get_script_dir()
    perm_dir = get_permanent_dir()
    
    # Step 1: Migration Check
    step(1, total_steps, "Analyzing location...")
    is_temp = any(x in str(script_dir).lower() for x in ["download", "temp", "tmp", "desktop"])
    
    if is_temp:
        warning(f"Running from temporary location: {C.WHITE}{script_dir.name}{C.RESET}")
        if relocate_self(perm_dir):
            install_path = perm_dir
        else:
            warning("Staying in current location due to migration error.")
            install_path = script_dir
    else:
        success(f"Running from stable location: {C.WHITE}{script_dir}{C.RESET}")
        install_path = script_dir

    # Step 2: Check Python & UV
    step(2, total_steps, "Checking environment...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 11):
        error(f"Python 3.11+ required, found {version.major}.{version.minor}")
        return False
    success(f"Python {version.major}.{version.minor}.{version.micro}")
    
    if check_uv_installed():
        success("uv detected (will be used for execution)")
    else:
        warning("uv not found (falling back to python)")

    # Step 3: Install package & Venv
    step(3, total_steps, "Installing IDA Pro MCP environment...")
    dim("This may take a moment...")
    dim("Stopping running IDA/IDAT processes to prevent file locks...")
    kill_processes_for_paths([], kill_ida=True)
    if not setup_virtualenv(install_path):
        return False
    
    # Step 4: Configure MCP Clients
    step(4, total_steps, "Configuring MCP clients...")
    configs = get_mcp_config_paths()
    configured = []
    
    # Pass the install_path to get correct config
    def configure_with_path(client, path):
        if client == "OpenCode":
            return update_opencode_config(path, install_path=install_path)
        elif path.suffix == '.toml':
            return update_toml_config(path, install_path=install_path)
        else:
            return update_json_config(path, client_name=client, install_path=install_path)

    priority_clients = ["Gemini CLI", "Antigravity", "Claude Code", "Claude Desktop", "Copilot CLI", "OpenCode"]

    for client, config_path in configs.items():
        if config_path.exists() or config_path.parent.exists() or client in priority_clients:
            if configure_with_path(client, config_path):
                configured.append(client)
                success(f"{client}")

    # Step 5: Install IDA Plugin
    step(5, total_steps, "Installing IDA Pro plugin...")
    ida_plugin_dir = get_ida_plugin_dir()
    plugin_installed = False
    
    if ida_plugin_dir.parent.exists():  # Check if IDA config folder exists
        try:
            ida_plugin_dir.mkdir(parents=True, exist_ok=True)
            
            # Source files
            src_loader = install_path / "src" / "ida_pro_mcp" / "ida_mcp.py"
            src_pkg = install_path / "src" / "ida_pro_mcp" / "ida_mcp"
            
            # Destination
            dst_loader = ida_plugin_dir / "ida_mcp.py"
            dst_pkg = ida_plugin_dir / "ida_mcp"
            
            # Install loader
            if src_loader.exists():
                if dst_loader.exists() or dst_loader.is_symlink():
                    dst_loader.unlink()
                try:
                    os.symlink(src_loader, dst_loader)
                except OSError:
                    shutil.copy2(src_loader, dst_loader)
                success(f"Plugin loader: {dst_loader}")
            
            # Install package
            if src_pkg.exists():
                if dst_pkg.exists():
                    if dst_pkg.is_symlink():
                        dst_pkg.unlink()
                    else:
                        shutil.rmtree(dst_pkg)
                try:
                    os.symlink(src_pkg, dst_pkg, target_is_directory=True)
                except OSError:
                    shutil.copytree(src_pkg, dst_pkg)
                success(f"Plugin package: {dst_pkg}")
            
            plugin_installed = True
        except Exception as e:
            warning(f"Plugin install failed: {e}")
    else:
        warning("IDA Pro config folder not found. Install IDA Pro first, then re-run installer.")

    # Step 6: Verify
    step(6, total_steps, "Verifying installation...")
    server_script = install_path / "ida_mcp_stdio.py"
    if server_script.exists():
        success(f"Active server at: {server_script}")
    else:
        error(f"Server script not found!")
    
    # Summary
    print(f"""
{C.GREEN}================================================================================{C.RESET}

   {C.GREEN}Installation Complete!{C.RESET}

   {C.WHITE}Deployed Components:{C.RESET}
      - {C.CYAN}MCP Server{C.RESET} (headless host for IDEs)
      - {C.CYAN}IDA Plugin{C.RESET} {'(installed)' if plugin_installed else '(not installed - IDA not found)'}

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
      2. In IDA Pro, enable the plugin via Edit -> Plugins -> MCP (Ctrl+Alt+M)

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
