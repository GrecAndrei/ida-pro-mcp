"""Loader and file operations for IDA Pro MCP.

This module provides tools for:
- Managing the IDB lifecycle (Save, Close, Open)
- File system operations (List, Read/Write auxiliary files)
- Changing working directories
"""

import os
import datetime
from typing import Annotated, Optional

import idaapi
import ida_loader
import idc
import ida_segment
import ida_bytes
import ida_ida

from .rpc import tool, unsafe
from .sync import idawrite, idaread, IDAError, IDASyncError
from .utils import FileInfo, normalize_list_input

# ============================================================================
# IDB Lifecycle
# ============================================================================

@tool
@idawrite
def save_database(
    path: Annotated[str | None, "Path to save IDB to (defaults to current)"] = None
) -> dict:
    """Save the current database.
    
    If path is provided, performs a 'Save As'.
    If path is None, performs a 'Save'.
    """
    try:
        # verify path if provided
        if path:
             # Ensure path has database extension
             if not (path.endswith('.idb') or path.endswith('.i64')):
                 path = path + ('.i64' if ida_ida.inf_is_64bit() else '.idb')
             
        # idaapi.save_database returns True on success
        # It takes specific flags or path?
        # SDK says: save_database(outfile, flags=0)
        # If outfile is None, saves to current.
        
        ok = idaapi.save_database(path, 0) if path else idaapi.save_database(None, 0)
        
        if ok:
            return {"ok": True, "path": path or idaapi.get_idb_path()}
        else:
            return {"error": "Failed to save database"}
            
    except Exception as e:
        return {"error": str(e)}


@tool
@unsafe
@idawrite
def close_database(
    save: Annotated[bool, "Save changes before closing?"] = True
) -> dict:
    """Close the current database.
    
    WARNING: This will close the current analysis session.
    The MCP connection may be terminated if the plugin unloads.
    """
    try:
        if save:
            idaapi.save_database(None, 0)
            
        idaapi.close_database(0) # 0 = don't ask
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


@tool
@unsafe
@idawrite
def open_database(
    path: Annotated[str, "Path to IDB/I64 file"]
) -> dict:
    """Open an existing database.
    
    WARNING: This will replace the current analysis session.
    The MCP connection will likely reset.
    """
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}
        
    try:
        # check if it's a database
        if not path.endswith(('.idb', '.i64')):
            return {"error": "File must be .idb or .i64. For raw binaries, start a new IDA instance."}
            
        idaapi.open_database(path, False) # False = read-write
        return {"ok": True, "status": "Opening database..."}
    except Exception as e:
        return {"error": str(e)}


@tool
@unsafe
@idawrite
def load_raw_binary(
    path: Annotated[str, "Path to binary file"],
    address: Annotated[str, "Target address (hex)"],
    seg_name: Annotated[str, "Segment name"] = "LOADED_BIN"
) -> dict:
    """Load a raw binary file into the CURRENT database at a specific address.
    
    This creates a new segment and patches the bytes from the file.
    Useful for loading raw firmware blobs, overlays, or additional data.
    """
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}
        
    try:
        # Parse address
        try:
            ea = int(address, 16)
        except:
             return {"error": f"Invalid address format: {address}"}
             
        # Read file
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            data = f.read()
            
        # Create segment
        # add_segm(start_ea, end_ea, name, class)
        # We need to calculate end_ea
        end_ea = ea + size
        
        # Check if segment exists or overlaps? 
        # ida_segment.add_segm returns bool
        if not ida_segment.add_segm(0, ea, end_ea, seg_name, "DATA"):
             return {"error": "Failed to create segment (overlap?)"}
             
        # Patch bytes
        ida_bytes.put_bytes(ea, data)
        
        return {
            "ok": True, 
            "start": hex(ea), 
            "end": hex(end_ea), 
            "size": size,
            "message": f"Loaded {size} bytes at {hex(ea)}"
        }
        
    except Exception as e:
        return {"error": str(e)}

@tool
def list_recent_files() -> list[str]:
    """List recently opened files (Windows Registry attempt)"""
    try:
        import winreg
        history = []
        # Try common IDA registry paths
        paths = [
            r"Software\Hex-Rays\IDA",
            r"Software\Hex-Rays\IDA Pro",
        ]
        
        for path in paths:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, str(path) + r"\History") as key:
                    i = 0
                    while True:
                        try:
                            # Values are named A, B, C... or 0, 1, 2?
                            # Actually it's File1, File2... usually or standard MRU
                            name, value, _ = winreg.EnumValue(key, i)
                            if isinstance(value, str) and os.path.exists(value):
                                history.append(value)
                            i += 1
                        except OSError:
                            break
            except:
                continue
                
        return sorted(list(set(history))) # Dedupe
    except:
        return []


# ============================================================================
# File System Operations
# ============================================================================

@tool
def get_working_directory() -> str:
    """Get the current working directory"""
    return os.getcwd()


@tool
def set_working_directory(
    path: Annotated[str, "New working directory path"]
) -> dict:
    """Change the current working directory"""
    try:
        os.chdir(path)
        return {"ok": True, "path": os.getcwd()}
    except Exception as e:
        return {"error": str(e)}


@tool
def list_directory(
    path: Annotated[str, "Directory path"] = "."
) -> list[FileInfo]:
    """List files in a directory"""
    try:
        entries = []
        with os.scandir(path) as it:
            for entry in it:
                info: FileInfo = {
                    "name": entry.name,
                    "path": entry.path,
                    "type": "dir" if entry.is_dir() else "file",
                    "size": entry.stat().st_size,
                    "mtime": datetime.datetime.fromtimestamp(entry.stat().st_mtime).isoformat()
                }
                entries.append(info)
        return entries
    except Exception as e:
        # Return error as a special entry or empty?
        # TypedDict enforces structure.
        # We'll rely on MCP exception propagation usually, 
        # but returning empty list + error log might be safer.
        # Let's raise to let MCP handle it.
        raise e


@tool
def file_exists(
    path: Annotated[str, "Path to check"]
) -> bool:
    """Check if a file or directory exists"""
    return os.path.exists(path)


@tool
def read_text_file(
    path: Annotated[str, "Path to file"],
    max_size: Annotated[int, "Max bytes to read"] = 1024 * 1024 # 1MB
) -> dict:
    """Read contents of a text file.
    
    Useful for reading scripts, logs, or reports.
    Restricted to 1MB by default to prevent OOM.
    """
    if not os.path.exists(path):
        return {"error": "File not found"}
        
    try:
        size = os.path.getsize(path)
        if size > max_size:
            return {"error": f"File too large ({size} > {max_size})"}
            
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            
        return {"content": content, "size": size}
    except Exception as e:
        return {"error": str(e)}


@tool
def write_text_file(
    path: Annotated[str, "Path to file"],
    content: Annotated[str, "Content to write"],
    overwrite: Annotated[bool, "Overwrite if exists"] = False
) -> dict:
    """Write text data to a file.
    
    Useful for saving scripts or reports.
    """
    if os.path.exists(path) and not overwrite:
        return {"error": "File exists and overwrite=False"}
        
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return {"ok": True, "size": len(content)}
    except Exception as e:
        return {"error": str(e)}
