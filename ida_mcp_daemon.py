#!/usr/bin/env python3
"""
IDA MCP Daemon - Standalone Background Service

Runs WITHOUT IDA GUI. Auto-spawns idat.exe workers for analysis.
Features:
- Multi-session management
- IDB caching (loads existing .i64/.idb instantly)
- Parallel analysis when possible
- Error handling and recovery
- Background operation

Usage:
    python ida_mcp_daemon.py                    # Start daemon
    python ida_mcp_daemon.py --port 13337       # Custom port
    python ida_mcp_daemon.py --ida-dir "C:/..."  # Custom IDA path

Environment:
    IDADIR - Path to IDA installation (auto-detected if not set)
"""

import os
import sys
import json
import time
import subprocess
import threading
import hashlib
import argparse
import logging
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ida-mcp-daemon")

# =============================================================================
# Configuration
# =============================================================================

@dataclass
class DaemonConfig:
    host: str = "127.0.0.1"
    port: int = 13337
    ida_dir: str = ""
    cache_dir: str = ""
    max_workers: int = 4
    analysis_timeout: int = 300  # 5 min for fresh analysis
    cache_timeout: int = 60     # 1 min for cached load

    def __post_init__(self):
        # Auto-detect IDA directory
        if not self.ida_dir:
            self.ida_dir = os.environ.get("IDADIR", "")
        
        if not self.ida_dir:
            # Common paths
            candidates = [
                r"C:\Program Files\IDA Professional 9.2",
                r"C:\Program Files\IDA Pro 9.2",
                r"C:\Program Files\IDA Professional 9.0",
                r"C:\Program Files (x86)\IDA Pro",
                "/opt/ida",
                "/Applications/IDA Pro.app/Contents/MacOS",
            ]
            for c in candidates:
                if os.path.exists(c):
                    self.ida_dir = c
                    break
        
        if not self.cache_dir:
            self.cache_dir = os.path.join(os.path.expanduser("~"), ".ida_mcp_cache")
        
        os.makedirs(self.cache_dir, exist_ok=True)

# =============================================================================
# Session Manager
# =============================================================================

@dataclass
class AnalysisResult:
    path: str
    success: bool
    cached: bool = False
    functions: int = 0
    strings: int = 0
    md5: str = ""
    error: str = ""
    analysis_time: float = 0.0

class SessionManager:
    def __init__(self, config: DaemonConfig):
        self.config = config
        self.sessions: Dict[str, AnalysisResult] = {}
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=config.max_workers)
        
        # Find idat executable
        self.idat_exe = self._find_idat()
        if not self.idat_exe:
            raise RuntimeError(f"idat executable not found in {config.ida_dir}")
        
        logger.info(f"Using idat: {self.idat_exe}")
        logger.info(f"Cache dir: {config.cache_dir}")
    
    def _find_idat(self) -> Optional[str]:
        """Find idat.exe (text-mode IDA for scripting)"""
        candidates = ["idat.exe", "idat64.exe", "idat"] if os.name == "nt" else ["idat64", "idat"]
        for cand in candidates:
            path = os.path.join(self.config.ida_dir, cand)
            if os.path.exists(path):
                return path
        return None
    
    def _get_cache_path(self, filepath: str) -> str:
        """Get cache file path for a given input file"""
        file_hash = hashlib.md5(filepath.encode()).hexdigest()[:16]
        return os.path.join(self.config.cache_dir, f"{file_hash}.json")
    
    def _check_idb_exists(self, filepath: str) -> Optional[str]:
        """Check if IDB already exists for this file"""
        # IDA names IDBs as: filename.exe.i64 OR filename.i64
        # Check both patterns
        for ext in ['.i64', '.idb']:
            # Pattern 1: file.exe.i64
            idb_path = filepath + ext
            if os.path.exists(idb_path):
                return idb_path
            # Pattern 2: file.i64 (strip original extension)
            base = os.path.splitext(filepath)[0]
            idb_path2 = base + ext
            if os.path.exists(idb_path2):
                return idb_path2
        return None
    
    def _load_cached_result(self, filepath: str) -> Optional[AnalysisResult]:
        """Load cached analysis result if available and fresh"""
        cache_path = self._get_cache_path(filepath)
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    data = json.load(f)
                # Check if source file hasn't changed
                if os.path.exists(filepath):
                    file_mtime = os.path.getmtime(filepath)
                    cache_mtime = data.get("mtime", 0)
                    if file_mtime <= cache_mtime:
                        return AnalysisResult(**{k: v for k, v in data.items() if k != "mtime"})
            except Exception as e:
                logger.warning(f"Failed to load cache for {filepath}: {e}")
        return None
    
    def _save_cached_result(self, filepath: str, result: AnalysisResult):
        """Save analysis result to cache"""
        cache_path = self._get_cache_path(filepath)
        try:
            data = asdict(result)
            data["mtime"] = os.path.getmtime(filepath) if os.path.exists(filepath) else time.time()
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save cache for {filepath}: {e}")
    
    def analyze_file(self, filepath: str, force_fresh: bool = False) -> AnalysisResult:
        """Analyze a single file, using cache when possible"""
        start_time = time.time()
        
        if not os.path.exists(filepath):
            return AnalysisResult(path=filepath, success=False, error="File not found")
        
        # Check result cache first
        if not force_fresh:
            cached = self._load_cached_result(filepath)
            if cached:
                cached.cached = True
                logger.info(f"Cache hit: {filepath}")
                return cached
        
        # Check if IDB exists
        idb_path = self._check_idb_exists(filepath)
        target = idb_path or filepath
        timeout = self.config.cache_timeout if idb_path else self.config.analysis_timeout
        
        # Create analysis script
        output_file = os.path.join(self.config.cache_dir, f"result_{os.getpid()}_{threading.get_ident()}.json")
        
        # Escape backslashes for Windows paths
        escaped_filepath = filepath.replace('\\', '\\\\')
        escaped_output = output_file.replace('\\', '\\\\')
        
        script = f'''import json
import idautils
import idc
import ida_pro

try:
    func_count = len(list(idautils.Functions()))
    string_count = len(list(idautils.Strings()))
    md5 = idc.retrieve_input_file_md5().hex() if hasattr(idc, 'retrieve_input_file_md5') else ""
    result = {{"path": idc.get_input_file_path(), "success": True, "functions": func_count, "strings": string_count, "md5": md5}}
except Exception as e:
    result = {{"path": "{escaped_filepath}", "success": False, "error": str(e)}}

with open("{escaped_output}", "w") as f:
    json.dump(result, f)

ida_pro.qexit(0)
'''
        
        script_file = os.path.join(self.config.cache_dir, f"script_{os.getpid()}_{threading.get_ident()}.py")
        
        try:
            with open(script_file, 'w', encoding='utf-8') as f:
                f.write(script)
            
            cmd = [self.idat_exe, "-A", f"-S{script_file}", target]
            logger.info(f"Analyzing: {filepath} (cached IDB: {bool(idb_path)})")
            logger.debug(f"Command: {' '.join(cmd)}")
            
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
            
            logger.debug(f"Return code: {proc.returncode}")
            logger.debug(f"Stdout: {proc.stdout[:200] if proc.stdout else 'empty'}")
            logger.debug(f"Stderr: {proc.stderr[:200] if proc.stderr else 'empty'}")
            logger.debug(f"Output file exists: {os.path.exists(output_file)}")
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)
                
                result = AnalysisResult(
                    path=filepath,
                    success=data.get("success", False),
                    cached=bool(idb_path),
                    functions=data.get("functions", 0),
                    strings=data.get("strings", 0),
                    md5=data.get("md5", ""),
                    error=data.get("error", ""),
                    analysis_time=time.time() - start_time
                )
                
                # Save to cache
                self._save_cached_result(filepath, result)
                
                with self.lock:
                    self.sessions[filepath] = result
                
                return result
            else:
                return AnalysisResult(
                    path=filepath, 
                    success=False, 
                    error="Analysis produced no output",
                    analysis_time=time.time() - start_time
                )
        
        except subprocess.TimeoutExpired:
            return AnalysisResult(
                path=filepath,
                success=False,
                error=f"Analysis timed out ({timeout}s)",
                analysis_time=time.time() - start_time
            )
        except Exception as e:
            return AnalysisResult(
                path=filepath,
                success=False,
                error=str(e),
                analysis_time=time.time() - start_time
            )
        finally:
            # Cleanup temporary files
            for f in [script_file, output_file]:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except:
                    pass
    
    def analyze_batch(self, paths: List[str], force_fresh: bool = False) -> Dict[str, Any]:
        """Analyze multiple files in parallel"""
        start_time = time.time()
        results = []
        
        # Submit all analysis jobs
        futures = {
            self.executor.submit(self.analyze_file, p, force_fresh): p 
            for p in paths
        }
        
        # Collect results as they complete
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(asdict(result))
            except Exception as e:
                path = futures[future]
                results.append({"path": path, "success": False, "error": str(e)})
        
        return {
            "total": len(paths),
            "success": len([r for r in results if r.get("success")]),
            "cached": len([r for r in results if r.get("cached")]),
            "failed": len([r for r in results if not r.get("success")]),
            "total_time": time.time() - start_time,
            "results": results
        }
    
    def get_sessions(self) -> Dict[str, Any]:
        """Get all tracked sessions"""
        with self.lock:
            return {
                "count": len(self.sessions),
                "sessions": [asdict(s) for s in self.sessions.values()]
            }

# =============================================================================
# HTTP Server (Simple MCP-like interface)
# =============================================================================

class MCPHandler(BaseHTTPRequestHandler):
    manager: SessionManager = None
    
    def log_message(self, format, *args):
        logger.debug(f"{self.address_string()} - {format % args}")
    
    def send_json(self, data: dict, status: int = 200):
        response = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response))
        self.end_headers()
        self.wfile.write(response)
    
    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode() if content_length else ""
            request = json.loads(body) if body else {}
            
            action = request.get("action", "")
            
            if action == "analyze":
                path = request.get("path", "")
                if not path:
                    self.send_json({"error": "path required"}, 400)
                    return
                
                result = self.manager.analyze_file(path, request.get("force_fresh", False))
                self.send_json(asdict(result))
            
            elif action == "batch":
                paths = request.get("paths", [])
                directory = request.get("directory", "")
                
                if directory:
                    if os.path.isdir(directory):
                        for f in os.listdir(directory):
                            full = os.path.join(directory, f)
                            if os.path.isfile(full):
                                ext = os.path.splitext(f)[1].lower()
                                if ext in ['.exe', '.dll', '.so', '.dylib', '.bin', '.elf', '']:
                                    paths.append(full)
                
                if not paths:
                    self.send_json({"error": "paths or directory required"}, 400)
                    return
                
                result = self.manager.analyze_batch(paths, request.get("force_fresh", False))
                self.send_json(result)
            
            elif action == "sessions":
                self.send_json(self.manager.get_sessions())
            
            elif action == "status":
                self.send_json({
                    "status": "running",
                    "idat": self.manager.idat_exe,
                    "cache_dir": self.manager.config.cache_dir,
                    "sessions": len(self.manager.sessions)
                })
            
            else:
                self.send_json({"error": f"Unknown action: {action}"}, 400)
        
        except Exception as e:
            logger.exception("Error handling request")
            self.send_json({"error": str(e)}, 500)
    
    def do_GET(self):
        """Health check"""
        self.send_json({
            "status": "running",
            "service": "ida-mcp-daemon",
            "sessions": len(self.manager.sessions)
        })

# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="IDA MCP Daemon - Standalone Background Service")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=13337, help="Port to listen on")
    parser.add_argument("--ida-dir", default="", help="Path to IDA installation")
    parser.add_argument("--cache-dir", default="", help="Path to cache directory")
    parser.add_argument("--workers", type=int, default=4, help="Max parallel workers")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create config
    config = DaemonConfig(
        host=args.host,
        port=args.port,
        ida_dir=args.ida_dir,
        cache_dir=args.cache_dir,
        max_workers=args.workers
    )
    
    if not config.ida_dir or not os.path.exists(config.ida_dir):
        logger.error(f"IDA directory not found: {config.ida_dir}")
        logger.error("Set IDADIR environment variable or use --ida-dir")
        sys.exit(1)
    
    # Create session manager
    try:
        manager = SessionManager(config)
    except Exception as e:
        logger.error(f"Failed to initialize: {e}")
        sys.exit(1)
    
    # Setup HTTP server
    MCPHandler.manager = manager
    server = HTTPServer((config.host, config.port), MCPHandler)
    
    logger.info("=" * 60)
    logger.info("IDA MCP Daemon - Standalone Background Service")
    logger.info("=" * 60)
    logger.info(f"IDA Dir:    {config.ida_dir}")
    logger.info(f"idat:       {manager.idat_exe}")
    logger.info(f"Cache:      {config.cache_dir}")
    logger.info(f"Workers:    {config.max_workers}")
    logger.info(f"Listening:  http://{config.host}:{config.port}")
    logger.info("=" * 60)
    logger.info("")
    logger.info("API Endpoints:")
    logger.info("  POST /  action=analyze  path=<file>           Analyze single file")
    logger.info("  POST /  action=batch    paths=[...]           Analyze multiple files")
    logger.info("  POST /  action=batch    directory=<dir>       Analyze directory")
    logger.info("  POST /  action=sessions                       List sessions")
    logger.info("  GET  /                                        Health check")
    logger.info("")
    logger.info("Press Ctrl+C to stop")
    logger.info("")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
        server.shutdown()

if __name__ == "__main__":
    main()
