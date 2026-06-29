#!/usr/bin/env python3
"""
Interactive IDA MCP Client
Connect to the MCP server and interact with a binary through IDA Pro.
"""
import json
import os
import queue
import subprocess
import sys
import threading
import time


class IDAMCPClient:
    def __init__(self):
        self.proc = None
        self.stdout_queue = queue.Queue()
        self.request_id = 0
        self.session = None

    def start(self):
        print("[*] Starting MCP server...")
        # Locate ida_mcp_stdio.py: it sits at the repo root, not in scripts/.
        here = os.path.dirname(os.path.abspath(__file__))
        stdio_candidates = [
            os.path.join(os.path.dirname(here), "ida_mcp_stdio.py"),
            os.path.join(here, "ida_mcp_stdio.py"),
        ]
        stdio_entry = next((p for p in stdio_candidates if os.path.isfile(p)), None)
        if stdio_entry is None:
            raise FileNotFoundError(
                f"ida_mcp_stdio.py not found; tried: {stdio_candidates}"
            )
        self.proc = subprocess.Popen(
            [sys.executable, "-u", stdio_entry],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(here) or ".",
            bufsize=0
        )

        # Readers
        def read_stderr():
            for line in self.proc.stderr:
                decoded = line.decode('utf-8', errors='replace').strip()
                if decoded:
                    print(f"[IDA] {decoded}", file=sys.stderr)

        def read_stdout():
            for line in self.proc.stdout:
                self.stdout_queue.put(line)

        threading.Thread(target=read_stderr, daemon=True).start()
        threading.Thread(target=read_stdout, daemon=True).start()
        time.sleep(0.3)

        # Initialize
        resp = self._call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ida-mcp-client"}
        })
        if "result" not in resp:
            print(f"[!] Initialize failed: {resp}")
            return False
        print("[+] MCP server initialized")
        return True

    def _call(self, method, params, timeout=120):
        self.request_id += 1
        req = {"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params}
        self.proc.stdin.write((json.dumps(req) + "\n").encode('utf-8'))
        self.proc.stdin.flush()

        start = time.time()
        while time.time() - start < timeout:
            try:
                line = self.stdout_queue.get(timeout=1)
                resp = json.loads(line.decode('utf-8'))
                if resp.get("id") == self.request_id:
                    return resp
            except queue.Empty:
                if self.proc.poll() is not None:
                    return {"error": "Server died"}
            except json.JSONDecodeError:
                continue
        return {"error": "Timeout"}

    def call_tool(self, tool_name, **args):
        """Call an IDA MCP tool and return the parsed result"""
        resp = self._call("tools/call", {"name": tool_name, "arguments": args})
        if "result" not in resp:
            return resp

        content = resp["result"].get("content", [{}])[0].get("text", "{}")
        try:
            return json.loads(content)
        except:
            return {"raw": content}

    def open_binary(self, binary_path):
        """Open a binary in IDA and create a session"""
        print(f"[*] Opening {binary_path}...")
        result = self.call_tool("session", action="create", binary_path=os.path.abspath(binary_path))
        if result.get("ok") or result.get("session"):
            self.session = result.get("session", result)
            print(f"[+] Session created: {self.session}")
            return True
        else:
            print(f"[!] Failed: {result}")
            return False

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except:
                self.proc.kill()

def interactive_session(client):
    """Interactive REPL for IDA MCP"""
    print("\n" + "="*60)
    print("IDA MCP Interactive Client")
    print("="*60)
    print("Commands:")
    print("  open <path>       - Open a binary")
    print("  call <tool> [args] - Call a tool (args as JSON)")
    print("  funcs             - List functions")
    print("  strings           - List strings")
    print("  decomp <addr>     - Decompile at address")
    print("  disasm <addr>     - Disassemble at address")
    print("  xrefs <addr>      - Get xrefs to address")
    print("  meta              - Get database metadata")
    print("  help              - Show tool list")
    print("  exit              - Quit")
    print("="*60)

    while True:
        try:
            cmd = input("\nida> ").strip()
            if not cmd:
                continue

            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if action in ("exit", "quit", "q"):
                break

            if action == "open":
                if not arg:
                    print("Usage: open <binary_path>")
                    continue
                client.open_binary(arg)

            elif action == "call":
                # call <tool> {"arg": "value"}
                tool_parts = arg.split(maxsplit=1)
                if not tool_parts:
                    print("Usage: call <tool> [json_args]")
                    continue
                tool_name = tool_parts[0]
                try:
                    tool_args = json.loads(tool_parts[1]) if len(tool_parts) > 1 else {}
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON: {e}")
                    continue
                result = client.call_tool(tool_name, **tool_args)
                print(json.dumps(result, indent=2))

            elif action == "funcs":
                result = client.call_tool("data", action="functions")
                if "functions" in result:
                    for f in result["functions"][:30]:
                        print(f"  {f.get('address', '?'):16} {f.get('name', '?')}")
                    if len(result["functions"]) > 30:
                        print(f"  ... and {len(result['functions']) - 30} more")
                else:
                    print(json.dumps(result, indent=2))

            elif action == "strings":
                result = client.call_tool("data", action="strings")
                if "strings" in result:
                    for s in result["strings"][:30]:
                        addr = s.get("address", "?")
                        val = s.get("value", "?")[:60]
                        print(f"  {addr:16} {repr(val)}")
                    if len(result["strings"]) > 30:
                        print(f"  ... and {len(result['strings']) - 30} more")
                else:
                    print(json.dumps(result, indent=2))

            elif action in ("decomp", "decompile"):
                if not arg:
                    print("Usage: decomp <address>")
                    continue
                result = client.call_tool("code", action="decompile", address=arg)
                if "pseudocode" in result:
                    print(result["pseudocode"])
                else:
                    print(json.dumps(result, indent=2))

            elif action == "disasm":
                if not arg:
                    print("Usage: disasm <address>")
                    continue
                result = client.call_tool("code", action="disasm", address=arg, count=20)
                if "lines" in result:
                    for line in result["lines"]:
                        print(f"  {line.get('address', ''):16} {line.get('text', '')}")
                else:
                    print(json.dumps(result, indent=2))

            elif action == "xrefs":
                if not arg:
                    print("Usage: xrefs <address>")
                    continue
                result = client.call_tool("code", action="xrefs_to", address=arg)
                print(json.dumps(result, indent=2))

            elif action == "meta":
                result = client.call_tool("idb", action="meta")
                print(json.dumps(result, indent=2))

            elif action == "help":
                result = client._call("tools/list", {})
                if "result" in result:
                    tools = result["result"].get("tools", [])
                    print(f"\nAvailable tools ({len(tools)}):")
                    for t in tools:
                        print(f"  {t['name']:15} - {t.get('description', '')[:55]}...")
                else:
                    print(f"Error: {result}")

            else:
                # Try as a direct tool call
                result = client.call_tool(action, action=arg or "meta")
                print(json.dumps(result, indent=2))

        except KeyboardInterrupt:
            print("\nUse 'exit' to quit")
        except EOFError:
            break
        except Exception as e:
            print(f"Error: {e}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="IDA MCP Interactive Client")
    parser.add_argument("binary", nargs="?", help="Binary to open")
    parser.add_argument("--cmd", "-c", help="Execute a single command and exit")
    args = parser.parse_args()

    client = IDAMCPClient()
    if not client.start():
        sys.exit(1)

    try:
        if args.binary and not client.open_binary(args.binary):
            sys.exit(1)

        if args.cmd:
            # Single command mode
            parts = args.cmd.split(maxsplit=1)
            result = client.call_tool(parts[0], **(json.loads(parts[1]) if len(parts) > 1 else {}))
            print(json.dumps(result, indent=2))
        else:
            interactive_session(client)
    finally:
        client.stop()
        print("[*] Client stopped.")

if __name__ == "__main__":
    main()
