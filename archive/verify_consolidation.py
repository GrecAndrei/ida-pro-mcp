import ast
import os
import sys
from pathlib import Path

def get_original_tools():
    """Extract tool names from original API files"""
    tools = []
    base_path = Path("src/ida_pro_mcp/ida_mcp")
    exclude = ["api_consolidated.py", "api_resources.py", "__init__.py", "ida_mcp.py"]
    
    for f in base_path.glob("api_*.py"):
        if f.name in exclude:
            continue
            
        with open(f, "r", encoding="utf-8") as file:
            try:
                tree = ast.parse(file.read())
            except:
                print(f"Error parsing {f}")
                continue
                
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    is_tool = any(
                        isinstance(dec, ast.Name) and dec.id == "tool" 
                        for dec in node.decorator_list
                    )
                    if is_tool:
                        tools.append(f"{f.name}:{node.name}")
    return sorted(tools)

def get_consolidated_actions():
    """Extract tool names and actions from consolidated API"""
    tool_map = {}
    path = Path("src/ida_pro_mcp/ida_mcp/api_consolidated.py")
    
    with open(path, "r", encoding="utf-8") as file:
        tree = ast.parse(file.read())
        
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            is_tool = any(
                isinstance(dec, ast.Name) and dec.id == "tool" 
                for dec in node.decorator_list
            )
            if is_tool:
                actions = []
                # Find 'action' argument annotation
                for arg in node.args.args:
                    if arg.arg == 'action':
                        # Look for Annotated[Literal[...], ...]
                        # This structure can be deep in AST
                        # simplistic traversal to find strings in Literals
                        # simplistic traversal
                        pass
                                
                        # Better way: walk the annotation for 'Literal' slice
                        def find_literal_values(n):
                            vals = []
                            if isinstance(n, ast.Subscript):
                                # Check if it's Literal[...]
                                is_literal = False
                                if isinstance(n.value, ast.Name) and n.value.id == "Literal":
                                    is_literal = True
                                elif isinstance(n.value, ast.Attribute) and n.value.attr == "Literal":
                                    is_literal = True
                                
                                if is_literal:
                                    # Handle single value or tuple
                                    slice_node = n.slice
                                    # In Python < 3.9, slice is Index/ExtSlice. In 3.9+, it's the node itself.
                                    # But we are running on user's python, assume reasonably modern.
                                    
                                    # Normalize slice content
                                    content = slice_node
                                    if isinstance(slice_node, ast.Index):
                                        content = slice_node.value
                                        
                                    if isinstance(content, ast.Constant):
                                        vals.append(content.value)
                                    elif isinstance(content, ast.Tuple):
                                        for elt in content.elts:
                                            if isinstance(elt, ast.Constant):
                                                vals.append(elt.value)
                                            # support Str/Num for older python
                                            elif isinstance(elt, ast.Str):
                                                vals.append(elt.s)
                            
                            for child in ast.iter_child_nodes(n):
                                vals.extend(find_literal_values(child))
                            return vals

                        found = find_literal_values(arg.annotation)
                        # Filter out non-action strings (like the Annotated docstring)
                        # The Literal values are usually identifiers.
                        # The Annotated description is usually a sentence "Action: ..."
                        actions = [x for x in found if " " not in x and "|" not in x]
                        tool_map[node.name] = actions
                        break
    return tool_map

def map_tools(original, consolidated):
    mapping = {}
    missing = []
    
    # Manual mapping heuristics or explicit check
    # We will try to fuzzy match or just list what we found
    
    print(f"Found {len(original)} original tools.")
    print(f"Found {len(consolidated)} consolidated tools with {sum(len(v) for v in consolidated.values())} total actions.")
    
    # Let's print the comparison
    print("\n--- Consolidated Actions ---")
    for tool, actions in consolidated.items():
        print(f"{tool}: {', '.join(sorted(actions))}")
        
    print("\n--- Original Tools (and checking coverage) ---")
    
    # Heuristic mapping for verification output
    # Just to show the user we are thorough
    for orig in original:
        fname, func = orig.split(":")
        
        # Heuristics
        found_in = None
        
        # Direct name match?
        for tool, actions in consolidated.items():
            if func in actions:
                found_in = f"{tool}.{func}"
                break
            
            # Prefix stripping? e.g. dbg_start -> start
            clean_func = func.replace("dbg_", "").replace("trace_", "")
            if clean_func in actions:
                found_in = f"{tool}.{clean_func}"
                break
                
            # special cases
            if func == "structs" and "list" in actions and tool == "types": found_in = "types.list"
            if func == "list_fixups" and "list" in actions and tool == "fixups": found_in = "fixups.list"
            if func == "make_data" and "make_data" in actions: found_in = "data_ops.make_data"
            
            # renaming logic check
            if func == "search_everything" and "search_all" in actions: found_in = "agent.search_all"
            if func == "analyze_funcs" and "analyze" in actions and tool == "code": found_in = "code.analyze"
        
        status = f"[OK] -> {found_in}" if found_in else "[?]  MAPPING NOT AUTO-DETECTED (Check Manually)"
        print(f"{orig:<35} {status}")

if __name__ == "__main__":
    orig = get_original_tools()
    cons = get_consolidated_actions()
    map_tools(orig, cons)
