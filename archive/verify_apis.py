import re
import sys
import importlib

# Modules to check
MODULES = {
    "idaapi": None,
    "idc": None,
    "idautils": None,
    "ida_bytes": None,
    "ida_funcs": None,
    "ida_nalt": None, # Handled dynamically
    "ida_loader": None,
    "ida_hexrays": None,
    "ida_typeinf": None,
    "ida_name": None,
    "ida_dbg": None,
    "ida_segment": None,
    "ida_kernwin": None,
    "ida_frame": None,
    #"ida_struct": None, # Removed/Missing
    "ida_xref": None,
    "ida_search": None,
    "ida_entry": None, # might fail
    "ida_undo": None, # might fail
}

# Load modules
for name in list(MODULES.keys()):
    try:
        MODULES[name] = importlib.import_module(name)
    except ImportError:
        pass

# Naive parser to find usages like "ida_loader.open_database"
def check_apis(content):
    missing = []
    # Regex for module.attr
    matches = re.findall(r'\b(ida[a-z0-9_]+)\.([a-zA-Z0-9_]+)', content)
    matches += re.findall(r'\b(idc)\.([a-zA-Z0-9_]+)', content)
    
    unique_calls = set(matches)
    
    for mod_name, attr_name in unique_calls:
        if mod_name not in MODULES:
            continue
            
        module = MODULES[mod_name]
        if module is None:
             # Module itself missing
             continue
             
        if not hasattr(module, attr_name):
            missing.append(f"{mod_name}.{attr_name}")
            
    return missing

# Read the file
with open(r"c:\Users\Alexander\Desktop\idamcp\src\ida_pro_mcp\ida_mcp\api_consolidated.py", "r", encoding="utf-8") as f:
    content = f.read()

missing = check_apis(content)
if missing:
    raise Exception("MISSING APIs: " + str(missing))
else:
    print("All static API references exist.")
