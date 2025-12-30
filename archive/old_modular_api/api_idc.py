"""IDC script execution for IDA Pro MCP."""

from typing import Annotated

import idc

from .rpc import tool, unsafe
from .sync import idaread


@tool
@idaread
@unsafe
def idc_eval(
    code: Annotated[str, "IDC code to execute"]
) -> dict:
    """Execute IDC script code"""
    try:
        # IDC evaluation using idc.eval_idc
        result = idc.eval_idc(code)
        
        # Convert result to string for JSON serialization
        if result is None:
            return {"result": None, "ok": True}
        elif isinstance(result, (int, float)):
            return {"result": result, "hex": hex(int(result)) if isinstance(result, int) else None, "ok": True}
        else:
            return {"result": str(result), "ok": True}
            
    except Exception as e:
        return {"error": str(e)}
