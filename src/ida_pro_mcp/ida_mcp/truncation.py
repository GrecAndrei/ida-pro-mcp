
import json
from typing import Any, Dict, List, Union

def truncate_response(response: Dict[str, Any], max_tokens: int = 4000) -> Dict[str, Any]:
    """
    Intelligently truncate large MCP responses to fit within LLM context windows.
    
    Args:
        response: The original tool response dictionary.
        max_tokens: Approximate character limit (roughly 1 char = 1 token for simplicity).
        
    Returns:
        A pruned response with truncation markers.
    """
    # 1. Check if the total size is already within limits
    resp_str = json.dumps(response)
    if len(resp_str) < max_tokens:
        return response

    pruned = response.copy()
    pruned["_truncated"] = True
    
    # 2. Target high-frequency list keys (functions, strings, matches, etc.)
    # We look for lists that are likely the source of the bloat
    for key, value in pruned.items():
        if isinstance(value, list) and len(value) > 10:
            # We found a large list. Prune it.
            original_len = len(value)
            
            # Keep the first N items until we hit the limit
            # We estimate 200 chars per item for safety
            keep_count = max(5, (max_tokens // 200))
            
            if original_len > keep_count:
                pruned[key] = value[:keep_count]
                pruned[f"{key}_total_count"] = original_len
                pruned[f"{key}_note"] = f"Showing first {keep_count} of {original_len} items. Use 'offset' and 'count' parameters to read more."

    # 3. Handle massive single strings (e.g. decompilation, logs)
    for key, value in pruned.items():
        if isinstance(value, str) and len(value) > max_tokens:
            pruned[key] = value[:max_tokens] + "... [TRUNCATED]"
            pruned[f"{key}_original_size"] = len(value)

    return pruned
