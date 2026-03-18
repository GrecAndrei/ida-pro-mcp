import fnmatch
import difflib
import json
import os
import re
import struct
import sys
import tempfile
from typing import (
    Annotated,
    Any,
    Callable,
    Generic,
    Literal,
    Optional,
    TypedDict,
    TypeVar,
    overload,
)

# Compatibility for Python < 3.11
try:
    from typing import NotRequired
except ImportError:
    try:
        from typing_extensions import NotRequired
    except ImportError:
        # Fallback for old Python without typing_extensions
        NotRequired = Optional

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_typeinf
import idaapi
import idautils
import idc

# Support both package mode and standalone mode
try:
    from sync import IDAError
except ImportError:
    try:
        from .sync import IDAError
    except ImportError:
        class IDAError(Exception):
            pass

# ============================================================================
# TypedDict Definitions for API Parameters
# ============================================================================


class MemoryRead(TypedDict):
    """Memory read request"""

    addr: Annotated[str, "Address to read from (hex or decimal)"]
    size: Annotated[int, "Number of bytes to read"]


class MemoryPatch(TypedDict):
    """Memory patch operation"""

    addr: Annotated[str, "Address to patch (hex or decimal)"]
    data: Annotated[str, "Hex data to write (space-separated bytes)"]


class CommentOp(TypedDict):
    """Comment operation"""

    addr: Annotated[str, "Address (hex or decimal)"]
    comment: Annotated[str, "Comment text"]


class AsmPatchOp(TypedDict):
    """Assembly patch operation"""

    addr: Annotated[str, "Address (hex or decimal)"]
    asm: Annotated[str, "Assembly instruction(s), semicolon-separated"]


class FunctionRename(TypedDict):
    """Function rename operation"""

    addr: Annotated[str, "Function address (hex or decimal)"]
    name: Annotated[str, "New function name"]


class GlobalRename(TypedDict):
    """Global variable rename operation"""

    old: Annotated[str, "Current variable name"]
    new: Annotated[str, "New variable name"]


class LocalRename(TypedDict):
    """Local variable rename operation"""

    func_addr: Annotated[str, "Function address containing the local variable"]
    old: Annotated[str, "Current variable name"]
    new: Annotated[str, "New variable name"]


class StackRename(TypedDict):
    """Stack variable rename operation"""

    func_addr: Annotated[str, "Function address containing the stack variable"]
    old: Annotated[str, "Current variable name"]
    new: Annotated[str, "New variable name"]


class RenameBatch(TypedDict, total=False):
    """Batch rename operations across all entity types"""

    func: Annotated[
        list[FunctionRename] | FunctionRename | None, "Function rename operations"
    ]
    data: Annotated[
        list[GlobalRename] | GlobalRename | None,
        "Global/data variable rename operations",
    ]
    local: Annotated[
        list[LocalRename] | LocalRename | None, "Local variable rename operations"
    ]
    stack: Annotated[
        list[StackRename] | StackRename | None, "Stack variable rename operations"
    ]


class PathQuery(TypedDict):
    """Path finding query"""

    source: Annotated[str, "Source address (hex or decimal)"]
    target: Annotated[str, "Target address (hex or decimal)"]


class StructFieldQuery(TypedDict):
    """Struct field query for xrefs"""

    struct: Annotated[str, "Structure name"]
    field: Annotated[str, "Field name"]


class ListQuery(TypedDict, total=False):
    """Pagination query for listing operations"""

    filter: Annotated[str, "Optional glob pattern to filter results"]
    offset: Annotated[int, "Starting index (default: 0)"]
    count: Annotated[int, "Maximum number of results (default: 50, 0 for all)"]


class StringFilter(TypedDict, total=False):
    """String analysis filter"""

    pattern: Annotated[str, "Optional pattern to match in strings"]
    min_length: Annotated[int, "Optional minimum string length"]


class BreakpointOp(TypedDict):
    """Debugger breakpoint operation"""

    addr: Annotated[str, "Breakpoint address (hex or decimal)"]
    enabled: Annotated[bool, "Enable (true) or disable (false)"]


class InsnPattern(TypedDict, total=False):
    """Instruction pattern for operand search"""

    mnem: Annotated[str, "Instruction mnemonic to match"]
    op0: Annotated[int, "Value to match in first operand"]
    op1: Annotated[int, "Value to match in second operand"]
    op2: Annotated[int, "Value to match in third operand"]
    op_any: Annotated[int, "Value to match in any operand"]


class NumberConversion(TypedDict, total=False):
    """Number conversion request"""

    text: Annotated[str, "Number string to convert"]
    size: Annotated[int, "Byte size for conversion (omit for auto)"]


class StructRead(TypedDict):
    """Structure read request"""

    addr: Annotated[str, "Memory address (hex or decimal)"]
    struct: Annotated[str, "Structure name"]


class TypeApplication(TypedDict, total=False):
    """Type application operation"""

    addr: Annotated[str, "Memory address"]
    name: Annotated[str, "Variable/function name"]
    ty: Annotated[str, "Type name or declaration"]
    kind: Annotated[str, "Type of entity (auto-detected if omitted)"]
    signature: Annotated[str, "Function signature (for kind=function)"]
    variable: Annotated[str, "Local variable name (for kind=local)"]


class StackVarDecl(TypedDict):
    """Stack variable declaration"""

    addr: Annotated[str, "Function address"]
    offset: Annotated[str, "Stack offset"]
    name: Annotated[str, "Variable name"]
    ty: Annotated[str, "Type name"]


class StackVarDelete(TypedDict):
    """Stack variable deletion"""

    addr: Annotated[str, "Function address"]
    name: Annotated[str, "Variable name"]


# ============================================================================
# TypedDict Definitions for Results
# ============================================================================


class Metadata(TypedDict):
    path: str
    module: str
    base: str
    size: str
    md5: str
    sha256: str
    crc32: str
    filesize: str


class Function(TypedDict):
    addr: str
    name: str
    size: str


class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str


class Global(TypedDict):
    addr: str
    name: str


class Import(TypedDict):
    addr: str
    imported_name: str
    module: str


class String(TypedDict):
    addr: str
    length: int
    string: str


class Segment(TypedDict):
    name: str
    start: str
    end: str
    size: str
    permissions: str


class DisassemblyLine(TypedDict):
    segment: NotRequired[str]
    addr: str
    label: NotRequired[str]
    instruction: str
    comments: NotRequired[list[str]]


class Argument(TypedDict):
    name: str
    type: str


class StackFrameVariable(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class DisassemblyFunction(TypedDict):
    name: str
    start_ea: str
    return_type: NotRequired[str]
    arguments: NotRequired[list[Argument]]
    stack_frame: list[StackFrameVariable]
    lines: list[DisassemblyLine]


class Xref(TypedDict):
    addr: str
    type: str
    fn: Optional[Function]


class StructureMember(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class StructureDefinition(TypedDict):
    name: str
    size: str
    members: list[StructureMember]


class RegisterValue(TypedDict):
    name: str
    value: str


class ThreadRegisters(TypedDict):
    thread_id: int
    registers: list[RegisterValue]


class Breakpoint(TypedDict):
    addr: str
    enabled: bool
    condition: Optional[str]


class FunctionAnalysis(TypedDict):
    addr: str
    name: Optional[str]
    code: Optional[str]
    asm: Optional[str]
    xto: list[Xref]
    xfrom: list[Xref]
    callees: list[dict]
    callers: list[Function]
    strings: list[String]
    constants: list[dict]
    blocks: list[dict]
    error: Optional[str]


class PatternMatch(TypedDict):
    pattern: str
    matches: list[str]
    count: int


class CodePattern(TypedDict):
    mnemonic: str
    operands: NotRequired[list[str]]


class EnumMember(TypedDict):
    name: str
    value: str
    serial: int


class EnumDef(TypedDict):
    name: str
    id: str  # Hex string
    size: int
    flags: str
    members: int  # count


class EnumInfo(TypedDict):
    name: str
    id: str
    width: int
    flag: str
    members: list[EnumMember]


class BasicBlock(TypedDict):
    start: str
    end: str
    size: int
    type: int
    successors: list[str]
    predecessors: list[str]


class FileInfo(TypedDict):
    name: str
    path: str
    type: str  # 'file' or 'dir'
    size: int
    mtime: str


T = TypeVar("T")


class Page(TypedDict):
    """Generic paginated response"""

    items: list[Any]
    total: int
    offset: int
    count: int


# ============================================================================
# Helper Functions
# ============================================================================


def get_image_size() -> int:
    try:
        info = idaapi.get_inf_structure()
        omin_ea = info.omin_ea
        omax_ea = info.omax_ea
    except AttributeError:
        import ida_ida

        omin_ea = ida_ida.inf_get_omin_ea()
        omax_ea = ida_ida.inf_get_omax_ea()
    image_size = omax_ea - omin_ea
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size


def is_64bit() -> bool:
    """Check if the current IDB is 64-bit in a way compatible with IDA 7.x-9.x"""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_is_64bit"):
            return ida_ida.inf_is_64bit()
        if hasattr(ida_ida, "inf_get_is_64bit"):
            return ida_ida.inf_get_is_64bit()
    except ImportError:
        pass
    return idaapi.get_inf_structure().is_64bit()


def parse_address(addr: str | int) -> int:
    if isinstance(addr, int):
        return addr
    
    # Try direct integer conversion (hex or decimal)
    try:
        return int(addr, 0)
    except ValueError:
        pass
    
    # Try resolving as a symbol/name
    import idc
    ea = idc.get_name_ea_simple(addr)
    if ea != idaapi.BADADDR:
        return ea
        
    # Final attempt: check if it's a hex string without 0x prefix
    try:
        if all(c in "0123456789abcdefABCDEF" for c in addr):
            return int(addr, 16)
    except ValueError:
        pass
        
    raise IDAError(f"Failed to resolve address or symbol: {addr}")


def normalize_list_input(value: list | str) -> list:
    """Normalize input to list - accepts list or comma-separated string"""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]

def resolve_symbol(query: str) -> dict:
    """Resolve an address or name to a canonical {addr,name,is_func} dict."""
    if query is None:
        raise IDAError("query required")
    # Try address forms first
    try:
        if looks_like_address(str(query)):
            ea = parse_address(str(query))
            name = idc.get_name(ea) or ""
            func = idaapi.get_func(ea)
            return {"addr": hex(ea), "name": name, "is_func": func is not None}
    except Exception:
        pass
    # Try as name
    ea = idc.get_name_ea_simple(str(query))
    if ea != idaapi.BADADDR:
        func = idaapi.get_func(ea)
        return {"addr": hex(ea), "name": str(query), "is_func": func is not None}
    raise IDAError(f"Not found: {query}")


def normalize_dict_list(
    value: list[dict] | dict | str | list[str] | Any,
    string_parser: Optional[Callable[[str], dict]] = None,
) -> list[dict]:
    """Normalize input to list[dict] with optional string parsing

    Args:
        value: Input value (dict, list[dict], str, list[str], or any)
        string_parser: Optional function to convert string → dict
                      If None, strings → empty dict

    Flow:
        dict → [dict]
        str → split by ',' → list[str] → map(string_parser) → list[dict]
        list[str] → map(string_parser) → list[dict]
        list[dict] → list[dict]
        Any → [{}]
    """
    if isinstance(value, dict):
        return [value]
    elif isinstance(value, list):
        if not value:
            return [{}]
        # Check if list[str] or list[dict]
        if all(isinstance(item, dict) for item in value):
            return value
        elif all(isinstance(item, str) for item in value):
            # list[str] → map with parser
            if string_parser:
                return [string_parser(s.strip()) for s in value if s.strip()]
            return [{}]
        else:
            # Mixed types - filter dicts only
            return [item for item in value if isinstance(item, dict)] or [{}]
    elif isinstance(value, str):
        # Try JSON parse first
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return [parsed]
            elif isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass

        # Not JSON - split by comma and parse
        parts = [s.strip() for s in value.split(",") if s.strip()]
        if not parts:
            return [{}]

        if string_parser:
            return [string_parser(part) for part in parts]
        return [{}]
    else:
        # Any other type → empty dict
        return [{}]


def looks_like_address(s: str) -> bool:
    """Check if string looks like an address (0x prefix or all hex chars)"""
    if s.startswith("0x") or s.startswith("0X"):
        return True
    # All hex chars and at least 4 chars → likely address
    if len(s) >= 4 and all(c in "0123456789abcdefABCDEF" for c in s):
        return True
    return False


@overload
def get_function(addr: int, *, raise_error: Literal[True]) -> Function: ...


@overload
def get_function(addr: int) -> Function: ...


@overload
def get_function(addr: int, *, raise_error: Literal[False]) -> Optional[Function]: ...


def get_function(addr, *, raise_error=True):
    fn = idaapi.get_func(addr)
    if fn is None:
        if raise_error:
            raise IDAError(f"No function found at address {hex(addr)}")
        return None

    try:
        name = fn.get_name()
    except AttributeError:
        name = ida_funcs.get_func_name(fn.start_ea)

    return Function(addr=hex(addr), name=name, size=hex(fn.end_ea - fn.start_ea))


def get_prototype(fn: ida_funcs.func_t) -> Optional[str]:
    try:
        prototype: ida_typeinf.tinfo_t = fn.get_prototype()
        if prototype is not None:
            return str(prototype)
        else:
            return None
    except AttributeError:
        try:
            return idc.get_type(fn.start_ea)
        except Exception:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, fn.start_ea):
                return str(tif)
            return None
    except Exception as e:
        print(f"Error getting function prototype: {e}")
        return None


DEMANGLED_TO_EA = {}


def create_demangled_to_ea_map():
    for ea in idautils.Functions():
        demangled = idaapi.demangle_name(idc.get_name(ea, 0), idaapi.MNG_NODEFINIT)
        if demangled:
            DEMANGLED_TO_EA[demangled] = ea


def get_type_by_name(type_name: str) -> ida_typeinf.tinfo_t:
    # 8-bit integers
    if type_name in ("int8", "__int8", "int8_t", "char", "signed char"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT8)
    elif type_name in ("uint8", "__uint8", "uint8_t", "unsigned char", "byte", "BYTE"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT8)
    # 16-bit integers
    elif type_name in (
        "int16",
        "__int16",
        "int16_t",
        "short",
        "short int",
        "signed short",
        "signed short int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT16)
    elif type_name in (
        "uint16",
        "__uint16",
        "uint16_t",
        "unsigned short",
        "unsigned short int",
        "word",
        "WORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT16)
    # 32-bit integers
    elif type_name in (
        "int32",
        "__int32",
        "int32_t",
        "int",
        "signed int",
        "long",
        "long int",
        "signed long",
        "signed long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
    elif type_name in (
        "uint32",
        "__uint32",
        "uint32_t",
        "unsigned int",
        "unsigned long",
        "unsigned long int",
        "dword",
        "DWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT32)
    # 64-bit integers
    elif type_name in (
        "int64",
        "__int64",
        "int64_t",
        "long long",
        "long long int",
        "signed long long",
        "signed long long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT64)
    elif type_name in (
        "uint64",
        "__uint64",
        "uint64_t",
        "unsigned int64",
        "unsigned long long",
        "unsigned long long int",
        "qword",
        "QWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT64)
    # 128-bit integers
    elif type_name in ("int128", "__int128", "int128_t", "__int128_t"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT128)
    elif type_name in (
        "uint128",
        "__uint128",
        "uint128_t",
        "__uint128_t",
        "unsigned int128",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT128)
    # Floating point types
    elif type_name in ("float",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_FLOAT)
    elif type_name in ("double",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_DOUBLE)
    elif type_name in ("long double", "ldouble"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_LDOUBLE)
    # Boolean type
    elif type_name in ("bool", "_Bool", "boolean"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_BOOL)
    # Void type
    elif type_name in ("void",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
    # Named types
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_STRUCT):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_TYPEDEF):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_ENUM):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_UNION):
        return tif
    if tif := ida_typeinf.tinfo_t(type_name):
        return tif

    raise IDAError(f"Unable to retrieve {type_name} type info object")


def paginate(data: list[T], offset: int, count: int) -> Page[T]:
    if count == 0:
        count = len(data)
    next_offset = offset + count
    if next_offset >= len(data):
        next_offset = None
    return {
        "data": data[offset : offset + count],
        "next_offset": next_offset,
    }


def _is_regex(pattern: str) -> bool:
    """Detect if a pattern string looks like a regular expression.

    Returns True when the pattern contains regex-specific metacharacters that
    would not appear in a plain substring search.  Explicit ``/pattern/flags``
    syntax is also recognised.

    Glob-only wildcards (``*`` and ``?`` without other regex syntax) are *not*
    treated as regex so that simple wildcard searches keep working via
    ``fnmatch``.
    """
    if not pattern:
        return False

    # Explicit /pattern/flags notation
    if pattern.startswith("/") and pattern.count("/") >= 2:
        return True

    # Characters / sequences that are strong regex indicators
    _REGEX_INDICATORS = (
        r"\d", r"\w", r"\s", r"\b", r"\D", r"\W", r"\S", r"\B",
        r"\A", r"\Z",
    )
    for ind in _REGEX_INDICATORS:
        if ind in pattern:
            return True

    # Backslash-escaped metacharacters (e.g. \., \(, \), \*, \+) are regex
    if re.search(r"\\[.^$*+?{}()|[\]\\]", pattern):
        return True

    # Regex-only metacharacters (not glob wildcards)
    _REGEX_META = set("^$+{}()|")
    if _REGEX_META.intersection(pattern):
        return True

    # Character classes like [a-z]
    if re.search(r"\[.+\]", pattern):
        return True

    # Quantifiers attached to a character e.g. a{2,4}, .+, .?
    if re.search(r".\{[0-9]", pattern):
        return True

    return False


_SEMANTIC_CANONICALS = {
    # Search / discovery
    "find": "search",
    "lookup": "search",
    "locate": "search",
    "discover": "search",
    "query": "search",
    "match": "search",
    # Decompilation / pseudocode
    "decompiler": "decompile",
    "decompiled": "decompile",
    "pseudocode": "decompile",
    "hexrays": "decompile",
    "ctree": "decompile",
    # Function naming
    "routine": "function",
    "procedure": "function",
    "proc": "function",
    "method": "function",
    "subroutine": "function",
    # Data naming
    "global": "data",
    "variable": "data",
    "memory": "data",
    # Cross-reference naming
    "xref": "reference",
    "ref": "reference",
    "refs": "reference",
    "callsite": "reference",
    "caller": "reference",
    "callee": "reference",
    # String naming
    "literal": "string",
    "text": "string",
    # Import/symbol naming
    "api": "import",
    "symbol": "import",
    "extern": "import",
}
# Ignore semantic fallback for very short one-word queries to reduce false positives.
_SEMANTIC_SINGLE_TOKEN_MIN_LEN = 5
# Conservative typo tolerance: catches small misspellings without broad overmatching.
_SEMANTIC_FUZZY_CUTOFF = 0.86


def _normalize_semantic_token(token: str) -> str:
    tok = token.lower().strip()
    if not tok:
        return tok
    # Light stemming for noisy search tokens.
    for suffix in ("ing", "ers", "ies", "ied", "er", "ed", "es", "s"):
        if len(tok) > 4 and tok.endswith(suffix):
            if suffix in ("ies", "ied"):
                tok = tok[:-3] + "y"
            else:
                tok = tok[: -len(suffix)]
            break
    return _SEMANTIC_CANONICALS.get(tok, tok)


def _semantic_tokenize(text: str) -> list[str]:
    if not text:
        return []
    tokens: list[str] = []
    for raw in re.findall(r"[a-z0-9_]+", text.lower()):
        for part in raw.split("_"):
            tok = _normalize_semantic_token(part)
            if len(tok) >= 2:
                tokens.append(tok)
    return tokens


def _compile_semantic_matcher(pattern: str):
    query_tokens = _semantic_tokenize(pattern)
    if not query_tokens:
        return None
    # Keep semantic fallback conservative for short plain tokens.
    if (
        len(query_tokens) == 1
        and len(query_tokens[0]) < _SEMANTIC_SINGLE_TOKEN_MIN_LEN
        and " " not in pattern
    ):
        return None

    query_set = set(query_tokens)
    # Require at least half of query concepts (rounded up) to avoid noisy matches.
    overlap_needed = max(1, (len(query_set) + 1) // 2)
    fuzzy_tokens = [tok for tok in query_set if len(tok) >= _SEMANTIC_SINGLE_TOKEN_MIN_LEN]

    def _semantic_matches(text: str) -> bool:
        text_tokens = set(_semantic_tokenize(text))
        if not text_tokens:
            return False

        overlap = len(query_set.intersection(text_tokens))
        if overlap >= overlap_needed:
            return True

        if not fuzzy_tokens:
            return False
        fuzzy_hits = 0
        for qtok in fuzzy_tokens:
            if difflib.get_close_matches(qtok, text_tokens, n=1, cutoff=_SEMANTIC_FUZZY_CUTOFF):
                fuzzy_hits += 1
                if overlap + fuzzy_hits >= overlap_needed:
                    return True
        return False

    return _semantic_matches


def smart_match(pattern: str, text: str, case_sensitive: bool = False) -> bool:
    """Match *text* against *pattern*, auto-detecting the match strategy.

    1. ``/pattern/flags`` – explicit regex
    2. Auto-detected regex (see :func:`_is_regex`) – compiled & searched
    3. Glob wildcards (``*`` / ``?``) – ``fnmatch``
    4. Plain substring containment
    5. Semantic token fallback (auto, conservative)
    """
    if not pattern:
        return True

    compiled = compile_smart_pattern(pattern, case_sensitive)
    return compiled(text)


def compile_smart_pattern(pattern: str, case_sensitive: bool = False):
    """Return a *callable(text) -> bool* for the given pattern.

    Compiling the pattern once and reusing the callable in a tight loop is
    more efficient than calling :func:`smart_match` per item.
    """
    if not pattern:
        return lambda _text: True

    regex = None

    # 1. Explicit /pattern/flags
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash = pattern.rfind("/")
        body = pattern[1:last_slash]
        flag_str = pattern[last_slash + 1:]
        flags = 0
        for ch in flag_str:
            if ch == "i":
                flags |= re.IGNORECASE
            elif ch == "m":
                flags |= re.MULTILINE
            elif ch == "s":
                flags |= re.DOTALL
        try:
            regex = re.compile(body, flags or (0 if case_sensitive else re.IGNORECASE))
        except re.error:
            regex = None

    # 2. Auto-detected regex
    elif _is_regex(pattern):
        try:
            regex = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error:
            regex = None  # fall through to substring

    if regex is not None:
        return lambda _text, _re=regex: bool(_re.search(_text))

    # 3. Glob wildcards
    if "*" in pattern or "?" in pattern:
        pat_lower = pattern.lower()
        return lambda _text, _p=pat_lower: fnmatch.fnmatch(_text.lower(), _p)

    # 4. Plain substring (+ semantic fallback)
    if case_sensitive:
        return lambda _text, _p=pattern: _p in _text

    pat_lower = pattern.lower()
    semantic_match = _compile_semantic_matcher(pattern)
    if semantic_match is None:
        return lambda _text, _p=pat_lower: _p in _text.lower()
    return lambda _text, _p=pat_lower, _sem=semantic_match: (_p in _text.lower()) or _sem(_text)


def pattern_filter(data: list[T], pattern: str, key: str) -> list[T]:
    if not pattern:
        return data

    matcher = compile_smart_pattern(pattern)

    def get_value(item) -> str:
        try:
            v = item[key]
        except Exception:
            v = getattr(item, key, "")
        return "" if v is None else str(v)

    return [item for item in data if matcher(get_value(item))]


def refresh_decompiler_widget():
    widget = ida_kernwin.get_current_widget()
    if widget is not None:
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu is not None:
            vu.refresh_ctext()


def refresh_decompiler_ctext(fn_addr: int):
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(
        fn_addr, error, ida_hexrays.DECOMP_WARNINGS
    )
    if cfunc:
        cfunc.refresh_func_ctext()


class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvinf):
        for lvar_saved in lvinf.lvvec:
            lvar_saved: ida_hexrays.lvar_saved_info_t
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False


def parse_decls_ctypes(decls: str, hti_flags: int) -> tuple[int, list[str]]:
    if sys.platform == "win32":
        import ctypes

        assert isinstance(decls, str), "decls must be a string"
        assert isinstance(hti_flags, int), "hti_flags must be an int"
        c_decls = decls.encode("utf-8")
        c_til = None
        ida_dll = ctypes.CDLL("ida")
        ida_dll.parse_decls.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        ida_dll.parse_decls.restype = ctypes.c_int

        messages: list[str] = []

        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
        def magic_printer(fmt: bytes, arg1: bytes):
            if fmt.count(b"%") == 1 and b"%s" in fmt:
                formatted = fmt.replace(b"%s", arg1)
                messages.append(formatted.decode("utf-8"))
                return len(formatted) + 1
            else:
                messages.append(f"unsupported magic_printer fmt: {repr(fmt)}")
                return 0

        errors = ida_dll.parse_decls(c_til, c_decls, magic_printer, hti_flags)
    else:
        errors = ida_typeinf.parse_decls(None, decls, False, hti_flags)
        messages = []
    return errors, messages


def get_stack_frame_variables_internal(
    fn_addr: int, raise_error: bool
) -> list[StackFrameVariable]:
    try:
        from .sync import ida_major
    except ImportError:
        ida_major = 9  # Assume IDA 9+ in standalone mode

    if ida_major < 9:
        return []

    func = idaapi.get_func(fn_addr)
    if not func:
        if raise_error:
            raise IDAError(f"No function found at address {fn_addr}")
        return []

    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(func.frame) or not tif.is_udt():
        return []

    members: list[StackFrameVariable] = []
    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    for udm in udt:
        if not udm.is_gap():
            name = udm.name
            offset = udm.offset // 8
            size = udm.size // 8
            type = str(udm.type)
            members.append(
                StackFrameVariable(
                    name=name, offset=hex(offset), size=hex(size), type=type
                )
            )
    return members


def decompile_checked(addr: int):
    """Decompile a function and raise IDAError on failure"""
    if not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler is not available")
    error = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile_func(addr, error, ida_hexrays.DECOMP_WARNINGS)
    if not cfunc:
        if error.code == ida_hexrays.MERR_LICENSE:
            raise IDAError(
                "Decompiler license is not available. Use `disassemble_function` to get the assembly code instead."
            )

        message = f"Decompilation failed at {hex(addr)}"
        if error.str:
            message += f": {error.str}"
        if error.errea != idaapi.BADADDR:
            message += f" (address: {hex(error.errea)})"
        raise IDAError(message)
    return cfunc


def decompile_function_safe(ea: int) -> Optional[str]:
    """Safely decompile a function, returning None on failure"""
    import ida_lines

    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
        error = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile_func(ea, error, ida_hexrays.DECOMP_WARNINGS)
        if not cfunc:
            return None
        sv = cfunc.get_pseudocode()
        return "\n".join(ida_lines.tag_remove(sl.line) for sl in sv)
    except Exception:
        return None


def get_assembly_lines(ea: int) -> str:
    """Get assembly lines for a function in compact string format"""
    func = idaapi.get_func(ea)
    if not func:
        return ""

    func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"

    # Get segment from first instruction
    first_seg = idaapi.getseg(func.start_ea)
    segment_name = idaapi.get_segm_name(first_seg) if first_seg else "UNKNOWN"

    # Build compact string format
    lines_str = f"{func_name} ({segment_name} @ {hex(func.start_ea)}):"

    for item_ea in idautils.FuncItems(func.start_ea):
        mnem = idc.print_insn_mnem(item_ea) or ""
        ops = []
        for n in range(8):
            if idc.get_operand_type(item_ea, n) == idaapi.o_void:
                break
            ops.append(idc.print_operand(item_ea, n) or "")
        instruction = f"{mnem} {', '.join(ops)}".rstrip()
        lines_str += f"\n{item_ea:x}  {instruction}"

    return lines_str


def get_all_xrefs(ea: int) -> dict:
    """Get all xrefs to and from an address"""
    return {
        "to": [
            {"addr": hex(x.frm), "type": "code" if x.iscode else "data"}
            for x in idautils.XrefsTo(ea, 0)
        ],
        "from": [
            {"addr": hex(x.to), "type": "code" if x.iscode else "data"}
            for x in idautils.XrefsFrom(ea, 0)
        ],
    }


def get_all_comments(ea: int) -> dict:
    """Get all comments for an address"""
    func = idaapi.get_func(ea)
    if not func:
        return {}

    comments = {}
    for item_ea in idautils.FuncItems(func.start_ea):
        cmt = idaapi.get_cmt(item_ea, False)
        if cmt:
            comments[hex(item_ea)] = {"regular": cmt}
        cmt = idaapi.get_cmt(item_ea, True)
        if cmt:
            if hex(item_ea) not in comments:
                comments[hex(item_ea)] = {}
            comments[hex(item_ea)]["repeatable"] = cmt
    return comments


def get_callees(addr: str) -> list[dict]:
    """Get callees for a single function address"""
    try:
        func_start = parse_address(addr)
        func = idaapi.get_func(func_start)
        if not func:
            return []
        func_end = idc.find_func_end(func_start)
        callees: list[dict[str, str]] = []
        current_ea = func_start
        while current_ea < func_end:
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, current_ea)
            if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                target = idc.get_operand_value(current_ea, 0)
                target_type = idc.get_operand_type(current_ea, 0)
                if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                    func_type = (
                        "internal"
                        if idaapi.get_func(target) is not None
                        else "external"
                    )
                    func_name = idc.get_name(target)
                    if func_name is not None:
                        callees.append(
                            {
                                "addr": hex(target),
                                "name": func_name,
                                "type": func_type,
                            }
                        )
            current_ea = idc.next_head(current_ea, func_end)

        unique_callee_tuples = {tuple(callee.items()) for callee in callees}
        unique_callees = [dict(callee) for callee in unique_callee_tuples]
        return unique_callees
    except Exception:
        return []


def get_callers(addr: str) -> list[Function]:
    """Get callers for a single function address"""
    try:
        callers = {}
        for caller_addr in idautils.CodeRefsTo(parse_address(addr), 0):
            func = get_function(caller_addr, raise_error=False)
            if not func:
                continue
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, caller_addr)
            if insn.itype not in [
                idaapi.NN_call,
                idaapi.NN_callfi,
                idaapi.NN_callni,
            ]:
                continue
            callers[func["addr"]] = func

        return list(callers.values())
    except Exception:
        return []


def get_xrefs_from_internal(ea: int) -> list[Xref]:
    """Get all xrefs from an address"""
    xrefs = []
    for xref in idautils.XrefsFrom(ea, 0):
        xrefs.append(
            Xref(
                addr=hex(xref.to),
                type="code" if xref.iscode else "data",
                fn=get_function(xref.to, raise_error=False),
            )
        )
    return xrefs


def extract_function_strings(ea: int) -> list[String]:
    """Extract string references from a function"""
    func = idaapi.get_func(ea)
    if not func:
        return []

    strings = []
    for item_ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(item_ea, 0):
            if not xref.iscode:
                # Check if target is a string
                str_type = ida_nalt.get_str_type(xref.to)
                if str_type != ida_nalt.STRTYPE_C:
                    continue
                try:
                    str_content = idc.get_strlit_contents(xref.to)
                    if str_content:
                        strings.append(
                            String(
                                addr=hex(xref.to),
                                length=len(str_content),
                                string=str_content.decode("utf-8", errors="replace"),
                            )
                        )
                except Exception:
                    pass
    return strings


def extract_function_constants(ea: int) -> list[dict]:
    """Extract immediate constants from a function"""
    func = idaapi.get_func(ea)
    if not func:
        return []

    constants = []
    for item_ea in idautils.FuncItems(func.start_ea):
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, item_ea) > 0:
            for op in insn.ops:
                if op.type == idaapi.o_imm:
                    constants.append(
                        {
                            "addr": hex(item_ea),
                            "value": hex(op.value),
                            "decimal": op.value,
                        }
                    )
    return constants


# ============================================================================
# Large Output Handling
# ============================================================================


def handle_large_output(result: Any, line_threshold: int = 3000) -> Any:
    """
    Handle potentially large outputs by writing to temp file if needed.

    Args:
        result: The result object to check
        line_threshold: Number of lines above which to write to file (default: 3000)

    Returns:
        Either the original result or a dict with file path if written to file
    """
    try:
        serialized = json.dumps(result, indent=2)
        line_count = serialized.count("\n") + 1

        if line_count > line_threshold:
            fd, temp_path = tempfile.mkstemp(
                suffix=".json", prefix="ida_mcp_", text=True
            )
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(serialized)

                return {
                    "type": "file_reference",
                    "path": temp_path,
                    "line_count": line_count,
                    "message": f"Output too large ({line_count} lines), written to file",
                }
            except Exception:
                os.close(fd)
                raise

        return result

    except Exception:
        return result

# Formatting helpers
def hex_ea(ea: int) -> str:
    return hex(ea)

def hex_size(size: int) -> str:
    return hex(size)
