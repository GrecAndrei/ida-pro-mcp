from collections.abc import Callable

try:
    from .zeromcp import McpHttpRequestHandler, McpRpcRegistry, McpServer, McpToolError
    from .. import __version__
except ImportError:  # flat sys.path layout used when IDA loads the plugin by file
    from zeromcp import McpHttpRequestHandler, McpRpcRegistry, McpServer, McpToolError
    try:
        from _version import __version__
    except ImportError:
        __version__ = "unknown"

MCP_SERVER = McpServer("ida-pro-mcp", version=__version__)
MCP_UNSAFE: set[str] = set()
TESTS: dict[str, tuple[Callable, str]] = {}


def test(expression: str = "") -> Callable[[Callable], Callable]:
    def decorator(func: Callable) -> Callable:
        TESTS[func.__name__] = (func, expression)
        return func

    return decorator


def tool(func):
    return MCP_SERVER.tool(func)


def resource(uri):
    return MCP_SERVER.resource(uri)


def prompt(func):
    return MCP_SERVER.prompt(func)


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    return func


__all__ = [
    "McpRpcRegistry",
    "McpServer",
    "McpToolError",
    "McpHttpRequestHandler",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "tool",
    "unsafe",
    "resource",
    "prompt",
]
