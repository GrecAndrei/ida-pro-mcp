import json
import inspect
import traceback
from typing import Any, Callable, get_type_hints, get_origin, get_args, Union, TypedDict, TypeAlias, is_typeddict, Literal, Optional

# Compatibility for Python < 3.11
try:
    from typing import NotRequired
except ImportError:
    try:
        from typing_extensions import NotRequired
    except ImportError:
        NotRequired = Optional
from types import UnionType

JsonRpcId: TypeAlias = str | int | float | None
JsonRpcParams: TypeAlias = dict[str, Any] | list[Any] | None

class JsonRpcRequest(TypedDict):
    jsonrpc: str
    method: str
    params: NotRequired[JsonRpcParams]
    id: NotRequired[JsonRpcId]

class JsonRpcError(TypedDict):
    code: int
    message: str
    data: NotRequired[Any]

class JsonRpcResponse(TypedDict):
    jsonrpc: str
    result: NotRequired[Any]
    error: NotRequired[JsonRpcError]
    id: JsonRpcId

class JsonRpcException(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data

class JsonRpcRegistry:
    def __init__(self):
        self.methods: dict[str, Callable] = {}
        self._cache: dict[Callable, tuple[inspect.Signature, dict, list[str]]] = {}
        self.redact_exceptions = False

    def method(self, func: Callable, name: str | None = None) -> Callable:
        self.methods[name or func.__name__] = func # type: ignore
        return func

    def dispatch(self, request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        try:
            if not isinstance(request, dict):
                request = json.loads(request)
            if not isinstance(request, dict):
                return self._error(None, -32600, "Invalid request: must be a JSON object")
        except Exception as e:
            return self._error(None, -32700, "JSON parse error", str(e))

        # JSON-RPC 2.0 (section 4.2): a Request object without an "id" member
        # is a Notification, and the server MUST NOT reply to it — including
        # when it is structurally invalid. Determine this up front so the
        # validation errors below are suppressed for notifications; only
        # genuinely unparseable input (non-object) still gets an error
        # response with id null (per section 5, "invalid Request" detection).
        request_id: JsonRpcId = request.get("id")
        is_notification = "id" not in request

        if request.get("jsonrpc") != "2.0":
            if is_notification:
                return None
            return self._error(None, -32600, "Invalid request: 'jsonrpc' must be '2.0'")

        method = request.get("method")
        if method is None:
            if is_notification:
                return None
            return self._error(None, -32600, "Invalid request: 'method' is required")
        if not isinstance(method, str):
            if is_notification:
                return None
            return self._error(None, -32600, "Invalid request: 'method' must be a string")

        params: JsonRpcParams = request.get("params")
        try:
            result = self._call(method, params)
            if is_notification:
                return None
            return {
                "jsonrpc": "2.0",
                "result": result,
                "id": request_id,
            }
        except JsonRpcException as e:
            if is_notification:
                return None
            return self._error(request_id, e.code, e.message, e.data)
        except Exception as e:
            if is_notification:
                return None
            error = self.map_exception(e)
            return self._error(request_id, error["code"], error["message"], error.get("data"))

    def map_exception(self, e: Exception) -> JsonRpcError:
        if self.redact_exceptions:
            return {
                "code": -32603,
                "message": f"Internal Error: {str(e)}",
            }
        return {
            "code": -32603,
            "message": "\n".join(traceback.format_exception(e)).strip() + "\n\nPlease report a bug!",
        }

    def _call(self, method: str, params: Any) -> Any:
        if method not in self.methods:
            raise JsonRpcException(-32601, f"Method '{method}' not found")

        func = self.methods[method]

        # Check for cached reflection data
        if func not in self._cache:
            sig = inspect.signature(func)
            hints = get_type_hints(func)
            hints.pop("return", None)

            # Determine required vs optional parameters. *args/**kwargs are
            # never "required": their default is always empty, so counting
            # them here would make tools/call fail with -32602 for every
            # tool whose signature ends in **kwargs (nearly all of ours,
            # e.g. `def calc(action, expr=None, **kwargs)`).
            required_params = []
            for param_name, param in sig.parameters.items():
                if param.kind in (
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                ):
                    continue
                if param.default is inspect.Parameter.empty:
                    required_params.append(param_name)

            self._cache[func] = (sig, hints, required_params)

        sig, hints, required_params = self._cache[func]

        # A **kwargs parameter means callers may pass arbitrary extra keyword
        # arguments, so the "no extra params" validation below must not
        # reject keys the signature does not declare.
        has_var_keyword = any(
            p.kind is inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values()
        )

        # Handle None params
        if params is None:
            if len(required_params) == 0:
                return func()
            else:
                raise JsonRpcException(-32602, "Missing required params")

        # Convert list params to dict by parameter names
        if isinstance(params, list):
            if len(params) < len(required_params):
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: expected at least {len(required_params)} arguments, got {len(params)}"
                )
            if len(params) > len(sig.parameters):
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: expected at most {len(sig.parameters)} arguments, got {len(params)}"
                )
            params = dict(zip(sig.parameters.keys(), params))

        # Validate dict params
        if isinstance(params, dict):
            # Check all required params are present
            missing = set(required_params) - set(params.keys())
            if missing:
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: missing required parameters: {list(missing)}"
                )

            # Check no extra params (extra kwargs are allowed only when the
            # function declares **kwargs; they flow into it below)
            if not has_var_keyword:
                extra = set(params.keys()) - set(sig.parameters.keys())
                if extra:
                    raise JsonRpcException(
                        -32602,
                        f"Invalid params: unexpected parameters: {list(extra)}"
                    )

            validated_params = {}
            for param_name, value in params.items():
                # If no type hint, pass through without validation
                if param_name not in hints:
                    validated_params[param_name] = value
                    continue

                # Has type hint, validate
                expected_type = hints[param_name]

                # Inline type validation
                origin = get_origin(expected_type)
                args = get_args(expected_type)

                # Handle None/null
                if value is None:
                    if expected_type is not type(None):
                        # Check if None is allowed in a Union
                        if not (origin in (Union, UnionType) and type(None) in args):
                            raise JsonRpcException(-32602, f"Invalid params: {param_name} cannot be null")
                    validated_params[param_name] = None
                    continue

                # Handle Union types (int | str, Optional[int], etc.)
                if origin in (Union, UnionType):
                    type_matched = False
                    for arg_type in args:
                        if arg_type is type(None):
                            continue

                        arg_origin = get_origin(arg_type)
                        check_type = arg_origin if arg_origin is not None else arg_type

                        # TypedDict cannot be used with isinstance - check for dict instead
                        if is_typeddict(arg_type):
                            check_type = dict

                        if isinstance(value, check_type):
                            type_matched = True
                            break

                    if not type_matched:
                        raise JsonRpcException(-32602, f"Invalid params: {param_name} union does not contain {type(value).__name__}")
                    validated_params[param_name] = value
                    continue

                if origin is Literal:
                    if value not in args:
                        raise JsonRpcException(-32602, f"Invalid params: {param_name} expected one of {args}, got {value}")
                    validated_params[param_name] = value
                    continue

                # Handle generic types (list[X], dict[K,V])
                if origin is not None:
                    if not isinstance(value, origin):
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} expected {origin.__name__}, got {type(value).__name__}"
                        )
                    validated_params[param_name] = value
                    continue

                # Handle TypedDict (must check before basic types)
                if is_typeddict(expected_type):
                    if not isinstance(value, dict):
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} expected dict, got {type(value).__name__}"
                        )
                    validated_params[param_name] = value
                    continue

                # Handle Any
                if expected_type is Any:
                    validated_params[param_name] = value
                    continue

                # Handle basic types
                if isinstance(expected_type, type):
                    # Allow int -> float conversion
                    if expected_type is float and isinstance(value, int):
                        validated_params[param_name] = float(value)
                        continue
                    if not isinstance(value, expected_type):
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} expected {expected_type.__name__}, got {type(value).__name__}"
                        )
                    validated_params[param_name] = value
                    continue

            return func(**validated_params)

        else:
            raise JsonRpcException(-32602, "Invalid params: must be array or object")

    def _error(self, request_id: JsonRpcId, code: int, message: str, data: Any = None) -> JsonRpcResponse | None:
        error: JsonRpcError = {
            "code": code,
            "message": message,
        }
        if data is not None:
            error["data"] = data
        return {
            "jsonrpc": "2.0",
            "error": error,
            "id": request_id,
        }
