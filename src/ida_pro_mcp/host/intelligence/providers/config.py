"""Strict provider configuration for Jev/custom/disabled intelligence.

Configuration is intentionally fail-closed.  The old embedding, Gemini, and
native settings are not interpreted as provider selection and cause an
explicit configuration error when present.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import SplitResult, urlsplit

from .types import _SECRET_KEY_RE, _SECRET_VALUE_RE, ProviderCapabilities, ProviderConfigError

MODES = frozenset({"jev", "custom", "disabled"})
JEV_BASE_URL = "https://api.typesafe.ai"
JEV_INVOKE_PATH = "/v1/systemone"
JEV_DEFAULT_MODEL = "jev-latest"
JEV_DEFAULT_INPUT_USD_PER_MTOK = 0.042
JEV_DEFAULT_OUTPUT_USD_PER_MTOK = 0.0
CONFIG_FILE_NAME = "intelligence.json"
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_SAFE_MAPPING_PATH_RE = re.compile(
    r"^\$(?:state|model|questions|answers|usage|response|body)"
    r"(?:\.[A-Za-z_][A-Za-z0-9_-]{0,63})*"
    r"(?:\[\*\](?:\.[A-Za-z_][A-Za-z0-9_-]{0,63})*)?$"
)

# These settings represented implicit backend selection in the old runtime.
# They must not silently become Jev or custom.
LEGACY_PROVIDER_STATE_KEYS = frozenset(
    {
        "backend",
        "provider_type",
        "provider_name",
        "embed_backend",
        "embed_model",
        "embedder",
        "gemini_model",
        "gemini_dimension",
        "rerank",
        "reranker",
        "native",
    }
)

LEGACY_PROVIDER_ENV_VARS = (
    "IDA_MCP_BACKEND",
    "IDA_MCP_PROVIDER",
    "IDA_MCP_INTELLIGENCE_PROVIDER",
    "IDA_MCP_INTELLIGENCE_BACKEND",
    "IDA_MCP_MODEL_PATH",
    "IDA_MCP_ENABLE_NATIVE_EMBED",
    "IDA_MCP_ENABLE_NATIVE_RERANK",
    "IDA_MCP_EMBED_BACKEND",
    "IDA_MCP_EMBED_MODEL",
    "IDA_MCP_EMBED_SERVER_BIN",
    "IDA_MCP_EMBED_PROFILE",
    "IDA_MCP_EMBED_DISABLED",
    "IDA_MCP_EMBED_CTX",
    "IDA_MCP_EMBED_BATCH",
    "IDA_MCP_NATIVE",
    "IDA_MCP_NATIVE_LIB",
    "IDA_MCP_NATIVE_KV",
    "IDA_MCP_RERANK_ENABLED",
    "IDA_MCP_RERANK_DISABLED",
    "IDA_MCP_RERANK_MODEL",
    "IDA_MCP_RERANK_PROFILE",
    "IDA_MCP_RERANK_POOL",
    "IDA_MCP_RERANK_TIMEOUT",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "IDA_MCP_GEMINI_MODEL",
    "IDA_MCP_GEMINI_DIM",
    "IDA_MCP_GEMINI_VERTEX",
    "IDA_MCP_GEMINI_API_KEY",
)

@dataclass(frozen=True)
class AuthConfig:
    source: str = "env"
    env_var: str | None = None
    file_path: str | None = None
    header: str = "Authorization"
    prefix: str = "Bearer "
    secret_reader: Callable[[], str] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.source not in {"env", "file"}:
            raise ProviderConfigError("authentication source is invalid")
        if self.source == "env" and not self.env_var:
            raise ProviderConfigError("authentication environment variable is required")
        if self.source == "file" and not self.file_path:
            raise ProviderConfigError("authentication secret file is required")
        if not _ENV_NAME_RE.fullmatch(self.env_var or "") and self.source == "env":
            raise ProviderConfigError("authentication environment variable name is invalid")
        if (
            not isinstance(self.header, str)
            or any(ord(char) < 0x20 for char in self.header)
            or not _HEADER_NAME_RE.fullmatch(self.header)
        ):
            raise ProviderConfigError("authentication header name is invalid")
        if (
            not isinstance(self.prefix, str)
            or any(ord(char) < 0x20 for char in self.prefix)
            or len(self.prefix) > 64
            or _SECRET_VALUE_RE.search(self.prefix)
            or not re.fullmatch(r"(?:[A-Za-z][A-Za-z0-9._-]{0,31} )?", self.prefix)
        ):
            raise ProviderConfigError("authentication prefix is invalid")

    def read_secret(self) -> str:
        """Read a bounded credential at request time without logging it."""
        try:
            if self.source == "env":
                if self.secret_reader is not None:
                    value = self.secret_reader()
                else:
                    value = os.environ.get(self.env_var or "", "")
            else:
                secret_path = Path(str(self.file_path))
                if secret_path.is_symlink() or not secret_path.is_file():
                    return ""
                with secret_path.open("r", encoding="utf-8") as handle:
                    value = handle.read(4097)
        except (OSError, UnicodeError):
            return ""
        secret = str(value or "").strip()
        return secret if len(secret) <= 4096 else ""

    def present(self) -> bool:
        return bool(self.read_secret())


@dataclass(frozen=True)
class ProviderConfig:
    mode: str
    provider_id: str
    protocol: str = "typed_questions"
    model: str | None = None
    base_url: str | None = None
    invoke_path: str = "/v1/systemone"
    allowed_origins: tuple[str, ...] = ()
    local_http: bool = False
    auth: AuthConfig | None = None
    capabilities: ProviderCapabilities = field(default_factory=ProviderCapabilities)
    data_policy: str = "compact_only"
    mapping_version: int = 1
    request_mapping: dict[str, Any] = field(default_factory=dict)
    response_mapping: dict[str, Any] = field(default_factory=dict)
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 30.0
    total_timeout_seconds: float = 60.0
    max_attempts: int = 3
    backoff_initial_seconds: float = 0.5
    backoff_max_seconds: float = 8.0
    max_input_chars: int = 262_144
    max_questions: int = 64
    max_response_bytes: int = 1_048_576
    input_usd_per_mtok: float | None = None
    output_usd_per_mtok: float | None = None
    allow_unknown_pricing: bool = False

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ProviderConfigError("provider mode must be jev, custom, or disabled")
        if (
            not isinstance(self.provider_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", self.provider_id)
            or _SECRET_KEY_RE.search(self.provider_id)
        ):
            raise ProviderConfigError("provider id is required and must be non-sensitive")
        if self.mode != "disabled" and self.protocol != "typed_questions":
            raise ProviderConfigError("provider protocol must be typed_questions")
        if self.mode != "disabled":
            _validate_path(self.invoke_path, name="provider invoke path", default="/v1/systemone")
        if not isinstance(self.allowed_origins, (tuple, list)):
            raise ProviderConfigError("provider origin allowlist must be a sequence")
        if self.mode != "disabled" and (not self.model or not str(self.model).strip()):
            raise ProviderConfigError("enabled providers require a model")
        if self.mode == "jev":
            if self.base_url != JEV_BASE_URL or self.invoke_path != JEV_INVOKE_PATH:
                raise ProviderConfigError("the Jev endpoint is fixed and cannot be overridden")
            if self.data_policy != "compact_only":
                raise ProviderConfigError("Jev providers must use the compact_only data policy")
        if self.mode == "custom":
            if not self.base_url or not self.allowed_origins:
                raise ProviderConfigError("custom providers require an explicit base URL and origin allowlist")
            base_origin, _ = _validate_origin(self.base_url, name="custom base_url", local_http=self.local_http)
            allowed = {
                _validate_origin(origin, name="custom allowed origin", local_http=self.local_http)[0]
                for origin in self.allowed_origins
            }
            if base_origin not in allowed:
                raise ProviderConfigError("custom base_url is not in the explicit origin allowlist")
        if self.data_policy not in {"local_only", "compact_only"}:
            raise ProviderConfigError("provider data policy is invalid")
        try:
            input_limit = int(self.max_input_chars)
            question_limit = int(self.max_questions)
            response_limit = int(self.max_response_bytes)
        except (TypeError, ValueError, OverflowError):
            raise ProviderConfigError("provider limits are malformed") from None
        if (
            isinstance(self.max_input_chars, bool)
            or isinstance(self.max_questions, bool)
            or isinstance(self.max_response_bytes, bool)
            or not (
                1 <= input_limit <= 1_000_000
                and 1 <= question_limit <= 64
                and 1_024 <= response_limit <= 16_777_216
            )
        ):
            raise ProviderConfigError("provider limits are outside their allowed ranges")
        try:
            attempts = int(self.max_attempts)
            backoff_initial = float(self.backoff_initial_seconds)
            backoff_max = float(self.backoff_max_seconds)
        except (TypeError, ValueError):
            raise ProviderConfigError("provider retry settings are malformed") from None
        if isinstance(self.max_attempts, bool) or not 1 <= attempts <= 5:
            raise ProviderConfigError("provider max_attempts is outside its allowed range")
        if not math.isfinite(backoff_initial) or not math.isfinite(backoff_max) or backoff_initial < 0 or backoff_max < backoff_initial:
            raise ProviderConfigError("provider retry backoffs are malformed")
        for name in ("connect_timeout_seconds", "read_timeout_seconds", "total_timeout_seconds"):
            value = float(getattr(self, name))
            if not math.isfinite(value) or value <= 0:
                raise ProviderConfigError("provider timeouts must be finite and positive")
        for name in ("input_usd_per_mtok", "output_usd_per_mtok"):
            value = getattr(self, name)
            if value is not None and (not math.isfinite(float(value)) or float(value) < 0):
                raise ProviderConfigError("provider prices must be finite and non-negative")

    @property
    def origin(self) -> str | None:
        if not self.base_url:
            return None
        return _origin(self.base_url)

    def safe_dict(self) -> dict[str, Any]:
        """Serialize status-safe configuration; never includes credential sources."""
        def label(value: Any, limit: int = 256) -> str | None:
            text = str(value or "").replace("\x00", "").replace("\r", " ").replace("\n", " ")[:limit]
            return "<redacted>" if _SECRET_KEY_RE.search(text) else (text or None)

        return {
            "mode": self.mode,
            "provider": label(self.provider_id, 128),
            "protocol": label(self.protocol, 64),
            "model": label(self.model),
            "base_url": self.origin,
            "allowed_origins": list(self.allowed_origins),
            "capabilities": self.capabilities.names(),
            "data_policy": self.data_policy,
            "mapping_version": self.mapping_version,
            "timeouts": {
                "connect_seconds": self.connect_timeout_seconds,
                "read_seconds": self.read_timeout_seconds,
                "total_seconds": self.total_timeout_seconds,
            },
            "limits": {
                "max_input_chars": self.max_input_chars,
                "max_questions": self.max_questions,
                "max_response_bytes": self.max_response_bytes,
            },
            "pricing_configured": self.input_usd_per_mtok is not None and self.output_usd_per_mtok is not None,
        }


def _bool_value(value: Any, *, name: str, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    raw = str(value).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ProviderConfigError(f"{name} must be true or false")


def _int_value(value: Any, *, name: str, default: int, minimum: int, maximum: int) -> int:
    if value is None or value == "":
        return default
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise ProviderConfigError(f"{name} must be an integer") from None
    if not minimum <= result <= maximum:
        raise ProviderConfigError(f"{name} is outside its allowed range")
    return result


def _float_value(value: Any, *, name: str, default: float, minimum: float, maximum: float) -> float:
    if value is None or value == "":
        return default
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ProviderConfigError(f"{name} must be a number") from None
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ProviderConfigError(f"{name} is outside its allowed range")
    return result


def _safe_identifier(value: Any, *, name: str, default: str = "") -> str:
    text = str(value or default).strip()
    if not text or len(text) > 256 or _SECRET_KEY_RE.search(text):
        raise ProviderConfigError(f"{name} is required and must be non-sensitive")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", text):
        raise ProviderConfigError(f"{name} contains unsupported characters")
    return text


def _price_value(value: Any, *, name: str) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    result = _float_value(value, name=name, default=0.0, minimum=0.0, maximum=1_000_000.0)
    return result


def _split_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _read_state_file(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path).expanduser())
    explicit = os.environ.get("IDA_MCP_INTELLIGENCE_CONFIG", "").strip()
    if explicit:
        candidates.append(Path(explicit).expanduser())
    cache_dir = os.environ.get("IDA_MCP_CACHE_DIR") or os.environ.get("IDA_MCP_DATA_DIR")
    if cache_dir:
        candidates.append(Path(cache_dir).expanduser() / CONFIG_FILE_NAME)
    install_root = os.environ.get("IDA_PRO_MCP_HOME")
    if install_root:
        candidates.append(Path(install_root).expanduser() / CONFIG_FILE_NAME)
    candidates.extend(
        [
            Path.home() / ".config" / "ida-pro-mcp" / CONFIG_FILE_NAME,
            Path.home() / ".local" / "state" / "ida-pro-mcp" / CONFIG_FILE_NAME,
        ]
    )
    seen: set[str] = set()
    for candidate in candidates:
        try:
            normalized = str(candidate.resolve())
        except OSError:
            normalized = str(candidate.absolute())
        if normalized in seen or not candidate.is_file():
            continue
        seen.add(normalized)
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ProviderConfigError("intelligence configuration file is unreadable") from None
        if not isinstance(payload, dict):
            raise ProviderConfigError("intelligence configuration file must contain an object")
        return payload
    return {}


def _state_provider(state: Mapping[str, Any]) -> dict[str, Any]:
    provider = state.get("provider", {})
    if provider is None:
        return {}
    if not isinstance(provider, Mapping):
        raise ProviderConfigError("provider configuration must be an object")
    return dict(provider)


def _require_object_fields(value: Any, *, name: str, allowed: set[str]) -> Mapping[str, Any] | None:
    """Validate optional nested configuration objects without accepting drift."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ProviderConfigError(f"{name} must be an object")
    unknown = {str(key) for key in value if str(key) not in allowed}
    if unknown:
        raise ProviderConfigError(f"{name} contains unsupported fields")
    return value


def _reject_persisted_secrets(value: Any, *, path: str = "") -> None:
    """Reject credential values while allowing safe token-budget metadata."""
    del path
    secret_name = re.compile(
        r"(?:(?:api[_-]?key|secret|password|passwd|authorization|credential)(?:[_-].*)?"
        r"|(?:access[_-]?token|refresh[_-]?token|bearer[_-]?token))$",
        re.IGNORECASE,
    )
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key)
            if secret_name.search(name) or name.lower() in {"token", "key"}:
                raise ProviderConfigError("credentials must be supplied at request time, not persisted")
            _reject_persisted_secrets(item, path="")
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_persisted_secrets(item, path="")


def validate_mapping(value: Any, *, name: str = "mapping", max_depth: int = 6) -> dict[str, Any]:
    """Validate the closed custom mapping DSL and return a detached copy."""
    if value in (None, {}):
        return {}
    if not isinstance(value, Mapping):
        raise ProviderConfigError(f"{name} must be an object")

    def walk(item: Any, depth: int) -> Any:
        if depth > max_depth:
            raise ProviderConfigError(f"{name} is too deeply nested")
        if callable(item):
            raise ProviderConfigError(f"{name} cannot contain executable values")
        if isinstance(item, str):
            if item.startswith("$") and not _SAFE_MAPPING_PATH_RE.fullmatch(item):
                raise ProviderConfigError(f"{name} contains an unsupported placeholder")
            if any(token in item for token in ("{{", "}}", "=>", "__", ";")):
                raise ProviderConfigError(f"{name} contains an executable expression")
            if _SECRET_VALUE_RE.search(item):
                raise ProviderConfigError(f"{name} contains a credential-like constant")
            return item[:512]
        if item is None or isinstance(item, (bool, int, float)):
            if isinstance(item, float) and not math.isfinite(item):
                raise ProviderConfigError(f"{name} contains a non-finite constant")
            return item
        if isinstance(item, Mapping):
            if len(item) > 64:
                raise ProviderConfigError(f"{name} contains too many fields")
            result: dict[str, Any] = {}
            for key, child in item.items():
                key_text = str(key)
                safe_usage_key = key_text in {"input_tokens", "output_tokens", "total_tokens", "estimated"}
                if not key_text or len(key_text) > 128 or (_SECRET_KEY_RE.search(key_text) and not safe_usage_key):
                    raise ProviderConfigError(f"{name} contains a sensitive or invalid field name")
                result[key_text] = walk(child, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            if len(item) > 64:
                raise ProviderConfigError(f"{name} contains too many list entries")
            # Wildcards are represented by a one-item list.  Nested list
            # wildcards are intentionally not accepted.
            return [walk(child, depth + 1) for child in item]
        raise ProviderConfigError(f"{name} contains an unsupported value")

    result = walk(dict(value), 0)
    return result if isinstance(result, dict) else {}


def _validate_path(value: Any, *, name: str, default: str) -> str:
    path = str(value or default)
    parsed = urlsplit(path)
    if not path.startswith("/") or parsed.query or parsed.fragment or "//" in path:
        raise ProviderConfigError(f"{name} must be a relative path without query or fragment")
    if any(part in {"", ".", ".."} for part in path.split("/")[1:]):
        raise ProviderConfigError(f"{name} contains unsafe path components")
    if len(path) > 512 or not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", path):
        raise ProviderConfigError(f"{name} contains unsupported path characters")
    return path


def _host_is_loopback(host: str) -> bool:
    lowered = host.strip("[]").lower()
    if lowered == "localhost":
        return True
    try:
        return ipaddress.ip_address(lowered).is_loopback
    except ValueError:
        return False


def _reject_literal_private_host(host: str) -> None:
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return
    if address.is_private or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified:
        raise ProviderConfigError("cloud provider origins cannot target private or special-use addresses")


def _split_url(value: Any, *, name: str) -> SplitResult:
    raw = str(value or "").strip()
    if not raw or len(raw) > 2048:
        raise ProviderConfigError(f"{name} is required and bounded")
    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.hostname or parsed.username or parsed.password:
        raise ProviderConfigError(f"{name} must be an origin without credentials")
    if parsed.query or parsed.fragment:
        raise ProviderConfigError(f"{name} cannot contain a query or fragment")
    try:
        _port = parsed.port
    except ValueError:
        raise ProviderConfigError(f"{name} has an invalid port") from None
    if parsed.scheme not in {"https", "http"}:
        raise ProviderConfigError(f"{name} must use https or explicitly allowed local http")
    return parsed


def _origin(value: str) -> str:
    parsed = _split_url(value, name="base_url")
    host = parsed.hostname or ""
    port = parsed.port
    if (parsed.scheme == "https" and port in (None, 443)) or (parsed.scheme == "http" and port == 80):
        authority = host if ":" not in host else f"[{host}]"
    else:
        authority = f"{host}:{port}"
    return f"{parsed.scheme}://{authority}".lower()


def _validate_origin(value: Any, *, name: str, local_http: bool) -> tuple[str, str]:
    parsed = _split_url(value, name=name)
    host = parsed.hostname or ""
    if parsed.scheme == "http":
        if not local_http or not _host_is_loopback(host):
            raise ProviderConfigError("HTTP custom origins require local_http and a loopback host")
    else:
        _reject_literal_private_host(host)
    if parsed.path not in {"", "/"}:
        raise ProviderConfigError(f"{name} must be an origin without a path")
    return _origin(value), parsed.scheme


def _auth_from(
    provider: Mapping[str, Any],
    *,
    default_env: str,
    env: Mapping[str, str],
    live_process_env: bool = False,
) -> AuthConfig:
    raw_auth = provider.get("auth", {})
    if raw_auth is None:
        raw_auth = {}
    if not isinstance(raw_auth, Mapping):
        raise ProviderConfigError("auth must be an object")
    _require_object_fields(
        raw_auth,
        name="auth",
        allowed={"source", "env_var", "file_path", "header", "prefix"},
    )
    raw_source = raw_auth.get("source")
    default_file = env.get("TYPESAFE_API_KEY_FILE") if default_env == "TYPESAFE_API_KEY" else env.get("IDA_MCP_CUSTOM_API_KEY_FILE")
    raw_file = raw_auth.get("file_path")
    if raw_file and default_file and os.path.abspath(os.path.expanduser(str(raw_file))) != os.path.abspath(os.path.expanduser(str(default_file))):
        raise ProviderConfigError("authentication secret file selectors conflict")
    env_var = raw_auth.get("env_var") or env.get("IDA_MCP_CUSTOM_API_KEY_ENV") or default_env
    file_path = raw_file or default_file
    # ``env`` is already the complete source of truth: normal resolution
    # passes a copy of os.environ, while tests and embedded callers pass an
    # explicit isolated mapping.  Do not merge the ambient process back in;
    # doing so could unexpectedly select or leak an operator credential.
    credential_names = {str(default_env), str(env_var)}
    env_credential_present = any(str(env.get(name) or "").strip() for name in credential_names)
    source = str(raw_source or ("file" if file_path else "env")).lower()
    if source == "file":
        # The installer may emit the custom default selector alongside a file
        # path for a stable client-config shape.  That selector is harmless
        # until a credential is actually present; a non-default selector or an
        # explicit persisted selector would otherwise be silently ignored.
        custom_selector = str(env.get("IDA_MCP_CUSTOM_API_KEY_ENV") or "").strip()
        if raw_auth.get("env_var") or (custom_selector and custom_selector != default_env):
            raise ProviderConfigError("authentication source selectors conflict")
        if env_credential_present:
            raise ProviderConfigError("authentication sources conflict; configure an environment variable or a secret file, not both")
        if not file_path:
            raise ProviderConfigError("secret file authentication requires a file path")
        # Do not read or log the file here; this validates only the path shape.
        file_path = os.path.abspath(os.path.expanduser(str(file_path)))
        if "\x00" in file_path or len(file_path) > 4096:
            raise ProviderConfigError("authentication secret file path is malformed")
    elif source == "env":
        if file_path:
            raise ProviderConfigError("authentication source selectors conflict")
        file_path = None
    else:
        raise ProviderConfigError("auth source must be env or file")
    # Read the selected source at request time so key rotation is observed.
    # ``env`` is an isolated snapshot for explicit resolution and is the
    # process environment snapshot for normal launches.
    source_env = env
    source_name = str(env_var)

    def _read_env() -> str:
        # Normal process resolution keeps the selected environment variable
        # live so key rotation is observed without rebuilding the provider.
        # Explicit environment mappings remain isolated for tests and embedded
        # callers, and therefore use the supplied snapshot only.
        source = os.environ if live_process_env else source_env
        return str(source.get(source_name) or "").strip()

    if source == "env" and default_env == "TYPESAFE_API_KEY" and str(env_var) != default_env:
        raise ProviderConfigError("Jev authentication must use TYPESAFE_API_KEY")
    return AuthConfig(
        source=source,
        env_var=str(env_var) if source == "env" else None,
        file_path=file_path,
        header=str(raw_auth.get("header") or "Authorization"),
        prefix=str(raw_auth.get("prefix") if raw_auth.get("prefix") is not None else "Bearer "),
        secret_reader=_read_env if source == "env" else None,
    )


def _mode_from(state: Mapping[str, Any], env: Mapping[str, str]) -> str:
    state_mode = state.get("intelligence_mode", state.get("mode"))
    provider = _state_provider(state)
    provider_mode = provider.get("mode")
    if state_mode is not None and provider_mode is not None and str(state_mode).strip().lower() != str(provider_mode).strip().lower():
        raise ProviderConfigError("persisted intelligence modes conflict")
    if state_mode is None and provider_mode is not None:
        state_mode = provider_mode
    env_mode = env.get("IDA_MCP_INTELLIGENCE_MODE")
    normalized_env = str(env_mode).strip().lower() if env_mode is not None and str(env_mode).strip() else None
    normalized_state = str(state_mode).strip().lower() if state_mode is not None and str(state_mode).strip() else None
    if normalized_env and normalized_env not in MODES:
        raise ProviderConfigError("IDA_MCP_INTELLIGENCE_MODE must be jev, custom, or disabled")
    if normalized_state and normalized_state not in MODES:
        raise ProviderConfigError("persisted intelligence mode must be jev, custom, or disabled")
    if normalized_env and normalized_state and normalized_env != normalized_state:
        raise ProviderConfigError("environment and persisted intelligence modes conflict")
    return normalized_env or normalized_state or "disabled"


def _conflicting_provider_settings(mode: str, env: Mapping[str, str], provider: Mapping[str, Any]) -> list[str]:
    """Return provider-specific settings that do not belong to *mode*."""
    jev_names = {
        "IDA_MCP_JEV_BASE_URL",
        "IDA_MCP_JEV_MODEL",
        "IDA_MCP_JEV_INPUT_USD_PER_MTOK",
        "IDA_MCP_JEV_OUTPUT_USD_PER_MTOK",
        "IDA_MCP_JEV_CONNECT_TIMEOUT",
        "IDA_MCP_JEV_READ_TIMEOUT",
        "IDA_MCP_JEV_TIMEOUT",
        "IDA_MCP_JEV_MAX_ATTEMPTS",
        "IDA_MCP_JEV_MAX_RESPONSE_BYTES",
        "IDA_MCP_JEV_MAX_INPUT_CHARS",
        "IDA_MCP_JEV_MAX_QUESTIONS",
        "IDA_MCP_JEV_ALLOW_UNKNOWN_PRICING",
    }
    custom_names = {
        "IDA_MCP_CUSTOM_BASE_URL",
        "IDA_MCP_CUSTOM_ALLOWED_ORIGINS",
        "IDA_MCP_CUSTOM_MODEL",
        "IDA_MCP_CUSTOM_PROVIDER_ID",
        "IDA_MCP_CUSTOM_PROTOCOL",
        "IDA_MCP_CUSTOM_API_KEY_ENV",
        "IDA_MCP_CUSTOM_API_KEY_FILE",
        "IDA_MCP_CUSTOM_LOCAL_HTTP",
        "IDA_MCP_CUSTOM_REQUEST_MAPPING",
        "IDA_MCP_CUSTOM_RESPONSE_MAPPING",
        "IDA_MCP_CUSTOM_INVOKE_PATH",
        "IDA_MCP_CUSTOM_CONNECT_TIMEOUT",
        "IDA_MCP_CUSTOM_READ_TIMEOUT",
        "IDA_MCP_CUSTOM_TIMEOUT",
        "IDA_MCP_CUSTOM_MAX_ATTEMPTS",
        "IDA_MCP_CUSTOM_MAX_INPUT_CHARS",
        "IDA_MCP_CUSTOM_MAX_QUESTIONS",
        "IDA_MCP_CUSTOM_MAX_RESPONSE_BYTES",
        "IDA_MCP_CUSTOM_INPUT_USD_PER_MTOK",
        "IDA_MCP_CUSTOM_OUTPUT_USD_PER_MTOK",
        "IDA_MCP_CUSTOM_ALLOW_UNKNOWN_PRICING",
    }
    auth_names = {"TYPESAFE_API_KEY", "TYPESAFE_API_KEY_FILE", "CUSTOM_PROVIDER_API_KEY"}
    configured: list[str] = []
    if mode == "disabled":
        configured.extend(name for name in (*jev_names, *custom_names, *auth_names) if str(env.get(name, "")).strip())
        if provider:
            configured.extend(str(key) for key in provider if str(key) not in {"mode"})
    elif mode == "jev":
        configured.extend(name for name in custom_names if str(env.get(name, "")).strip())
        configured.extend(name for name in ("CUSTOM_PROVIDER_API_KEY",) if str(env.get(name, "")).strip())
        # Accept only the canonical persisted Jev fields.  The endpoint and
        # invoke path remain immutable and are validated below.
        allowed_provider = {
            "mode", "id", "protocol", "model", "capabilities", "base_url", "paths",
            "auth", "data_policy", "input_usd_per_mtok", "output_usd_per_mtok",
            "allow_unknown_pricing", "connect_timeout_seconds", "read_timeout_seconds",
            "total_timeout_seconds", "max_attempts", "max_response_bytes",
            "max_input_chars", "max_questions",
        }
        for key in provider:
            if str(key) not in allowed_provider:
                configured.append(str(key))
        paths = provider.get("paths")
        if isinstance(paths, Mapping) and paths.get("invoke") not in (None, JEV_INVOKE_PATH):
            configured.append("paths.invoke")
        if str(provider.get("base_url") or "").rstrip("/") not in {"", JEV_BASE_URL}:
            configured.append("base_url")
    elif mode == "custom":
        configured.extend(name for name in jev_names if str(env.get(name, "")).strip())
        configured.extend(name for name in ("TYPESAFE_API_KEY", "TYPESAFE_API_KEY_FILE") if str(env.get(name, "")).strip())
        configured.extend(str(key) for key in provider if str(key) in {"gemini_model", "native", "embed_model"})
        allowed_provider = {
            "mode", "id", "protocol", "model", "capabilities", "base_url",
            "allowed_origins", "local_http", "auth", "paths", "data_policy",
            "mapping_version", "request_mapping", "response_mapping", "timeouts",
            "retries", "limits", "input_usd_per_mtok", "output_usd_per_mtok",
            "allow_unknown_pricing", "connect_timeout_seconds", "read_timeout_seconds",
            "total_timeout_seconds", "max_attempts", "max_input_chars", "max_questions",
            "max_response_bytes",
        }
        for key in provider:
            if str(key) not in allowed_provider:
                configured.append(str(key))
    return sorted(set(configured))


def _legacy_configured(env: Mapping[str, str]) -> list[str]:
    names = set(LEGACY_PROVIDER_ENV_VARS)
    for name in env:
        text = str(name)
        if text.startswith((
            "IDA_MCP_EMBED_",
            "IDA_MCP_EMBEDDING_",
            "IDA_MCP_RERANK_",
            "IDA_MCP_GEMINI_",
            "IDA_MCP_NATIVE_",
            "IDA_MCP_ENABLE_NATIVE_",
        )):
            names.add(text)
    return sorted(name for name in names if str(env.get(name, "")).strip())


def resolve_provider_config(
    *,
    env: Mapping[str, str] | None = None,
    state: Mapping[str, Any] | None = None,
    state_path: str | os.PathLike[str] | None = None,
) -> ProviderConfig:
    """Resolve and validate the only supported intelligence modes."""
    live_process_env = env is None
    values = dict(os.environ if env is None else env)
    # Explicit dependency-injected environment maps are isolated from the
    # operator's on-disk configuration unless a state path/map is supplied.
    # This keeps validation deterministic and prevents an unrelated profile
    # from changing a test or embedded host's selected mode.
    if state is None and state_path is None and env is not None:
        persisted = {}
    else:
        persisted = dict(_read_state_file(state_path) if state is None else state)
    _reject_persisted_secrets(persisted)
    if "schema_version" in persisted:
        try:
            schema_version = int(persisted["schema_version"])
        except (TypeError, ValueError):
            raise ProviderConfigError("intelligence configuration schema_version is invalid") from None
        if schema_version not in {1, 2}:
            raise ProviderConfigError("intelligence configuration schema_version is unsupported")
    mode = _mode_from(persisted, values)
    legacy = _legacy_configured(values)
    if legacy:
        raise ProviderConfigError(
            "legacy intelligence provider settings are unsupported; choose jev, custom, or disabled",
            details={"legacy_settings": legacy},
        )

    unknown_state = set(persisted) - {"schema_version", "mode", "intelligence_mode", "provider"} - LEGACY_PROVIDER_STATE_KEYS
    if unknown_state:
        raise ProviderConfigError(
            "intelligence configuration contains unsupported fields",
            details={"fields": sorted(str(item) for item in unknown_state)},
        )
    provider = _state_provider(persisted)
    conflicts = _conflicting_provider_settings(mode, values, provider)
    if conflicts:
        raise ProviderConfigError(
            "intelligence settings conflict with the selected provider mode",
            details={"conflicting_settings": conflicts},
        )
    legacy_state = set(LEGACY_PROVIDER_STATE_KEYS.intersection(str(key) for key in persisted))
    legacy_state.update(
        LEGACY_PROVIDER_STATE_KEYS.intersection(str(key) for key in provider)
    )
    if legacy_state:
        raise ProviderConfigError(
            "legacy persisted intelligence settings are unsupported; choose jev, custom, or disabled",
            details={"legacy_settings": sorted(legacy_state)},
        )
    # Validate budget settings during provider resolution as well as ledger
    # construction, so status/configuration calls fail closed instead of
    # reporting a seemingly healthy provider with unusable limits.
    from .usage_accounting import BudgetConfig

    BudgetConfig.from_env(values)
    if mode == "disabled":
        return ProviderConfig(
            mode="disabled",
            provider_id="disabled",
            model=None,
            capabilities=ProviderCapabilities(lexical_fallback=True),
            data_policy="local_only",
        )

    if mode == "jev":
        requested_url = values.get("IDA_MCP_JEV_BASE_URL") or provider.get("base_url")
        paths = _require_object_fields(provider.get("paths"), name="provider.paths", allowed={"invoke"})
        if provider.get("paths") is not None and paths is None:
            raise ProviderConfigError("provider.paths is malformed")
        if str(provider.get("protocol") or "typed_questions").strip().lower() != "typed_questions":
            raise ProviderConfigError("Jev provider protocol must be typed_questions")
        if str(provider.get("data_policy") or "compact_only").strip().lower() != "compact_only":
            raise ProviderConfigError("Jev providers must use the compact_only data policy")
        provider_capabilities = provider.get("capabilities")
        if provider_capabilities is not None:
            capability_names = {str(item).strip().lower() for item in _split_values(provider_capabilities)}
            if capability_names - {"classify", "score"}:
                raise ProviderConfigError("Jev capabilities are fixed to classify and score")
        if requested_url and str(requested_url).rstrip("/") != JEV_BASE_URL:
            raise ProviderConfigError("the Jev endpoint is fixed and cannot be overridden")
        auth = _auth_from(
            provider,
            default_env="TYPESAFE_API_KEY",
            env=values,
            live_process_env=live_process_env,
        )
        if auth.header != "Authorization" or auth.prefix != "Bearer ":
            raise ProviderConfigError("Jev authentication must use the Authorization bearer header")
        model = _safe_identifier(values.get("IDA_MCP_JEV_MODEL") or provider.get("model"), name="IDA_MCP_JEV_MODEL", default=JEV_DEFAULT_MODEL)
        input_price = _price_value(values.get("IDA_MCP_JEV_INPUT_USD_PER_MTOK", provider.get("input_usd_per_mtok")), name="jev input price")
        output_price = _price_value(values.get("IDA_MCP_JEV_OUTPUT_USD_PER_MTOK", provider.get("output_usd_per_mtok")), name="jev output price")
        if input_price is None:
            input_price = JEV_DEFAULT_INPUT_USD_PER_MTOK
        if output_price is None:
            output_price = JEV_DEFAULT_OUTPUT_USD_PER_MTOK
        return ProviderConfig(
            mode="jev",
            provider_id="typesafe-jev",
            model=model,
            base_url=JEV_BASE_URL,
            invoke_path=JEV_INVOKE_PATH,
            auth=auth,
            capabilities=ProviderCapabilities(classify=True, score=True, lexical_fallback=True),
            data_policy="compact_only",
            input_usd_per_mtok=input_price,
            output_usd_per_mtok=output_price,
            allow_unknown_pricing=_bool_value(values.get("IDA_MCP_JEV_ALLOW_UNKNOWN_PRICING", provider.get("allow_unknown_pricing")), name="jev unknown pricing", default=False),
            connect_timeout_seconds=_float_value(
                values.get("IDA_MCP_JEV_CONNECT_TIMEOUT", provider.get("connect_timeout_seconds")), name="jev connect timeout", default=5.0, minimum=0.1, maximum=60.0
            ),
            read_timeout_seconds=_float_value(values.get("IDA_MCP_JEV_READ_TIMEOUT", provider.get("read_timeout_seconds")), name="jev read timeout", default=30.0, minimum=0.1, maximum=300.0),
            total_timeout_seconds=_float_value(values.get("IDA_MCP_JEV_TIMEOUT", provider.get("total_timeout_seconds")), name="jev total timeout", default=60.0, minimum=0.1, maximum=600.0),
            max_attempts=_int_value(values.get("IDA_MCP_JEV_MAX_ATTEMPTS", provider.get("max_attempts")), name="jev max attempts", default=3, minimum=1, maximum=5),
            max_response_bytes=_int_value(
                values.get("IDA_MCP_JEV_MAX_RESPONSE_BYTES", provider.get("max_response_bytes")), name="jev max response bytes", default=1_048_576, minimum=1024, maximum=16_777_216
            ),
            max_input_chars=_int_value(
                values.get("IDA_MCP_JEV_MAX_INPUT_CHARS", provider.get("max_input_chars")), name="jev max input chars", default=262_144, minimum=1024, maximum=1_000_000
            ),
            max_questions=_int_value(
                values.get("IDA_MCP_JEV_MAX_QUESTIONS", provider.get("max_questions")), name="jev max questions", default=64, minimum=1, maximum=64
            ),
        )

    # custom
    paths = _require_object_fields(provider.get("paths"), name="provider.paths", allowed={"invoke"})
    timeouts = _require_object_fields(
        provider.get("timeouts"),
        name="provider.timeouts",
        allowed={"connect_seconds", "read_seconds", "total_seconds"},
    )
    retries = _require_object_fields(
        provider.get("retries"),
        name="provider.retries",
        allowed={"max_attempts", "backoff_initial_seconds", "backoff_max_seconds"},
    )
    limits = _require_object_fields(
        provider.get("limits"),
        name="provider.limits",
        allowed={"max_input_chars", "max_questions", "max_response_bytes"},
    )
    base_url = values.get("IDA_MCP_CUSTOM_BASE_URL") or provider.get("base_url")
    if not base_url:
        raise ProviderConfigError("custom mode requires IDA_MCP_CUSTOM_BASE_URL")
    local_http = _bool_value(values.get("IDA_MCP_CUSTOM_LOCAL_HTTP", provider.get("local_http")), name="custom local_http", default=False)
    base_origin, _scheme = _validate_origin(base_url, name="custom base_url", local_http=local_http)
    allowed_raw = values.get("IDA_MCP_CUSTOM_ALLOWED_ORIGINS") or provider.get("allowed_origins")
    allowed_values = _split_values(allowed_raw)
    if not allowed_values:
        raise ProviderConfigError("custom mode requires an explicit HTTPS origin allowlist")
    allowed: list[str] = []
    for item in allowed_values:
        origin, _ = _validate_origin(item, name="custom allowed origin", local_http=local_http)
        allowed.append(origin)
    if base_origin not in set(allowed):
        raise ProviderConfigError("custom base_url is not in the explicit origin allowlist")
    custom_provider = dict(provider)
    custom_provider["auth"] = provider.get("auth", {})
    auth = _auth_from(
        custom_provider,
        default_env="CUSTOM_PROVIDER_API_KEY",
        env=values,
        live_process_env=live_process_env,
    )
    model = _safe_identifier(values.get("IDA_MCP_CUSTOM_MODEL") or provider.get("model"), name="custom model")
    protocol = str(values.get("IDA_MCP_CUSTOM_PROTOCOL") or provider.get("protocol") or "typed_questions").strip().lower()
    if protocol != "typed_questions":
        raise ProviderConfigError("custom mode currently supports only typed_questions")

    def _mapping_setting(value: Any, name: str, allowed_keys: set[str] | None) -> dict[str, Any]:
        if isinstance(value, str) and value.strip():
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                raise ProviderConfigError(f"{name} must be a JSON object") from None
        result = validate_mapping(value, name=name)
        if allowed_keys is not None:
            unknown = set(result) - allowed_keys
            if unknown:
                raise ProviderConfigError(f"{name} contains unsupported canonical fields")
        return result

    request_mapping = _mapping_setting(
        values.get("IDA_MCP_CUSTOM_REQUEST_MAPPING", provider.get("request_mapping", {})),
        "request_mapping",
        None,
    )
    response_mapping = _mapping_setting(
        values.get("IDA_MCP_CUSTOM_RESPONSE_MAPPING", provider.get("response_mapping", {})),
        "response_mapping",
        {"model", "answers", "usage", "request_id"},
    )
    capabilities_raw = provider.get("capabilities", ["classify", "score"])
    capabilities_list = {str(item).strip().lower() for item in _split_values(capabilities_raw)}
    unknown_capabilities = capabilities_list - {"classify", "score"}
    if unknown_capabilities:
        raise ProviderConfigError("custom capabilities contain unsupported values")
    data_policy = str(provider.get("data_policy") or "compact_only").strip().lower()
    if data_policy != "compact_only":
        raise ProviderConfigError("custom providers must use the compact_only data policy")
    return ProviderConfig(
        mode="custom",
        provider_id=_safe_identifier(provider.get("id") or values.get("IDA_MCP_CUSTOM_PROVIDER_ID"), name="custom provider id", default="operator-provider"),
        protocol=protocol,
        model=model,
        base_url=str(base_url).strip().rstrip("/"),
        invoke_path=_validate_path(
            values.get("IDA_MCP_CUSTOM_INVOKE_PATH") or (paths or {}).get("invoke"),
            name="custom invoke path",
            default="/v1/systemone",
        ),
        allowed_origins=tuple(sorted(set(allowed))),
        local_http=local_http,
        auth=auth,
        capabilities=ProviderCapabilities(
            classify="classify" in capabilities_list,
            score="score" in capabilities_list,
            embeddings=False,
            lexical_fallback=True,
        ),
        data_policy=data_policy,
        mapping_version=_int_value(provider.get("mapping_version"), name="mapping_version", default=1, minimum=1, maximum=100),
        request_mapping=request_mapping,
        response_mapping=response_mapping,
        connect_timeout_seconds=_float_value(
            values.get("IDA_MCP_CUSTOM_CONNECT_TIMEOUT", (timeouts or {}).get("connect_seconds")),
            name="custom connect timeout",
            default=5.0,
            minimum=0.1,
            maximum=60.0,
        ),
        read_timeout_seconds=_float_value(
            values.get("IDA_MCP_CUSTOM_READ_TIMEOUT", (timeouts or {}).get("read_seconds")),
            name="custom read timeout",
            default=30.0,
            minimum=0.1,
            maximum=300.0,
        ),
        total_timeout_seconds=_float_value(
            values.get("IDA_MCP_CUSTOM_TIMEOUT", (timeouts or {}).get("total_seconds")),
            name="custom total timeout",
            default=60.0,
            minimum=0.1,
            maximum=600.0,
        ),
        max_attempts=_int_value(
            values.get("IDA_MCP_CUSTOM_MAX_ATTEMPTS", (retries or {}).get("max_attempts")),
            name="custom max attempts",
            default=3,
            minimum=1,
            maximum=5,
        ),
        backoff_initial_seconds=_float_value(
            (retries or {}).get("backoff_initial_seconds"), name="custom retry backoff", default=0.5, minimum=0.0, maximum=30.0
        ),
        backoff_max_seconds=_float_value(
            (retries or {}).get("backoff_max_seconds"), name="custom retry max backoff", default=8.0, minimum=0.0, maximum=120.0
        ),
        max_input_chars=_int_value(
            values.get(
                "IDA_MCP_CUSTOM_MAX_INPUT_CHARS",
                (limits or {}).get("max_input_chars")
                if limits is not None
                else provider.get("max_input_chars"),
            ),
            name="custom max input chars",
            default=32_768,
            minimum=1024,
            maximum=1_000_000,
        ),
        max_questions=_int_value(
            values.get(
                "IDA_MCP_CUSTOM_MAX_QUESTIONS",
                (limits or {}).get("max_questions")
                if limits is not None
                else provider.get("max_questions"),
            ),
            name="custom max questions",
            default=64,
            minimum=1,
            maximum=64,
        ),
        max_response_bytes=_int_value(
            values.get(
                "IDA_MCP_CUSTOM_MAX_RESPONSE_BYTES",
                (limits or {}).get("max_response_bytes")
                if limits is not None
                else provider.get("max_response_bytes"),
            ),
            name="custom max response bytes",
            default=1_048_576,
            minimum=1024,
            maximum=16_777_216,
        ),
        input_usd_per_mtok=_price_value(values.get("IDA_MCP_CUSTOM_INPUT_USD_PER_MTOK", provider.get("input_usd_per_mtok")), name="custom input price"),
        output_usd_per_mtok=_price_value(values.get("IDA_MCP_CUSTOM_OUTPUT_USD_PER_MTOK", provider.get("output_usd_per_mtok")), name="custom output price"),
        allow_unknown_pricing=_bool_value(values.get("IDA_MCP_CUSTOM_ALLOW_UNKNOWN_PRICING", provider.get("allow_unknown_pricing")), name="custom unknown pricing", default=False),
    )


def config_status(config: ProviderConfig) -> dict[str, Any]:
    result = config.safe_dict()
    result["auth_present"] = bool(config.auth and config.auth.present())
    result["ready"] = config.mode == "disabled" or bool(config.auth and config.auth.present())
    return result
