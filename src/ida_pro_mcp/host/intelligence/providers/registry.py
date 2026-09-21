"""Explicit provider resolution and safe status/error helpers."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from .config import ProviderConfig, config_status, resolve_provider_config
from .custom import CustomProvider
from .disabled import DisabledProvider
from .jev import JevProvider
from .types import ProviderError
from .usage_accounting import BudgetConfig, UsageLedger


def build_provider(
    config: ProviderConfig,
    *,
    transport: Any | None = None,
    ledger: UsageLedger | None = None,
    sleep=None,
):
    kwargs: dict[str, Any] = {"ledger": ledger}
    if transport is not None:
        kwargs["transport"] = transport
    if sleep is not None:
        kwargs["sleep"] = sleep
    if config.mode == "disabled":
        return DisabledProvider(config)
    if config.mode == "jev":
        return JevProvider(config, **kwargs)
    if config.mode == "custom":
        return CustomProvider(config, **kwargs)
    # This should be unreachable because config validation is strict.
    raise ValueError("unsupported intelligence mode")


def default_usage_ledger(*, env: Mapping[str, str] | None = None) -> UsageLedger:
    # Resolve the environment at call time. Tests, per-install launchers, and
    # multiple host instances may select different cache roots after this
    # module has already been imported.
    try:
        from ..config import CACHE_DIR
    except Exception:
        default_dir = os.path.join(str(Path.home()), ".local", "state", "ida-pro-mcp")
    else:
        default_dir = CACHE_DIR
    source = os.environ if env is None else env
    cache_dir = source.get("IDA_MCP_CACHE_DIR") or source.get("IDA_MCP_DATA_DIR") or default_dir
    budget = BudgetConfig.from_env(dict(env)) if env is not None else None
    return UsageLedger(os.path.join(str(cache_dir), "provider_usage.sqlite3"), budget=budget)


def resolve_provider(
    *,
    env: Mapping[str, str] | None = None,
    state: Mapping[str, Any] | None = None,
    state_path: str | os.PathLike[str] | None = None,
    transport: Any | None = None,
    ledger: UsageLedger | None = None,
    with_ledger: bool = True,
):
    config = resolve_provider_config(env=env, state=state, state_path=state_path)
    if with_ledger and ledger is None:
        ledger = default_usage_ledger(env=env)
    return build_provider(config, transport=transport, ledger=ledger)


def provider_status(*, env: Mapping[str, str] | None = None, state: Mapping[str, Any] | None = None, state_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    try:
        config = resolve_provider_config(env=env, state=state, state_path=state_path)
        provider = build_provider(config)
        result = config_status(config)
        result.update(provider.status().to_dict())
        return {"ok": True, "provider": result}
    except ProviderError as exc:
        return {
            "ok": False,
            "error": True,
            "code": exc.code,
            "message": exc.message,
            "details": dict(exc.details),
        }
    except Exception:
        return {
            "ok": False,
            "error": True,
            "code": "PROVIDER_CONFIG_INVALID",
            "message": "intelligence provider configuration could not be loaded",
        }


def provider_error_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, ProviderError):
        result: dict[str, Any] = {
            "error": True,
            "code": exc.code,
            "message": exc.message,
            "recoverable": bool(exc.recoverable),
        }
        if exc.details:
            result["details"] = dict(exc.details)
        return result
    return {
        "error": True,
        "code": "PROVIDER_ERROR",
        "message": "intelligence provider request failed",
        "recoverable": False,
    }
