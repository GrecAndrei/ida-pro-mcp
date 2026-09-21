"""Metadata-only provider usage accounting and bounded budgets."""

from __future__ import annotations

import contextlib
import datetime as _dt
import math
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .types import ProviderBudgetError, ProviderConfigError, Usage


def _safe_label(value: Any, limit: int, *, identifier: bool = False) -> str:
    text = str(value or "").replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    if any(marker in text.lower() for marker in ("api_key", "authorization", "bearer ", "secret", "token", "prompt", "completion")):
        return "<redacted>"
    if identifier and not all(char.isalnum() or char in "._:-" for char in text):
        return "<redacted>"
    return text[:limit]


@dataclass(frozen=True)
class BudgetConfig:
    request_input_tokens: int = 8_192
    request_output_tokens: int = 2_048
    request_count_session: int = 200
    request_count_daily: int = 2_000
    token_budget_session: int = 100_000
    token_budget_daily: int = 500_000
    cost_budget_session: float = 5.0
    cost_budget_daily: float = 20.0
    warn_thresholds: tuple[float, ...] = (0.70, 0.90)
    unknown_pricing_blocks: bool = True
    budget_mode: str = "block"  # block at limits, or warn and continue

    def __post_init__(self) -> None:
        for name in (
            "request_input_tokens", "request_output_tokens", "request_count_session",
            "request_count_daily", "token_budget_session", "token_budget_daily",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ProviderConfigError(f"{name} must be a positive integer")
        for name in ("cost_budget_session", "cost_budget_daily"):
            try:
                value = float(getattr(self, name))
            except (TypeError, ValueError):
                raise ProviderConfigError(f"{name} must be finite and non-negative") from None
            if value < 0 or not math.isfinite(value):
                raise ProviderConfigError(f"{name} must be finite and non-negative")
        if self.budget_mode not in {"warn", "block"}:
            raise ProviderConfigError("budget_mode must be warn or block")
        if not self.warn_thresholds:
            raise ProviderConfigError("warning thresholds must be between 0 and 1")
        for item in self.warn_thresholds:
            try:
                threshold = float(item)
            except (TypeError, ValueError):
                raise ProviderConfigError("warning thresholds must be between 0 and 1") from None
            if isinstance(item, bool) or not 0.0 < threshold < 1.0:
                raise ProviderConfigError("warning thresholds must be between 0 and 1")

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "BudgetConfig":
        values = os.environ if env is None else env

        def integer(names: tuple[str, ...], default: int, minimum: int = 0, maximum: int = 10_000_000) -> int:
            for name in names:
                raw = str(values.get(name, "")).strip()
                if not raw:
                    continue
                try:
                    parsed = int(raw)
                except (TypeError, ValueError):
                    raise ProviderConfigError(f"{name} must be an integer") from None
                if not minimum <= parsed <= maximum:
                    raise ProviderConfigError(f"{name} is outside the supported range")
                return parsed
            return default

        def number(names: tuple[str, ...], default: float, maximum: float = 1_000_000.0) -> float:
            for name in names:
                raw = str(values.get(name, "")).strip()
                if not raw:
                    continue
                try:
                    parsed = float(raw)
                except (TypeError, ValueError):
                    raise ProviderConfigError(f"{name} must be a number") from None
                if parsed < 0 or not math.isfinite(parsed) or parsed > maximum:
                    raise ProviderConfigError(f"{name} is outside the supported range")
                return parsed
            return default

        def boolean(names: tuple[str, ...], default: bool) -> bool:
            for name in names:
                raw = str(values.get(name, "")).strip().lower()
                if not raw:
                    continue
                if raw in {"1", "true", "yes", "on"}:
                    return True
                if raw in {"0", "false", "no", "off"}:
                    return False
                raise ProviderConfigError(f"{name} must be true or false")
            return default

        thresholds_raw = str(
            values.get("IDA_MCP_JEV_WARNING_THRESHOLDS")
            or values.get("IDA_MCP_INTELLIGENCE_WARNING_THRESHOLDS", "")
        ).strip()
        thresholds: list[float] = []
        if len(thresholds_raw) > 256:
            raise ProviderConfigError("warning thresholds are too long")
        if thresholds_raw:
            threshold_items = thresholds_raw.split(",")
            if len(threshold_items) > 16:
                raise ProviderConfigError("warning thresholds contain too many values")
            for item in threshold_items:
                try:
                    value = float(item.strip())
                except (TypeError, ValueError):
                    raise ProviderConfigError("warning thresholds must be numeric") from None
                if not 0.0 < value < 1.0:
                    raise ProviderConfigError("warning thresholds must be between 0 and 1")
                thresholds.append(value)
        if not thresholds:
            thresholds = [0.70, 0.90]
        budget_mode = str(
            values.get("IDA_MCP_JEV_BUDGET_MODE")
            or values.get("IDA_MCP_INTELLIGENCE_BUDGET_MODE")
            or "block"
        ).strip().lower()
        if budget_mode not in {"warn", "block"}:
            raise ProviderConfigError("budget mode must be warn or block")
        return cls(
            request_input_tokens=integer(("IDA_MCP_JEV_REQUEST_INPUT_TOKENS", "IDA_MCP_INTELLIGENCE_REQUEST_INPUT_TOKENS"), 8_192, 1),
            request_output_tokens=integer(("IDA_MCP_JEV_REQUEST_OUTPUT_TOKENS", "IDA_MCP_INTELLIGENCE_REQUEST_OUTPUT_TOKENS"), 2_048, 1),
            request_count_session=integer(("IDA_MCP_JEV_SESSION_REQUEST_LIMIT", "IDA_MCP_INTELLIGENCE_SESSION_REQUEST_LIMIT"), 200, 1),
            request_count_daily=integer(("IDA_MCP_JEV_DAILY_REQUEST_LIMIT", "IDA_MCP_INTELLIGENCE_DAILY_REQUEST_LIMIT"), 2_000, 1),
            token_budget_session=integer(("IDA_MCP_JEV_SESSION_TOKEN_BUDGET", "IDA_MCP_INTELLIGENCE_SESSION_TOKEN_BUDGET"), 100_000, 1),
            token_budget_daily=integer(("IDA_MCP_JEV_DAILY_TOKEN_BUDGET", "IDA_MCP_INTELLIGENCE_DAILY_TOKEN_BUDGET"), 500_000, 1),
            cost_budget_session=number(("IDA_MCP_JEV_SESSION_BUDGET_USD", "IDA_MCP_INTELLIGENCE_SESSION_BUDGET_USD"), 5.0),
            cost_budget_daily=number(("IDA_MCP_JEV_DAILY_BUDGET_USD", "IDA_MCP_INTELLIGENCE_DAILY_BUDGET_USD"), 20.0),
            warn_thresholds=tuple(sorted(set(thresholds))),
            unknown_pricing_blocks=boolean(("IDA_MCP_JEV_BLOCK_UNKNOWN_PRICING", "IDA_MCP_INTELLIGENCE_BLOCK_UNKNOWN_PRICING"), True),
            budget_mode=budget_mode,
        )


@dataclass(frozen=True)
class BudgetReservation:
    request_id: str
    session_id: str
    day: str
    reserved_input_tokens: int
    reserved_output_tokens: int
    reserved_total_tokens: int
    reserved_cost_usd: float | None
    price_known: bool
    input_price_usd_per_mtok: float | None = None
    output_price_usd_per_mtok: float | None = None
    warnings: tuple[str, ...] = ()


class UsageLedger:
    """SQLite ledger storing provider metadata, never request content."""

    def __init__(self, path: str | os.PathLike[str], *, budget: BudgetConfig | None = None):
        self.path = str(Path(path).expanduser())
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.budget = budget or BudgetConfig.from_env()
        self._lock = threading.RLock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS provider_usage (
                    request_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    day TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT,
                    operation TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    reserved_input_tokens INTEGER NOT NULL,
                    reserved_output_tokens INTEGER NOT NULL,
                    reserved_total_tokens INTEGER NOT NULL,
                    actual_input_tokens INTEGER,
                    actual_output_tokens INTEGER,
                    actual_total_tokens INTEGER,
                    reserved_cost_usd REAL,
                    actual_cost_usd REAL,
                    price_known INTEGER NOT NULL,
                    estimated INTEGER NOT NULL DEFAULT 0,
                    latency_ms REAL,
                    error_code TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_provider_usage_session_day
                    ON provider_usage(session_id, day);
                CREATE INDEX IF NOT EXISTS idx_provider_usage_day
                    ON provider_usage(day);
                """
            )
            # A host upgrade may retain the metadata table from an earlier
            # provider prototype.  Add only the metadata columns required by
            # the current ledger; request/response bodies are never migrated
            # into this table.
            existing = {str(row[1]) for row in conn.execute("PRAGMA table_info(provider_usage)")}
            # If an earlier prototype ever created request/response payload
            # columns, erase their contents on first open. Current reports do
            # not select them and the provider layer never writes them.
            for sensitive_column in ("body", "content", "completion", "prompt", "request", "request_body", "response", "response_body", "state"):
                if sensitive_column in existing:
                    try:
                        conn.execute(f'UPDATE provider_usage SET "{sensitive_column}" = NULL')
                    except sqlite3.OperationalError:
                        # A legacy NOT NULL payload column cannot be dropped
                        # portably on every supported SQLite; overwrite it
                        # with an empty value rather than retaining content.
                        with contextlib.suppress(sqlite3.OperationalError):
                            conn.execute(f'UPDATE provider_usage SET "{sensitive_column}" = ?', ("",))
            columns = {
                "actual_input_tokens": "INTEGER",
                "actual_output_tokens": "INTEGER",
                "actual_total_tokens": "INTEGER",
                "reserved_cost_usd": "REAL",
                "actual_cost_usd": "REAL",
                "price_known": "INTEGER NOT NULL DEFAULT 0",
                "estimated": "INTEGER NOT NULL DEFAULT 0",
                "latency_ms": "REAL",
                "error_code": "TEXT",
                "finished_at": "TEXT",
                "status": "TEXT NOT NULL DEFAULT 'complete'",
            }
            for name, definition in columns.items():
                if name not in existing:
                    conn.execute(f"ALTER TABLE provider_usage ADD COLUMN {name} {definition}")

    @staticmethod
    def _day() -> str:
        return _dt.datetime.now(_dt.UTC).date().isoformat()

    @staticmethod
    def _cost(input_tokens: int, output_tokens: int, input_price: float | None, output_price: float | None) -> float | None:
        if input_price is None or output_price is None:
            return None
        return (max(0, int(input_tokens)) * float(input_price) + max(0, int(output_tokens)) * float(output_price)) / 1_000_000.0

    @staticmethod
    def _usage_totals(conn: sqlite3.Connection, *, session_id: str | None, day: str) -> tuple[int, float | None, int]:
        where = "day = ?"
        args: list[Any] = [day]
        if session_id is not None:
            where += " AND session_id = ?"
            args.append(session_id)
        row = conn.execute(
            f"""
            SELECT
              COALESCE(SUM(CASE WHEN status='reserved' THEN reserved_total_tokens ELSE COALESCE(actual_total_tokens, 0) END), 0) AS tokens,
              SUM(CASE WHEN status='reserved' THEN reserved_cost_usd ELSE actual_cost_usd END) AS cost,
              COUNT(*) AS requests
            FROM provider_usage WHERE {where}
            """,
            args,
        ).fetchone()
        return int(row["tokens"] or 0), (float(row["cost"]) if row["cost"] is not None else None), int(row["requests"] or 0)

    def _check_budget(
        self,
        conn: sqlite3.Connection,
        *,
        session_id: str,
        day: str,
        projected_tokens: int,
        projected_cost: float | None,
        price_known: bool,
        allow_unknown_pricing: bool = False,
    ) -> tuple[str, ...]:
        if not price_known and self.budget.unknown_pricing_blocks and not allow_unknown_pricing:
            raise ProviderBudgetError("provider pricing is unknown; request blocked before transport", details={"reason": "unknown_pricing"})
        if self.budget.unknown_pricing_blocks and not allow_unknown_pricing:
            # Unknown historical cost makes the daily cost cap unverifiable,
            # so fail closed for every session until the ledger is rotated or
            # pricing is supplied.
            unknown_where = "day = ?"
            unknown_args: list[Any] = [day]
            unknown_count = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM provider_usage WHERE {unknown_where} AND price_known=0",
                    unknown_args,
                ).fetchone()[0]
            )
            if unknown_count:
                raise ProviderBudgetError(
                    "provider usage contains unknown pricing; request blocked until pricing is configured",
                    details={"reason": "unknown_pricing_history"},
                )
        session_tokens, session_cost, session_requests = self._usage_totals(conn, session_id=session_id, day=day)
        daily_tokens, daily_cost, daily_requests = self._usage_totals(conn, session_id=None, day=day)
        violations: list[tuple[str, str]] = []
        if session_requests >= self.budget.request_count_session or daily_requests >= self.budget.request_count_daily:
            violations.append(("request_count", "provider request budget exceeded"))
        if session_tokens + projected_tokens > self.budget.token_budget_session:
            violations.append(("session_tokens", "session token budget exceeded"))
        if daily_tokens + projected_tokens > self.budget.token_budget_daily:
            violations.append(("daily_tokens", "daily token budget exceeded"))
        if projected_cost is not None:
            if session_cost is not None and session_cost + projected_cost > self.budget.cost_budget_session:
                violations.append(("session_cost", "session cost budget exceeded"))
            if daily_cost is not None and daily_cost + projected_cost > self.budget.cost_budget_daily:
                violations.append(("daily_cost", "daily cost budget exceeded"))
        warnings: list[str] = [f"budget_{reason}" for reason, _message in violations]
        if violations and self.budget.budget_mode == "block":
            reason, message = violations[0]
            raise ProviderBudgetError(message, details={"reason": reason})
        for label, token_used, token_limit, cost_used, cost_limit in (
            ("session", session_tokens + projected_tokens, self.budget.token_budget_session, (session_cost or 0.0) + (projected_cost or 0.0), self.budget.cost_budget_session),
            ("daily", daily_tokens + projected_tokens, self.budget.token_budget_daily, (daily_cost or 0.0) + (projected_cost or 0.0), self.budget.cost_budget_daily),
        ):
            token_ratio = token_used / max(1, token_limit)
            cost_ratio = cost_used / max(0.000001, cost_limit)
            ratio = max(token_ratio, cost_ratio)
            for threshold in self.budget.warn_thresholds:
                if ratio >= threshold:
                    warnings.append(f"{label}_{int(threshold * 100)}")
        return tuple(sorted(set(warnings)))

    def reserve(
        self,
        *,
        session_id: str,
        provider: str,
        model: str | None,
        operation: str,
        input_price: float | None,
        output_price: float | None,
        request_id: str | None = None,
        allow_unknown_pricing: bool = False,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
    ) -> BudgetReservation:
        sid = _safe_label(session_id or "host", 128, identifier=True) or "host"
        request = _safe_label(request_id or uuid.uuid4().hex, 128, identifier=True) or uuid.uuid4().hex
        day = self._day()
        try:
            input_tokens = self.budget.request_input_tokens if input_tokens is None else int(input_tokens)
            output_tokens = self.budget.request_output_tokens if output_tokens is None else int(output_tokens)
        except (TypeError, ValueError, OverflowError):
            raise ProviderBudgetError("provider request token budget is malformed", details={"reason": "request_tokens"}) from None
        if (
            isinstance(input_tokens, bool)
            or isinstance(output_tokens, bool)
            or input_tokens < 1
            or output_tokens < 1
            or input_tokens > self.budget.request_input_tokens
            or output_tokens > self.budget.request_output_tokens
        ):
            raise ProviderBudgetError(
                "provider request token budget exceeded",
                details={"reason": "request_tokens"},
            )
        total_tokens = input_tokens + output_tokens
        cost = self._cost(input_tokens, output_tokens, input_price, output_price)
        price_known = cost is not None
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            warnings = self._check_budget(
                conn,
                session_id=sid,
                day=day,
                projected_tokens=total_tokens,
                projected_cost=cost,
                price_known=price_known,
                allow_unknown_pricing=allow_unknown_pricing,
            )
            started = _dt.datetime.now(_dt.UTC).isoformat()
            conn.execute(
                """
                INSERT INTO provider_usage(
                    request_id, session_id, day, provider, model, operation,
                    started_at, status, reserved_input_tokens,
                    reserved_output_tokens, reserved_total_tokens,
                    reserved_cost_usd, price_known
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?, ?, ?, ?)
                """,
                (
                    request,
                    sid,
                    day,
                    _safe_label(provider, 128, identifier=True),
                    _safe_label(model, 256, identifier=True),
                    _safe_label(operation, 128, identifier=True),
                    started,
                    input_tokens,
                    output_tokens,
                    total_tokens,
                    cost,
                    int(price_known),
                ),
            )
            conn.commit()
        return BudgetReservation(
            request,
            sid,
            day,
            input_tokens,
            output_tokens,
            total_tokens,
            cost,
            price_known,
            input_price,
            output_price,
            warnings,
        )

    def reconcile(
        self,
        reservation: BudgetReservation,
        *,
        usage: Usage | None,
        latency_ms: float | None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        over_budget = bool(
            usage
            and (
                usage.input_tokens > reservation.reserved_input_tokens
                or usage.output_tokens > reservation.reserved_output_tokens
                or usage.total_tokens > reservation.reserved_total_tokens
            )
        )
        if over_budget and not error_code:
            error_code = "BUDGET_EXCEEDED"
        status = "error" if error_code else "complete"
        actual_input = usage.input_tokens if usage and not over_budget else 0
        actual_output = usage.output_tokens if usage and not over_budget else 0
        actual_total = usage.total_tokens if usage and not over_budget else 0
        # Failed attempts release token/cost reservations, while the request
        # row remains to account for request-count limits and errors.
        actual_cost = None
        if usage and reservation.price_known:
            actual_cost = self._cost(
                actual_input,
                actual_output,
                reservation.input_price_usd_per_mtok,
                reservation.output_price_usd_per_mtok,
            )
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE provider_usage SET
                    finished_at=?, status=?, actual_input_tokens=?,
                    actual_output_tokens=?, actual_total_tokens=?,
                    actual_cost_usd=?, estimated=?, latency_ms=?, error_code=?
                WHERE request_id=?
                """,
                (
                    _dt.datetime.now(_dt.UTC).isoformat(),
                    status,
                    actual_input,
                    actual_output,
                    actual_total,
                    actual_cost,
                    int(bool(usage and usage.estimated)),
                    float(latency_ms) if latency_ms is not None else None,
                    _safe_label(error_code, 64, identifier=True) if error_code else None,
                    reservation.request_id,
                ),
            )
            conn.commit()
        result = {
            "request_id": reservation.request_id,
            "status": status,
            "input_tokens": actual_input,
            "output_tokens": actual_output,
            "total_tokens": actual_total,
            "estimated": bool(usage and not over_budget and usage.estimated),
            "warnings": list(reservation.warnings),
            "error_code": error_code,
        }
        if over_budget:
            raise ProviderBudgetError(
                "provider response exceeded the reserved request token budget",
                details={"reason": "request_tokens"},
            )
        return result

    def record(
        self,
        *,
        session_id: str,
        provider: str,
        model: str | None,
        operation: str,
        usage: Usage,
        latency_ms: float | None,
        input_price: float | None,
        output_price: float | None,
        error_code: str | None = None,
        allow_unknown_pricing: bool = False,
    ) -> dict[str, Any]:
        reservation = self.reserve(
            session_id=session_id,
            provider=provider,
            model=model,
            operation=operation,
            input_price=input_price,
            output_price=output_price,
            allow_unknown_pricing=allow_unknown_pricing,
        )
        return self.reconcile(reservation, usage=usage, latency_ms=latency_ms, error_code=error_code)

    def status(self, *, session_id: str | None = None) -> dict[str, Any]:
        day = self._day()
        safe_session = _safe_label(session_id, 128, identifier=True) if session_id is not None else None
        with self._lock, self._connect() as conn:
            tokens, cost, requests = self._usage_totals(conn, session_id=safe_session, day=day)
            where = "day = ?"
            args: list[Any] = [day]
            if safe_session is not None:
                where += " AND session_id = ?"
                args.append(safe_session)
            unknown_count = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM provider_usage WHERE {where} AND price_known=0",
                    args,
                ).fetchone()[0]
            )
        warning_labels: list[str] = []
        token_limit = self.budget.token_budget_session if safe_session is not None else self.budget.token_budget_daily
        cost_limit = self.budget.cost_budget_session if safe_session is not None else self.budget.cost_budget_daily
        token_ratio = tokens / max(1, token_limit)
        cost_ratio = (cost or 0.0) / max(0.000001, cost_limit)
        ratio = max(token_ratio, cost_ratio)
        for threshold in self.budget.warn_thresholds:
            if ratio >= threshold:
                warning_labels.append(f"budget_{int(threshold * 100)}")
        return {
            "day": day,
            "session_id": safe_session,
            "requests": requests,
            "tokens": tokens,
            "cost_usd": cost if cost is not None else 0.0,
            "warnings": warning_labels,
            "limits": {
                "requests": self.budget.request_count_session if session_id is not None else self.budget.request_count_daily,
                "tokens": self.budget.token_budget_session if session_id is not None else self.budget.token_budget_daily,
                "cost_usd": self.budget.cost_budget_session if session_id is not None else self.budget.cost_budget_daily,
            },
            "budget_mode": self.budget.budget_mode,
            "warning_thresholds": list(self.budget.warn_thresholds),
            "unknown_pricing_blocks": self.budget.unknown_pricing_blocks,
            "price_known": unknown_count == 0,
            "unknown_pricing_records": unknown_count,
        }

    def report(self, *, session_id: str | None = None, limit: int = 100) -> dict[str, Any]:
        safe_session = _safe_label(session_id, 128, identifier=True) if session_id is not None else None
        try:
            limit = max(1, min(500, int(limit)))
        except (TypeError, ValueError):
            limit = 100
        clauses = []
        args: list[Any] = []
        if safe_session is not None:
            clauses.append("session_id=?")
            args.append(safe_session)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT request_id, session_id, day, provider, model, operation,
                       started_at, finished_at, status, actual_input_tokens,
                       actual_output_tokens, actual_total_tokens, actual_cost_usd,
                       price_known, estimated, latency_ms, error_code
                FROM provider_usage{where} ORDER BY started_at DESC LIMIT ?
                """,
                [*args, limit],
            ).fetchall()
        attempts = [dict(row) for row in rows]
        for attempt in attempts:
            # Keep report values scalar and bounded; request/response bodies are
            # never columns in this ledger.
            if attempt.get("latency_ms") is not None:
                attempt["latency_ms"] = round(float(attempt["latency_ms"]), 3)
            if attempt.get("actual_cost_usd") is not None:
                attempt["actual_cost_usd"] = round(float(attempt["actual_cost_usd"]), 8)
        return {"status": self.status(session_id=session_id), "attempts": attempts}
