"""Structured logging with redaction applied before emission.

Two things distinguish this from a plain ``logging.basicConfig``:

* Every structured field passes through :mod:`mybot_security.redaction` on the
  way out.  A developer who logs ``token=...`` gets ``[REDACTED]`` rather than
  an incident.
* A request id is carried in a context variable and attached automatically, so
  one user request can be followed across the orchestrator, the policy engine
  and an integration adapter without threading a parameter through everything.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from .redaction import redact

_request_id: ContextVar[str | None] = ContextVar("mybot_request_id", default=None)
_owner_hint: ContextVar[str | None] = ContextVar("mybot_owner_hint", default=None)


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def current_request_id() -> str | None:
    return _request_id.get()


@contextmanager
def request_context(request_id: str | None = None, owner_id: str | None = None) -> Iterator[str]:
    rid = request_id or new_request_id()
    token = _request_id.set(rid)
    # Only the first 8 characters of the owner id are logged: enough to
    # correlate lines, not enough to be a useful identifier on its own.
    owner_token = _owner_hint.set(owner_id[:8] if owner_id else None)
    try:
        yield rid
    finally:
        _request_id.reset(token)
        _owner_hint.reset(owner_token)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        rid = _request_id.get()
        if rid:
            payload["request_id"] = rid
        owner = _owner_hint.get()
        if owner:
            payload["owner"] = owner
        extra = getattr(record, "mybot_fields", None)
        if extra:
            payload["fields"] = redact(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


class MyBotLogger:
    """Thin adapter that funnels structured fields through redaction."""

    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    def _emit(self, level: int, msg: str, **fields) -> None:
        self._log.log(level, msg, extra={"mybot_fields": fields} if fields else {})

    def debug(self, msg: str, **f) -> None:
        self._emit(logging.DEBUG, msg, **f)

    def info(self, msg: str, **f) -> None:
        self._emit(logging.INFO, msg, **f)

    def warning(self, msg: str, **f) -> None:
        self._emit(logging.WARNING, msg, **f)

    def error(self, msg: str, **f) -> None:
        self._emit(logging.ERROR, msg, **f)

    def exception(self, msg: str, **f) -> None:
        self._log.exception(msg, extra={"mybot_fields": f} if f else {})


def get_logger(name: str) -> MyBotLogger:
    return MyBotLogger(name)


def configure_logging(level: str = "INFO", *, json_output: bool = True) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s :: %(message)s")
        )
    root.addHandler(handler)
    root.setLevel(level.upper())
    # These are chatty and occasionally echo URLs containing query parameters.
    for noisy in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


__all__ = [
    "JsonFormatter",
    "MyBotLogger",
    "configure_logging",
    "current_request_id",
    "get_logger",
    "new_request_id",
    "request_context",
]
