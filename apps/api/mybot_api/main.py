"""MyBot API.

FastAPI application wiring. The interesting parts are the middleware, which is
where a few cross-cutting guarantees live:

* Every request gets a request id, carried in logs and stamped onto every
  audit event it produces. One user action is traceable end to end.
* Owner scoping is bound to the request's database session during
  authentication and dies with it, so no scope can leak into the next
  request on the same worker.
* Unhandled exceptions return an opaque message with the request id. Stack
  traces and database errors are for the log, not the client.
"""

from __future__ import annotations

import time

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from mybot_schemas.config import get_settings
from mybot_schemas.db.scope import CrossOwnerAccess, OwnerScopeError
from mybot_security.logging import configure_logging, get_logger, new_request_id, request_context
from mybot_security.vault import VaultAccessDenied

from .routers import actions, auth, automations, chat, life, security, today

settings = get_settings()
configure_logging(settings.log_level, json_output=settings.env != "development")
log = get_logger(__name__)

app = FastAPI(
    title="MyBot API",
    version="0.1.0",
    description=(
        "MyBot — a local-first personal life operating system. "
        "Intelligence, memory, permissions, credentials, actions and auditing are "
        "separate subsystems by design; see docs/ARCHITECTURE.md."
    ),
    docs_url="/docs" if not settings.is_production else None,
    redoc_url=None,
    openapi_url="/openapi.json" if not settings.is_production else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    # Explicit rather than "*": a wildcard here would let any origin drive the
    # approval endpoints with a stolen token.
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def request_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or new_request_id()
    started = time.perf_counter()

    with request_context(request_id):
        response = await call_next(request)

        elapsed = int((time.perf_counter() - started) * 1000)
        response.headers["x-request-id"] = request_id
        log.info(
            "http.request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=elapsed,
        )
        return response


@app.exception_handler(OwnerScopeError)
async def owner_scope_handler(request: Request, exc: OwnerScopeError):
    """An unscoped read of owned data is a bug, and a security-relevant one."""
    log.error("security.owner_scope_violation", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Request could not be completed safely."},
    )


@app.exception_handler(CrossOwnerAccess)
async def cross_owner_handler(request: Request, exc: CrossOwnerAccess):
    # Deliberately a 404: confirming the resource exists would leak it.
    log.warning("security.cross_owner_attempt", path=request.url.path)
    return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": "Not found"})


@app.exception_handler(VaultAccessDenied)
async def vault_handler(request: Request, exc: VaultAccessDenied):
    log.warning("security.vault_denied", path=request.url.path)
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN, content={"detail": "Access to that credential was denied."}
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    """Never leak internals.

    A database error message can contain column names, values and query
    fragments. The client gets a request id; the detail goes to the log.
    """
    from mybot_security.logging import current_request_id

    log.exception("http.unhandled", path=request.url.path, error_type=type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Something went wrong.",
            "request_id": current_request_id(),
        },
    )


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "version": "0.1.0", "env": settings.env}


@app.get("/api/v1/meta", tags=["meta"])
def meta():
    """Non-sensitive description of how this instance is configured.

    Useful for a developer, and honest for a user: it says plainly whether
    connectors are simulated and which model provider is in use.
    """
    from mybot_llm.router import default_router

    return {
        "version": "0.1.0",
        "env": settings.env,
        "integrations_mode": settings.integrations_mode,
        "llm": default_router().describe(),
        "pii_tokenization": settings.pii_tokenization,
        "max_external_classification": settings.max_external_classification.value,
        "database": settings.database_url.split("://", 1)[0],
    }


app.include_router(auth.router)
app.include_router(today.router)
app.include_router(life.router)
app.include_router(actions.router)
app.include_router(security.router)
app.include_router(chat.router)
app.include_router(automations.router)


@app.on_event("startup")
def on_startup():
    log.info(
        "mybot.startup",
        env=settings.env,
        integrations=settings.integrations_mode,
        llm=settings.llm_default_provider,
        database=settings.database_url.split("://", 1)[0],
    )
    if settings.is_production:
        # Fail loudly rather than run with a generated key in production.
        settings.resolved_jwt_secret()


__all__ = ["app"]
