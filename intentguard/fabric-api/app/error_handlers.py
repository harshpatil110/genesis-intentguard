"""Fabric-to-HTTP Deterministic Error Translation Engine.

Maps low-level gRPC and chaincode exceptions into standard, deterministic HTTP status codes:
- RequestValidationError -> 400 Bad Request (overriding FastAPI default 422)
- UNAUTHENTICATED -> 401 Unauthorized
- PERMISSION_DENIED -> 403 Forbidden
- NOT_FOUND / "does not exist" -> 404 Not Found
- ALREADY_EXISTS / "already exists" -> 409 Conflict
- UNAVAILABLE / DEADLINE_EXCEEDED -> 503 Service Unavailable
- Unhandled Exception -> 500 Internal Server Error
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Union

import grpc
import grpc.aio
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger("intentguard.fabric_api.error_handlers")


def _extract_grpc_code_and_details(exc: Any) -> tuple[Optional[grpc.StatusCode], str]:
    """Extract gRPC status code and text message from a gRPC exception."""
    code = None
    if hasattr(exc, "code") and callable(exc.code):
        try:
            code = exc.code()
        except Exception:
            code = None

    details = ""
    if hasattr(exc, "details") and callable(exc.details):
        try:
            details = exc.details() or ""
        except Exception:
            details = ""
    if not details:
        details = str(exc)

    return code, details


async def grpc_error_handler(request: Request, exc: Any) -> JSONResponse:
    """Translate gRPC RpcError / AioRpcError to deterministic HTTP status codes."""
    code, details = _extract_grpc_code_and_details(exc)
    details_lower = details.lower()

    if code == grpc.StatusCode.UNAUTHENTICATED or "unauthenticated" in details_lower:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "Unauthorized", "detail": details},
            headers={"WWW-Authenticate": "Bearer"},
        )

    if code == grpc.StatusCode.PERMISSION_DENIED or "permission denied" in details_lower:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "Forbidden", "detail": details},
        )

    if code == grpc.StatusCode.NOT_FOUND or "does not exist" in details_lower or "not found" in details_lower:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Not Found", "detail": details},
        )

    if (
        code == grpc.StatusCode.ALREADY_EXISTS
        or "already exists" in details_lower
        or "duplicate key" in details_lower
    ):
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "Conflict", "detail": details},
        )

    if (
        code in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED)
        or "unavailable" in details_lower
        or "connection refused" in details_lower
    ):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "Hyperledger Fabric network or endorsement peer is unreachable",
                "detail": details,
            },
        )

    logger.error("Unhandled gRPC error on %s: %s (code=%s)", request.url.path, details, code)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal Fabric gRPC Error", "detail": details},
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Translate Pydantic schema validation errors into HTTP 400 Bad Request instead of 422."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "Schema Validation Error",
            "detail": "Incoming payload failed schema or chaincode validation rules.",
            "details": exc.errors(),
        },
    )


async def chaincode_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Translate standard exceptions containing chaincode keywords into HTTP errors."""
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail, "detail": exc.detail},
            headers=exc.headers,
        )

    # If it is a gRPC error disguised as standard Exception
    if isinstance(exc, (grpc.RpcError, grpc.aio.AioRpcError)) or hasattr(exc, "code"):
        return await grpc_error_handler(request, exc)

    err_msg = str(exc)
    err_lower = err_msg.lower()

    if "does not exist" in err_lower or "not found" in err_lower:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Not Found", "detail": err_msg},
        )

    if "already exists" in err_lower or "duplicate" in err_lower:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "Conflict", "detail": err_msg},
        )

    if (
        "unavailable" in err_lower
        or "unreachable" in err_lower
        or "connection refused" in err_lower
        or "deadline exceeded" in err_lower
    ):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "Hyperledger Fabric network or endorsement peer is unreachable",
                "detail": err_msg,
            },
        )

    if "validation" in err_lower or "invalid" in err_lower or "schema" in err_lower:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Bad Request", "detail": err_msg},
        )

    logger.error("Unhandled server exception on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal Server Error", "detail": err_msg},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register custom exception translators on the FastAPI application."""
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(grpc.RpcError, grpc_error_handler)
    app.add_exception_handler(grpc.aio.AioRpcError, grpc_error_handler)
    app.add_exception_handler(Exception, chaincode_error_handler)
