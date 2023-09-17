from typing import Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse


async def server_error(request, exc) -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


async def route_not_found_error(request, exc) -> JSONResponse:
    detail = str(exc.detail)
    if detail == "Not Found":
        detail = "Route not found"
    return JSONResponse(status_code=404, content={"detail": detail})


exception_handlers = {500: server_error, 404: route_not_found_error}


def HTTPabort(status_code: int, description: Any, headers: dict = {}) -> None:
    if headers:
        raise HTTPException(
            status_code=status_code,
            detail=description,
            headers=headers,
        )
    else:
        raise HTTPException(status_code=status_code, detail=description)
