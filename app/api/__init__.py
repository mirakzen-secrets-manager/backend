from typing import Any, Optional

from common.config import cfg
from fastapi.responses import JSONResponse


def HTTPanswer(
    status_code: int,
    description: Any,
    action_cookie: Optional[str] = None,
    token: Optional[str] = None,
):
    response = JSONResponse(
        status_code=status_code,
        content={"content": description},
    )
    if action_cookie == "set":
        response.set_cookie(
            key=cfg.AUTH_TOKEN_NAME,
            value=token,
            path="/",
            domain=cfg.DOMAIN,
            httponly=True,
            secure=(True if cfg.ENV != "dev" else False),
            samesite=("strict" if cfg.ENV != "dev" else "lax"),
        )
    elif action_cookie == "delete":
        response.delete_cookie(cfg.AUTH_TOKEN_NAME, path="/", domain=cfg.DOMAIN)

    return response
