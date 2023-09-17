from argparse import ArgumentParser

import uvicorn
from common.config import cfg
from common.errors import exception_handlers
from fastapi import FastAPI

parser = ArgumentParser(description="mirakzen-secrets-manager backend")
parser.add_argument(
    "--host",
    "-H",
    action="store",
    dest="host",
    default="0.0.0.0",
    help="Host addr",
)
parser.add_argument(
    "--port",
    "-P",
    action="store",
    dest="port",
    default="9000",
    help="Port",
)
parser.add_argument(
    "--env",
    "-E",
    action="store",
    dest="env",
    default="dev",
    help="Running environment",
)
args = parser.parse_args()
CURRENT_ENV = args.env

FastAPP = FastAPI(
    title="mirakzen-secrets-manager",
    version="1.0.0",
    exception_handlers=exception_handlers,
    openapi_url="/api/openapi.json",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)


@FastAPP.on_event("startup")
async def startup():
    await cfg.update_from_file(CURRENT_ENV)
    print("INFO:\t  Config was loaded")

    from db.utils import check_db, check_or_create_admin

    await check_db()
    await check_or_create_admin()

    from api import routers

    FastAPP.include_router(routers.routers, prefix="/api")


@FastAPP.on_event("shutdown")
async def shutdown():
    from db.utils import _engine

    await _engine.dispose()


if __name__ == "__main__":
    log_config = uvicorn.config.LOGGING_CONFIG
    log_config["formatters"]["access"][
        "fmt"
    ] = "%(asctime)s - %(client_addr)s - '%(request_line)s' %(status_code)s"

    uvicorn.run(
        "main:FastAPP",
        host=args.host,
        port=int(args.port),
        proxy_headers=True,
        log_config=log_config,
        reload=(True if CURRENT_ENV == "dev" else False),
    )
