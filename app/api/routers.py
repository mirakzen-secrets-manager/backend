from fastapi import APIRouter

from .admin import router as admin_router
from .auth import router as auth_router
from .secrets import router as secrets_router

routers = APIRouter()

routers.include_router(admin_router, prefix="/admin")
routers.include_router(auth_router, prefix="/auth")
routers.include_router(secrets_router, prefix="/secrets")
