from common.config import cfg
from crud import admin as admin_crud
from crud import auth as auth_crud
from db.utils import get_session
from fastapi import APIRouter, Depends
from schemas import admin as admin_schemas

from . import HTTPanswer

router = APIRouter()


@router.get("/config", dependencies=[Depends(auth_crud.login_admin_required)])
async def config_get():
    return HTTPanswer(200, cfg.data)


@router.put("/config", dependencies=[Depends(auth_crud.login_admin_required)])
async def config_update(
    updated_config: admin_schemas.UpdatedConfig,
):
    await cfg.update(updated_config.model_dump(exclude_none=True))
    return HTTPanswer(200, "Config was updated to file")


@router.get("/accounts", dependencies=[Depends(auth_crud.login_admin_required)])
async def get_accounts(session=Depends(get_session)):
    return HTTPanswer(200, await admin_crud.get_accounts(session))


@router.delete("/accounts", dependencies=[Depends(auth_crud.login_admin_required)])
async def self_delete_account(
    login: admin_schemas.DeletedAccount,
    session=Depends(get_session),
):
    await auth_crud.self_delete_account(session, login.login)
    return HTTPanswer(200, "Account was deleted")
