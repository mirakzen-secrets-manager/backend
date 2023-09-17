from typing import List, Optional

from crud import auth as auth_crud
from crud import secrets as secrets_crud
from db.utils import get_session
from fastapi import APIRouter, Depends, Query
from schemas import secrets as secrets_schemas

from . import HTTPanswer

router = APIRouter()


@router.post("")
@router.post("/")
async def create_secret(
    new_secrets: list[secrets_schemas.NewSecret],
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    return HTTPanswer(
        201, await secrets_crud.create_secrets(session, current_account, new_secrets)
    )


@router.get("")
@router.get("/")
async def get_secrets(
    search: Optional[List[str]] = Query([]),
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    return HTTPanswer(
        200, await secrets_crud.get_secrets(session, current_account, search)
    )


@router.get("/{name:path}")
async def get_secret_info(
    name: str,
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    return HTTPanswer(
        200, await secrets_crud.get_secret(session, current_account, name)
    )


@router.put("/{name:path}")
async def update_secret(
    name: str,
    updated_secret: secrets_schemas.UpdatedSecret,
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    await secrets_crud.update_secret(session, current_account, name, updated_secret)
    return HTTPanswer(200, "Secret was updated")


@router.delete("/{name:path}")
async def delete_secret(
    name: str,
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    await secrets_crud.delete_secret(session, current_account, name)
    return HTTPanswer(200, "Secret was deleted")
