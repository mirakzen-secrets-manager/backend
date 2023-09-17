from typing import List, Optional

from crud import auth as auth_crud
from db.utils import get_session
from fastapi import APIRouter, Depends
from schemas import auth as auth_schemas

from . import HTTPanswer

router = APIRouter()


@router.post("/register", dependencies=[Depends(auth_crud.login_forbidden)])
async def register(
    new_account: auth_schemas.NewAccount,
    session=Depends(get_session),
):
    await auth_crud.register(session, new_account)
    return HTTPanswer(201, "Registered")


@router.post("/login", dependencies=[Depends(auth_crud.login_forbidden)])
async def login(
    account: auth_schemas.LoginAccount,
    session=Depends(get_session),
):
    db_account = await auth_crud.account_check(session, account)
    db_session = await auth_crud.create_session(
        session, db_account.id, account.login_type
    )
    if db_account.otp_confirmed:
        return HTTPanswer(200, {"content": str(db_session.otp_id), "OTP confirm": True})
    else:
        auth_token = await auth_crud.login(session, db_account, db_session)
        if account.login_type == "cookie":
            return HTTPanswer(
                200, {"content": "Logged-in", "OTP confirm": False}, "set", auth_token
            )
        else:
            return HTTPanswer(200, {"content": auth_token, "OTP confirm": False})


@router.post("/login-otp", dependencies=[Depends(auth_crud.login_forbidden)])
async def login_otp(
    otp_confirmation: auth_schemas.OTPConfirmation,
    session=Depends(get_session),
):
    db_account, db_session = await auth_crud.login_otp_verify(session, otp_confirmation)
    auth_token = await auth_crud.login(session, db_account, db_session)
    if db_session.type == "cookie":
        return HTTPanswer(200, "Logged-in", "set", auth_token)
    else:
        return HTTPanswer(200, auth_token)


@router.post("/otp-add")
async def otp_add(
    password: auth_schemas.Password,
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    return HTTPanswer(
        200, await auth_crud.otp_add(session, current_account, password.password)
    )


@router.post("/otp-add-confirm")
async def otp_add_confirm(
    code: auth_schemas.OTPCode,
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    await auth_crud.otp_add_confirm(session, current_account, code.code)
    return HTTPanswer(200, "OTP was added")


@router.delete("/otp-removal")
async def otp_remove(
    otp_removal: auth_schemas.OTPRemoval,
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    await auth_crud.otp_remove(session, current_account, otp_removal)
    return HTTPanswer(200, "OTP was removed")


@router.get("/logout")
async def logout(
    session=Depends(get_session), current_account=Depends(auth_crud.login_required)
):
    login_type = await auth_crud.logout(session, current_account)
    if login_type == "cookie":
        return HTTPanswer(200, "Account was logouted", "delete")
    else:
        return HTTPanswer(200, "Account was logouted")


@router.get("/me")
async def me(current_account=Depends(auth_crud.login_required)):
    return HTTPanswer(200, current_account.info())


@router.get("/sessions")
async def get_sessions(
    session=Depends(get_session), current_account=Depends(auth_crud.login_required)
):
    return HTTPanswer(200, await auth_crud.get_sessions(session, current_account))


@router.delete("/sessions")
async def close_sessions(
    sessions: Optional[List[auth_schemas.Session]] = [],
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    await auth_crud.close_sessions(session, current_account, sessions)
    return HTTPanswer(200, "Sessions were closed")


@router.put("/password")
async def change_password(
    passwords: auth_schemas.PasswordChanged,
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    await auth_crud.change_password(session, current_account, passwords)
    return HTTPanswer(200, "Password was changed")


@router.delete("/account")
async def self_delete_account(
    password: auth_schemas.Password,
    session=Depends(get_session),
    current_account=Depends(auth_crud.login_required),
):
    await auth_crud.self_delete_account(session, current_account, password.password)
    return HTTPanswer(200, "Account was deleted")
