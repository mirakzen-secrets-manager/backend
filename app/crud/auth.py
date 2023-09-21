import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from common.config import cfg
from common.errors import HTTPabort
from common.utils import (
    hash_password,
    is_password_strong,
    otp_get_link,
    otp_verify,
    verify_password,
)
from db.models import Accounts, Secrets, Sessions
from db.utils import _engine
from fastapi import Request
from jose import jwt
from schemas import auth as auth_schemas
from schemas.auth import CurrentAccount
from sqlalchemy import delete, func, join, select, update
from sqlalchemy.ext.asyncio import AsyncSession


async def get_current_account(request: Request) -> (CurrentAccount, str):
    token_cookie = request.cookies.get(cfg.AUTH_TOKEN_NAME)
    token_header = request.headers.get(cfg.AUTH_TOKEN_NAME)

    if not token_cookie and not token_header:
        return CurrentAccount(), "pass"

    try:
        payload = jwt.decode(
            token_cookie or token_header,
            cfg.AUTH_TOKEN_KEY,
            algorithms=["HS256"],
        )
        account_id = uuid.UUID(payload["account_id"])
        session_id = uuid.UUID(payload["session_id"])
        login = payload["login"]
        login_time = datetime.fromisoformat(payload["login_time"])
    except Exception:
        if token_cookie:
            return CurrentAccount(), "delete"
        else:
            return CurrentAccount(), "pass"

    async with AsyncSession(_engine, expire_on_commit=False) as session:
        async with session.begin():
            if token_cookie and datetime.now(timezone.utc) > (
                login_time + timedelta(days=cfg.AUTH_TOKEN_EXPIRE)
            ):
                await session.execute(
                    delete(Sessions).where(
                        Sessions.id == session_id, Sessions.aid == account_id
                    )
                )
                if token_cookie:
                    return CurrentAccount(), "delete"
                else:
                    return CurrentAccount(), "pass"

            account_session = await session.scalar(
                select(Sessions).where(
                    Sessions.id == session_id, Sessions.aid == account_id
                )
            )
            if not account_session:
                if token_cookie:
                    return CurrentAccount(), "delete"
                else:
                    return CurrentAccount(), "pass"

            return CurrentAccount(account_id, login, session_id), "pass"


async def login_required(request: Request) -> CurrentAccount:
    account, token_action = await get_current_account(request)
    if not account.is_auth:
        if token_action == "delete":
            HTTPabort(
                401,
                "Unauthorized",
                {
                    "set-cookie": f'{cfg.AUTH_TOKEN_NAME}=""; Domain={cfg.DOMAIN}; Max-age=0; Path=/'
                },
            )
        HTTPabort(401, "Unauthorized")
    return account


async def login_forbidden(request: Request) -> None:
    account, _ = await get_current_account(request)
    if account.is_auth:
        HTTPabort(409, "Must be unauthorized - Account already logged-in")


async def login_admin_required(request: Request) -> CurrentAccount:
    account = await login_required(request)
    if not account.login == "admin":
        HTTPabort(403, "Access denied")
    return account


async def register(session: AsyncSession, new_account: auth_schemas.NewAccount):
    if new_account.referal != cfg.REFERAL_CODE:
        HTTPabort(409, "Incorrect referal")
    if not is_password_strong(new_account.password):
        HTTPabort(400, "Password is not strong!")
    async with session.begin():
        db_account = await session.scalar(
            select(Accounts).where(Accounts.login == new_account.login.lower())
        )
        if db_account:
            HTTPabort(409, "Login already exists")

        account = Accounts(
            login=new_account.login,
            password=hash_password(new_account.password),
            otp_enabled=False,
            otp_confirmed=False,
            incorrect_login_count=0,
        )
        session.add(account)


async def account_check(
    session: AsyncSession, account: auth_schemas.LoginAccount
) -> Accounts:
    async with session.begin():
        db_account = await session.scalar(
            select(Accounts).where(func.lower(Accounts.login) == account.login.lower())
        )
        if not db_account:
            HTTPabort(400, "Incorrect login/password")

        if db_account.incorrect_login_count > cfg.INCORRECT_LOGIN_MAX_COUNT and (
            (
                db_account.incorrect_login_latest
                or datetime.fromisoformat("1970-01-01 00:00+00:00")
            )
            > (
                datetime.now(timezone.utc)
                - timedelta(minutes=cfg.INCORRECT_LOGIN_DELAY)
            )
        ):
            HTTPabort(400, "Incorrect login/password")

        if not verify_password(account.password, db_account.password):
            await session.execute(
                update(Accounts)
                .where(Accounts.id == db_account.id)
                .values(
                    incorrect_login_latest=datetime.now(timezone.utc),
                    incorrect_login_count=Accounts.incorrect_login_count + 1,
                )
            )
            await session.commit()
            HTTPabort(400, "Incorrect login/password")

        if db_account.incorrect_login_count != 0:
            await session.execute(
                update(Accounts)
                .where(Accounts.id == db_account.id)
                .values(incorrect_login_count=0)
            )
            db_account.incorrect_login_count = 0
        return db_account


async def create_session(
    session: AsyncSession,
    account_id: uuid.UUID,
    login_type: str,
) -> Sessions:
    async with session.begin():
        new_session = Sessions(
            aid=account_id,
            type=login_type,
            incorrect_login_count=0,
        )
        session.add(new_session)
        await session.flush()
        await session.refresh(new_session)
        return new_session


async def login(
    session: AsyncSession,
    db_account: Accounts,
    db_session: Sessions,
) -> str:
    async with session.begin():
        login_time = datetime.now(timezone.utc)
        await session.execute(
            update(Sessions)
            .where(Sessions.id == db_session.id, Sessions.otp_id == db_session.otp_id)
            .values(
                started=login_time,
                incorrect_login_count=0,
            )
        )
        payload = {
            "account_id": str(db_account.id),
            "session_id": str(db_session.id),
            "login": db_account.login,
            "login_time": login_time.isoformat(),
        }
        return jwt.encode(payload, cfg.AUTH_TOKEN_KEY, algorithm="HS256")


async def otp_add(
    session: AsyncSession, current_account: CurrentAccount, password: str
) -> str:
    async with session.begin():
        db_account = await session.scalar(
            select(Accounts).where(
                Accounts.id == current_account.id, Accounts.otp_confirmed == False
            )
        )
        if not db_account:
            HTTPabort(409, "Already has OPT enabled")
        if not verify_password(password, db_account.password):
            HTTPabort(400, "Incorrect password")

        await session.execute(
            update(Accounts)
            .where(Accounts.id == current_account.id)
            .values(otp_enabled=True)
        )

        return otp_get_link(
            cfg.AUTH_TOKEN_OTP, current_account.id, current_account.login
        )


async def otp_add_confirm(
    session: AsyncSession, current_account: CurrentAccount, otp_code: str
) -> None:
    async with session.begin():
        if not otp_verify(cfg.AUTH_TOKEN_OTP, current_account.id, otp_code):
            curr_session = await session.scalar(
                select(Sessions)
                .select_from(join(Sessions, Accounts, Sessions.aid == Accounts.id))
                .where(
                    Sessions.id == current_account.sid,
                    Sessions.aid == current_account.id,
                    Accounts.otp_enabled == True,
                    Accounts.otp_confirmed == False,
                )
            )
            if not curr_session:
                HTTPabort(
                    409, "Account doesn't have OTP enabled or it's already confirmed"
                )

            if curr_session.incorrect_login_count + 1 > cfg.INCORRECT_LOGIN_MAX_COUNT:
                await session.execute(
                    update(Accounts)
                    .where(Accounts.id == current_account.id)
                    .values(otp_enabled=False, otp_confirmed=False)
                )
                await session.execute(
                    update(Sessions)
                    .where(Sessions.id == current_account.sid)
                    .values(incorrect_login_count=0)
                )
            else:
                await session.execute(
                    update(Sessions)
                    .where(Sessions.id == current_account.sid)
                    .values(
                        incorrect_login_count=(Sessions.incorrect_login_count + 1),
                    )
                )

            await session.commit()
            HTTPabort(400, "Incorrect code")

        await session.execute(
            update(Sessions)
            .where(Sessions.id == current_account.sid)
            .values(incorrect_login_count=0)
        )
        await session.execute(
            update(Accounts)
            .where(Accounts.id == current_account.id)
            .values(otp_confirmed=True)
        )


async def otp_remove(
    session: AsyncSession,
    current_account: CurrentAccount,
    otp_removal: auth_schemas.OTPRemoval,
) -> None:
    async with session.begin():
        db_account = await session.scalar(
            select(Accounts).where(
                Accounts.id == current_account.id, Accounts.otp_confirmed == True
            )
        )
        if not db_account:
            HTTPabort(409, "OPT hasn't enabled")
        if not verify_password(otp_removal.password, db_account.password):
            HTTPabort(400, "Incorrect password")
        if not otp_verify(cfg.AUTH_TOKEN_OTP, current_account.id, otp_removal.code):
            HTTPabort(400, "Incorrect code")

        await session.execute(
            update(Accounts)
            .where(Accounts.id == current_account.id)
            .values(otp_enabled=False, otp_confirmed=False)
        )


async def login_otp_verify(
    session: AsyncSession, otp_confirmation: auth_schemas.OTPConfirmation
):
    async with session.begin():
        account_session = (
            await session.execute(
                select(Sessions, Accounts)
                .select_from(join(Sessions, Accounts, Sessions.aid == Accounts.id))
                .where(Sessions.otp_id == otp_confirmation.id)
            )
        ).fetchone()
        if not account_session:
            HTTPabort(400, "Try to OTP login again")

        if not otp_verify(
            cfg.AUTH_TOKEN_OTP, account_session.Sessions.aid, otp_confirmation.code
        ):
            if (
                account_session.Sessions.incorrect_login_count + 1
            ) > cfg.INCORRECT_LOGIN_MAX_COUNT:
                await session.execute(
                    delete(Sessions).where(Sessions.id == account_session.Sessions.id)
                )
            else:
                await session.execute(
                    update(Sessions)
                    .where(Sessions.id == account_session.Sessions.id)
                    .values(
                        incorrect_login_count=(Sessions.incorrect_login_count + 1),
                    )
                )
            await session.commit()
            HTTPabort(400, "Incorrect code")

        await session.execute(
            update(Sessions)
            .where(Sessions.id == account_session.Sessions.id)
            .values(incorrect_login_count=0)
        )

        return (account_session.Accounts, account_session.Sessions)


async def logout(session: AsyncSession, current_account: CurrentAccount) -> str:
    async with session.begin():
        return (
            (
                await session.execute(
                    delete(Sessions)
                    .where(Sessions.id == current_account.sid)
                    .returning(Sessions.type)
                )
            )
            .fetchone()
            .type
        )


async def get_sessions(session: AsyncSession, current_account: CurrentAccount) -> Dict:
    async with session.begin():
        account_sessions = await session.scalars(
            select(Sessions).where(Sessions.aid == current_account.id)
        )
        return {
            str(s.id): {
                "started": s.started.isoformat() if s.started else s.started,
                "type": s.type,
                "current": True if str(current_account.sid) == str(s.id) else False,
            }
            for s in account_sessions
        }


async def close_sessions(
    session: AsyncSession,
    current_account: CurrentAccount,
    sessions: List[auth_schemas.Session],
) -> None:
    async with session.begin():
        if sessions:
            await session.execute(
                delete(Sessions).where(Sessions.id.in_([s.id for s in sessions]))
            )
        else:
            await session.execute(
                delete(Sessions).where(Sessions.aid == current_account.id)
            )


async def change_password(
    session: AsyncSession,
    current_account: CurrentAccount,
    passwords: auth_schemas.PasswordChanged,
) -> None:
    if passwords.old == passwords.new:
        HTTPabort(409, "Entered old and new passwords are equal")
    if not is_password_strong(passwords.new):
        HTTPabort(400, "Password is not strong!")
    async with session.begin():
        db_account = await session.scalar(
            select(Accounts).where(Accounts.id == current_account.id)
        )
        if not verify_password(passwords.old, db_account.password):
            HTTPabort(400, "Incorrect password")

        await session.execute(
            update(Accounts)
            .where(Accounts.id == current_account.id)
            .values(password=hash_password(passwords.new))
        )
        await session.execute(
            delete(Sessions).where(Sessions.aid == current_account.id)
        )
    if current_account.login == "admin":
        await cfg.update_to_file({"admin_password": passwords.new})


async def self_delete_account(
    session: AsyncSession, current_account: CurrentAccount, password: str
) -> None:
    if current_account.login == "admin":
        HTTPabort(409, "Can't delete admin account")
    async with session.begin():
        db_account = await session.scalar(
            select(Accounts).where(Accounts.id == current_account.id)
        )
        if not verify_password(password, db_account.password):
            HTTPabort(400, "Incorrect password")

        await session.execute(
            delete(Sessions).where(Sessions.aid == current_account.id)
        )
        await session.execute(
            delete(Secrets).where(Secrets.account_id == current_account.id)
        )
        await session.execute(delete(Accounts).where(Accounts.id == current_account.id))
