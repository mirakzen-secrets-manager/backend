from typing import Dict

from common.errors import HTTPabort
from db.models import Accounts, Secrets, Sessions
from sqlalchemy import delete, func, join, select
from sqlalchemy.ext.asyncio import AsyncSession


async def get_accounts(session: AsyncSession) -> Dict:
    async with session.begin():
        accounts_stats = (
            await session.execute(
                select(
                    Accounts.login,
                    Accounts.otp_confirmed,
                    func.count(Secrets.id).label("secrets"),
                )
                .select_from(
                    join(
                        Accounts,
                        Secrets,
                        Accounts.id == Secrets.account_id,
                        isouter=True,
                    )
                )
                .where(Accounts.login != "admin")
                .group_by(Accounts.login, Accounts.otp_confirmed)
                .order_by(Accounts.login)
            )
        ).fetchall()

        return [
            {
                "login": account.login,
                "OTP": account.otp_confirmed,
                "secrets": account.secrets,
            }
            for account in accounts_stats
        ]


async def delete_account(session: AsyncSession, login: str) -> None:
    if login == "admin":
        HTTPabort(409, "Can't delete admin account!")
    async with session.begin():
        db_account = await session.scalar(select(Accounts).where(Accounts.id == login))
        if not db_account:
            HTTPabort(404, "Account not found!")

        await session.execute(delete(Sessions).where(Sessions.aid == db_account.id))
        await session.execute(
            delete(Secrets).where(Secrets.account_id == db_account.id)
        )
        await session.execute(delete(Accounts).where(Accounts.id == db_account.id))
