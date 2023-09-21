import json
from typing import Dict, List

from common.config import cfg
from common.errors import HTTPabort
from common.utils import get_secrets_key
from db.models import Secrets
from jose import jws
from schemas import secrets as secrets_schemas
from schemas.auth import CurrentAccount
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession


async def create_secrets(
    session: AsyncSession,
    current_account: CurrentAccount,
    new_secrets: list[secrets_schemas.NewSecret],
) -> None:
    async with session.begin():
        names = [secret.name.lower() for secret in new_secrets]

        db_secrets = await session.scalars(
            select(Secrets).where(
                Secrets.account_id == current_account.id,
                Secrets.name.in_(names),
            )
        )
        db_names = [secret.name for secret in db_secrets]
        data_for_insert = []
        names_for_insert = []
        for secret in new_secrets:
            if secret.name.lower() not in db_names:
                names_for_insert.append(secret.name.lower())
                data_for_insert.append(
                    {
                        "account_id": current_account.id,
                        "name": secret.name.lower(),
                        "data": jws.sign(
                            secret.data,
                            get_secrets_key(cfg.SECRETS_KEY, current_account.id),
                            algorithm="HS256",
                        ),
                    }
                )

        if not data_for_insert:
            HTTPabort(409, "Secrets already exist")
        await session.execute(insert(Secrets).values(data_for_insert))
        return names_for_insert


async def get_secrets(
    session: AsyncSession, current_account: CurrentAccount, search: List[str]
) -> Dict:
    async with session.begin():
        query = select(Secrets).where(Secrets.account_id == current_account.id)
        for condition in search:
            query = query.where(Secrets.name.ilike(f"%{condition}%"))
        db_secrets = await session.scalars(query)

        return {
            secret.name: json.loads(
                jws.verify(
                    secret.data,
                    get_secrets_key(cfg.SECRETS_KEY, current_account.id),
                    algorithms=["HS256"],
                )
            )
            for secret in db_secrets
        }


async def get_secret(
    session: AsyncSession, current_account: CurrentAccount, secret_name: str
) -> Dict:
    async with session.begin():
        db_secret = await session.scalar(
            select(Secrets).where(
                Secrets.account_id == current_account.id,
                Secrets.name == secret_name.lower(),
            )
        )
        if not db_secret:
            HTTPabort(404, "Secret doesn't exist")

        return {
            "name": db_secret.name,
            "data": json.loads(
                jws.verify(
                    db_secret.data,
                    get_secrets_key(cfg.SECRETS_KEY, current_account.id),
                    algorithms=["HS256"],
                )
            ),
        }


async def update_secret(
    session: AsyncSession,
    current_account: CurrentAccount,
    secret_name: str,
    updated_secret: secrets_schemas.UpdatedSecret,
) -> None:
    async with session.begin():
        db_secret = await session.scalar(
            select(Secrets).where(
                Secrets.account_id == current_account.id,
                Secrets.name == secret_name.lower(),
            )
        )
        if not db_secret:
            HTTPabort(404, "Secret doesn't exist")

        dicted_updated_secret = updated_secret.model_dump(exclude_none=True)
        if "name" in dicted_updated_secret:
            dicted_updated_secret["name"] = dicted_updated_secret["name"].lower()
            db_secret_name = await session.scalar(
                select(Secrets).where(
                    Secrets.account_id == current_account.id,
                    Secrets.name == dicted_updated_secret["name"],
                )
            )
            if db_secret_name:
                HTTPabort(404, "New name is exists")
        if "data" in dicted_updated_secret:
            dicted_updated_secret["data"] = jws.sign(
                dicted_updated_secret["data"],
                get_secrets_key(cfg.SECRETS_KEY, current_account.id),
                algorithm="HS256",
            )

        await session.execute(
            update(Secrets)
            .where(
                Secrets.account_id == current_account.id, Secrets.name == secret_name
            )
            .values(dicted_updated_secret)
        )


async def delete_secret(
    session: AsyncSession, current_account: CurrentAccount, secret_name: str
) -> None:
    async with session.begin():
        db_secret = await session.scalar(
            select(Secrets).where(
                Secrets.account_id == current_account.id,
                Secrets.name == secret_name.lower(),
            )
        )
        if not db_secret:
            HTTPabort(404, "Secret doesn't exist")

        await session.execute(
            delete(Secrets).where(
                Secrets.account_id == current_account.id,
                Secrets.name == secret_name.lower(),
            )
        )
