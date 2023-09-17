import uuid
from datetime import datetime

from sqlalchemy import MetaData
from sqlalchemy.orm import Mapped, declarative_base, mapped_column
from sqlalchemy.types import TIMESTAMP, UUID, Text

SCHEMA = "msm"
Base = declarative_base(metadata=MetaData(schema=SCHEMA))


class Accounts(Base):
    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    login: Mapped[str] = mapped_column(unique=True, nullable=False)
    password: Mapped[str] = mapped_column(nullable=False)
    type: Mapped[str]
    otp_enabled: Mapped[bool] = mapped_column(nullable=False)
    otp_confirmed: Mapped[bool] = mapped_column(nullable=False)
    incorrect_login_latest: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    incorrect_login_count: Mapped[int] = mapped_column(nullable=False)


class Sessions(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    otp_id: Mapped[uuid.UUID] = mapped_column(
        UUID, nullable=False, unique=True, default=uuid.uuid4
    )
    aid: Mapped[uuid.UUID] = mapped_column(UUID, nullable=False)
    started: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    type: Mapped[str]
    incorrect_login_count: Mapped[int] = mapped_column(nullable=False)


class Secrets(Base):
    __tablename__ = "secrets"

    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(UUID, nullable=False)
    name: Mapped[str] = mapped_column(nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False)
