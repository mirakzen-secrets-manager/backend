import uuid
from typing import Optional

from pydantic import BaseModel


class CurrentAccount:
    is_auth = False

    def __init__(self, id: uuid.UUID = None, login=None, sid: uuid.UUID = None):
        self.is_auth = True if id else False
        self.id = id
        self.login = login
        self.sid = sid

    def info(self) -> dict:
        return {
            "login": self.login,
            "session": str(self.sid),
        }


class NewAccount(BaseModel):
    login: str
    password: str
    referal: str


class LoginAccount(BaseModel):
    login: str
    password: str
    login_type: Optional[str] = "cookie"


class OTPConfirmation(BaseModel):
    id: uuid.UUID
    code: str


class OTPCode(BaseModel):
    code: str


class OTPRemoval(BaseModel):
    password: str
    code: str


class Session(BaseModel):
    id: uuid.UUID


class Password(BaseModel):
    password: str


class PasswordChanged(BaseModel):
    old: str
    new: str
