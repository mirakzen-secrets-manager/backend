from typing import Optional

from pydantic import BaseModel


class UpdatedConfig(BaseModel):
    domain: Optional[str] = None
    referal_code: Optional[str] = None
    incorrect_login_delay: Optional[str] = None
    incorrect_login_max_count: Optional[int] = None
    auth_token_header: Optional[str] = None
    auth_token_key: Optional[str] = None
    auth_token_expire: Optional[int] = None


class DeletedAccount(BaseModel):
    login: str
