import base64
import hashlib
import re
import uuid

import pyotp
from passlib.hash import bcrypt


def is_password_strong(password: str) -> bool:
    return re.match(
        r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[-+_!@#$%^&*.,?]).{12,32}$", password
    )


def hash_password(password: str) -> str:
    return bcrypt.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.verify(password, hashed_password)


def get_secrets_key(secret: str, account_id: uuid.UUID) -> str:
    return hashlib.sha256(
        (secret + str(account_id).replace("-", "")).encode("utf-8")
    ).hexdigest()


def otp_get_link(secret: str, account_id: uuid.UUID, account_login: str) -> str:
    return pyotp.TOTP(
        base64.b32encode((secret + str(account_id).replace("-", "")).encode("utf-8"))
    ).provisioning_uri(name=account_login, issuer_name="mirakzen-secrets-manager")


def otp_verify(secret: str, account_id: uuid.UUID, input_code: str) -> bool:
    return pyotp.TOTP(
        base64.b32encode((secret + str(account_id).replace("-", "")).encode("utf-8"))
    ).verify(input_code)
