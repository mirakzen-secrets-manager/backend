import yaml
from aiofile import async_open


class ConfigManager:
    def __init__(self) -> None:
        self._config_file = "config/config.yaml"

    async def update_from_file(self, env: str) -> None:
        async with async_open(self._config_file, "r") as f:
            self.data = yaml.safe_load(await f.read())

            self.ENV = env
            self.DOMAIN = self.data["domain"]
            self.REFERAL_CODE = self.data["referal_code"]

            database_postgres = self.data["database_postgres"]
            self.DB_CONNECTION_STRING = "{}://{}:{}@{}:{}/{}".format(
                "postgresql+asyncpg",
                database_postgres["user"],
                database_postgres["password"],
                database_postgres["host"],
                database_postgres["port"],
                database_postgres["database"],
            )

            self.ADMIN_PASSWORD = self.data["admin_password"]

            security = self.data["security"]
            self.INCORRECT_LOGIN_DELAY = security["incorrect_login_delay"]
            self.INCORRECT_LOGIN_MAX_COUNT = security["incorrect_login_max_count"]

            self.AUTH_TOKEN_NAME = security["auth_token_header"]
            self.AUTH_TOKEN_KEY = security["auth_token_key"]
            self.AUTH_TOKEN_EXPIRE = security["auth_token_expire"]
            self.AUTH_TOKEN_OTP = security["auth_token_otp"]

            self.SECRETS_KEY = security["secrets_key"]

    async def update(self, changed_data: dict) -> None:
        for key, value in changed_data.items():
            if value and hasattr(self, key.upper()):
                setattr(self, key.upper(), value)
                self.data["key"] = value

        async with async_open(self._config_file, "w") as f:
            yaml.dump(self.data, f)


cfg = ConfigManager()
