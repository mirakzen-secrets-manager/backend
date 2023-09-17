# mirkazen secrets manager backend

Secrets manager, written for a small virtual machine as simple analogue of Vault/AWS-secrets. Simply because I didn’t want to change config-files on the server every time for every change in the code or values for other services (for example [PWSI backend](https://github.com/pwsiris/backend)).

Originally it was tiny private repo, but now it has beed refactored (because of better hardware), adding better code structure, docker, GH-action for build and deployment, alembic for Postgres (previously used sql-scripts for SQLite) and One-Time-Password login confirmation.

## What it can:

-   Register, login (cookies and tokens), session control (default)
-   One-Time-Password setup and login with Google Authenticator/Authy/...
-   Manage secrets (JWS sign with key and HS256):
    -   Create
    -   Delete
    -   Update
    -   Get one or all (with filter)
-   Some admin control

## Desired further improvements

-   Email registration and confirmation
-   Better API description (swagger exists, but not described enough)
-   Fix bridge mode (currently host)
-   It's mostly tested, but, as you can see, there is to tests-folder(
-   Front-end
-   Changes and improvements that I haven't thought about yet
-   Better readme, better code?)

## Quick (not really) start:

To setup your own instance of secrets manager:
-   Install and setup Postgres (don't forget to allow connect from docker addr in pg_hba.conf and postgresql.conf if bridge docker mode)
-   Install docker
-   Create somewhere and fill config.yaml
-   Build image
-   Run image (some params can be taken from GH-action, like mounting config-file)
-   Apply alembic to postgres db

For development:
-   Install and setup Postgres
-   Setup virtual environment
    ```shell
    python3 -m virtualenv venv
    . venv/bin/activate
    pip3 install -U -r requirements.txt
    pip3 install -U -r requirements_for_developer.txt
    ```
-   Create and fill config/config.yaml
-   Apply alembic via `export MSM_DB_DSN=connection string` and alembic upgrade head
-   Run `python3 app/main.py` (has optional arguments)

Some extras:
-   Maybe you need to setup Nginx's reverse_proxy
-   QR-code from OTP-link can be created at front-end side, but you can use `qrcode.py` to render it


## Stack
-   Python3 + FastAPI (async) + uvicorn
-   PostgreSQL + SQLAlchemy (async)
-   passlib + bcrypt and python-jose
-   pyOTP, qrcode, pyyaml
-   Docker
