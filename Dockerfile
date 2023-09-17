FROM python:3.10-slim

WORKDIR /application

RUN mkdir /application/config
COPY ./requirements.txt /application/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /application/requirements.txt

COPY ./app /application/app

ENV APP_ENV=dev
ENV APP_PORT=9000
CMD python app/main.py -H 127.0.0.1 -P ${APP_PORT} -E ${APP_ENV}
