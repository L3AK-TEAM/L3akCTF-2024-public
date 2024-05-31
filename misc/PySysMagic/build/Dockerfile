FROM python:3.10-slim as prebuild

RUN apt-get update && apt-get install -y gcc
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app
WORKDIR /app

COPY chall.py .
COPY readflag.c .
COPY audit_sandbox.c .

RUN gcc -o readflag readflag.c
RUN python chall.py build

RUN rm -f readflag.c audit_sandbox.c

FROM pwn.red/jail

COPY --from=prebuild / /srv

COPY entrypoint.sh /srv/app/run
COPY flag.txt /srv/app/flag.txt
COPY chall.py /srv/app/chall.py

ENV JAIL_PIDS=40 JAIL_MEM=100M JAIL_TIME=120