FROM python:slim as prebuild

RUN mkdir -p /app
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

FROM pwn.red/jail
COPY --from=prebuild / /srv

WORKDIR /srv/app

COPY chall.py run
COPY flag.txt flag.txt

RUN chmod +x run

RUN mv flag.txt flag-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1).txt
RUN rm requirements.txt

ENV JAIL_PIDS=40 JAIL_TIME=60 JAIL_MEM=60M 

# Please test locally first!!
ENV JAIL_POW=15000 
