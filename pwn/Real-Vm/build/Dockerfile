FROM ubuntu:latest as base
FROM pwn.red/jail

COPY --from=base / /srv

COPY flag.txt /srv/app/flag.txt
COPY real-vm /srv/app/run
COPY libs/* /srv/app/libs/
COPY log.txt /srv/app/


RUN chmod +x /srv/app/run

ENV JAIL_TIME=180 JAIL_CPU=100 JAIL_MEM=10M JAIL_DEV=kvm 
