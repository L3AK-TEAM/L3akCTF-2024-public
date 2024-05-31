FROM ubuntu:22.04@sha256:cb2af41f42b9c9bc9bcdc7cf1735e3c4b3d95b2137be86fd940373471a34c8b0 AS base

FROM pwn.red/jail
COPY --from=base / /srv

COPY flag.txt /srv/app/flag.txt
COPY oorrww_revenge /srv/app/run
RUN chmod +x /srv/app/run

ENV JAIL_TIME=180 JAIL_CPU=100 JAIL_MEM=10M