FROM pwn.red/jail

COPY --from=opensuse/tumbleweed@sha256:129406cbf6664f80c1b92410b2e582379a24864e982f2dad3888a9ac9153d91d / /srv

RUN mkdir /srv/app
COPY chall /srv/app/run
COPY flag.txt /srv/app/flag.txt

RUN chmod +x /srv/app/run

ENV JAIL_TMP_SIZE=1M JAIL_TIME=120
