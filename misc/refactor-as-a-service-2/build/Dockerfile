FROM node:20-bullseye-slim AS app
RUN useradd -m ctfuser
RUN chown root:root /home/ctfuser
RUN chmod 755 /home/ctfuser

WORKDIR /home/ctfuser/app

COPY --chown=root:root package.json .
COPY --chown=root:root index.js .

RUN npm install

RUN echo "L3AK{4lw4y5_r3m3mb3r_2_3sc4p3_B4cK5la5h3S!}" > /home/ctfuser/app/flag && \

chmod 444 /home/ctfuser/app/flag

RUN chmod -R 555 /home/ctfuser/

FROM pwn.red/jail

COPY --from=app / /srv

COPY --chmod=555 run /srv/app/run

ENV JAIL_PIDS=40 JAIL_MEM=100M JAIL_TIME=120