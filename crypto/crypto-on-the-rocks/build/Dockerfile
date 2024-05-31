FROM sagemath/sagemath:latest-py3

USER root

RUN apt-get update -y && apt-get install -y python3 python3-pip socat \
    && sage -pip install pycryptodome \
    && pip3 install pycryptodome --no-cache-dir \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN mkdir /home/sage/ctf

COPY /src/chal.py /home/sage/ctf/chal.py

COPY /src/flag.txt /home/sage/ctf/flag.txt
COPY ./docker-entrypoint.sh /home/sage/ctf/docker-entrypoint.sh
RUN chmod +x /home/sage/ctf/docker-entrypoint.sh
USER sage
WORKDIR /home/sage/ctf
EXPOSE 1337
ENTRYPOINT ["./docker-entrypoint.sh"]