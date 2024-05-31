FROM  sagemath/sagemath:latest-py3
USER root
# Install SSH
RUN apt-get update -y && apt-get install -y python3 python3-pip && sage -pip install pycryptodome \
    && pip3 install pycryptodome --no-cache-dir \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN mkdir /home/sage/ctf
# Copy the server file
COPY /src/server.py /home/sage/ctf/server.py
# Copy the flag
COPY /src/flag.txt /home/sage/ctf/flag.txt
# Copy the entrypoint script
COPY ./docker-entrypoint-a.sh /home/sage/docker-entrypoint-a.sh

EXPOSE 13337 
# Set user to sage, the default user in the sagemath docker image
USER sage

# Set working dir.
WORKDIR /home/sage/ctf

CMD ["/bin/bash", "/home/sage/docker-entrypoint-a.sh"]

