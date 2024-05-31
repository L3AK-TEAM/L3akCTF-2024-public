FROM ubuntu:22.04
RUN apt-get update
RUN apt-get install -y python3 python3-pip
RUN pip3 install pycryptodome

# Install Socat
RUN apt-get -y install socat

# create users
RUN useradd -ms /bin/bash player

# Copy Files
COPY flag.py /home/player
COPY server.py /home/player
COPY circuit.py /home/player

# Switch User
USER player
WORKDIR /home/player

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:python3 server.py"]
