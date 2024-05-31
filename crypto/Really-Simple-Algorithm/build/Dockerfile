FROM python:3.11-slim-bookworm
RUN apt-get update
RUN apt-get install -y python3 python3-pip
RUN pip3 install pycryptodome

# Install Socat
RUN apt-get -y install socat

# create users
RUN useradd -ms /bin/bash player

# Copy Files
COPY --chmod=444 flag.txt /home/player/flag.txt
COPY server.py /home/player

# correct ownership for the flag.txt
RUN chown root:root /home/player/flag.txt

# Switch User
USER player
WORKDIR /home/player

CMD ["socat", "TCP-LISTEN:43012,reuseaddr,fork", "EXEC:python3 server.py"]
