FROM python:slim
RUN apt-get update
RUN pip3 install qiskit==1.0.2
RUN pip3 install qiskit-aer==0.14.1
RUN pip3 install pycryptodome

# Install Socat
RUN apt-get -y install socat

# create users
RUN useradd -ms /bin/bash twister

# Copy Files
COPY flag.txt /home/twister
COPY quantum.py /home/twister
COPY entry_point.sh /home/twister

# Switch User
USER twister
WORKDIR /home/twister

ENTRYPOINT ./entry_point.sh
