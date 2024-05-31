# Use an alpine python image as the base image:
FROM python:3.11-slim

# Install socat to run the challenge through it:
RUN apt-get update && apt-get install -y socat

# Setup a ctf user
RUN groupadd -r ctf && useradd -r -g ctf ctf

# Set the working directory to /home/ctf
WORKDIR /home/ctf

# Copy relevant files into the docker container:
COPY . .

# Give the ctf user permissions to relevant directories
RUN chmod -R 444 patterns/* symbols/* common.py server.py secret.py sample_data.png
RUN chmod 600 requirements.txt
RUN chown -R ctf:ctf /home/ctf

# Change to the ctf-user context
USER ctf

# Add the required python modules (-> using the ctf-user, because pip warns about issues when running as root...):
RUN pip install -r requirements.txt

# Run the challenge through socat:
# Options:
# '-T 30': Terminate stale connections 30 seconds after the last transmission.
# 'TCP-LISTEN:8448': Pipe the programs IO through 8448/tcp
# 'nodelay': Turns off the Nagle algorithm for measuring the RTT (round trip time).
# 'reuseaddr': Allows multiple clients to bind to the local port used by socat.
# 'fork': Forks a child-process to run the application in.
# 'EXEC:"python /app/server.py"' Run 'python /app/server.py', if a client connects.
CMD socat -T 30 TCP-LISTEN:8448,nodelay,reuseaddr,fork EXEC:"python /home/ctf/server.py"

# Declare the required port
EXPOSE 8448/tcp

# Build and run the container:
# 1. Build the container
#sudo docker build -t l3ak_ctf_2024_programming_windows-1252 .
# 2. [Optional] Cleanup: Remove temporary/unnecessary files from the docker build
#sudo docker system prune -f
# 3. Run the container; remove the option "-d" if you don't want to run it in detached-mode.
#sudo docker run -d --rm -p 8448:8448 l3ak_ctf_2024_programming_windows-1252
# 4. [Optional] Check which containers are running:
#sudo docker ps -a
# 5. Stop a running container (the CONTAINER ID can be found in the output of 4.):
# sudo docker stop <CONTAINER ID>
