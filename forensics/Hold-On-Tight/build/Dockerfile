# Use an alpine python image as the base image:
FROM python:3.11.8-alpine3.19

# Specify the working directory:
WORKDIR /app

# Install socat to run the challenge through it:
RUN apk add --no-cache socat

# Copy relevant files into the docker container:
COPY . .

# Setup a ctf user
RUN addgroup -S ctf && adduser -S ctf -G ctf

# Give the ctf user permissions to relevant directories
RUN chmod -R 544 server.py
RUN chown -R ctf:ctf /app

# Change to the ctf-user context
USER ctf

CMD socat -T 300 TCP-LISTEN:1234,nodelay,reuseaddr,fork EXEC:"python /app/server.py"

# Declare the required port
EXPOSE 1234/tcp
