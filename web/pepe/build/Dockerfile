FROM ubuntu:focal

WORKDIR /app

COPY . /app

RUN apt-get update && \
    apt-get -y install python3 fortune python3-pip

RUN pip3 install --no-cache-dir -r requirements.txt

RUN PATH=$PATH:/usr/games

EXPOSE 5000

CMD ["python3", "app.py"]
