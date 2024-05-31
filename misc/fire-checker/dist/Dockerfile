FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/user
COPY app /home/user/

WORKDIR /home/user/

RUN pip install --no-cache-dir -r requirements.txt

ENV FLAG="L3AK{test_flag}"

CMD ["socat", "tcp-listen:5000,fork,reuseaddr", "EXEC:python main.py"]