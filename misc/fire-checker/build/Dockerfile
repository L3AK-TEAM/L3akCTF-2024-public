FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m user
RUN chown -R root:root /home/user
RUN chmod 555 /tmp


COPY app /home/user/
WORKDIR /home/user/

RUN pip install --no-cache-dir -r requirements.txt

USER root
RUN chmod -R 555 /home/user && \
    chmod 444 /home/user/*


ENV FLAG="L3AK{tR4NSF0RMS_iNBuiL7_1n_CLi5_WHO_KneW?!}"

USER user
CMD ["socat", "tcp-listen:5000,fork,reuseaddr", "EXEC:python main.py"]
