FROM python:3.8-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

ENV FLAG = L3ak{__V3RY_B4S1C_SQLI}

EXPOSE 5000

ENV FLASK_APP=app.py

CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]