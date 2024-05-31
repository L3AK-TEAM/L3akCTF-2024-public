FROM python:3.9-slim

WORKDIR /app

COPY . /app/

RUN pip install discord.py

RUN pip install PyJWT

ENV TOKEN=MTE2NDI0NDA2NjY4MzMzNDgzNg.GWfJrx.PKZLq0pVdUWRSQgN4zgzSqacRLvyGulBx1bzxc
CMD ["python", "bot.py"]
