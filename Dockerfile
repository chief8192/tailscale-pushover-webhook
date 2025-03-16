FROM python:latest

WORKDIR /app

COPY app.py .
EXPOSE 443

CMD [ "python3", "-u", "app.py" ]