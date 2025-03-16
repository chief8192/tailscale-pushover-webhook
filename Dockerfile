FROM ubuntu:latest

WORKDIR /usr/src/app

COPY app.py /usr/src/app
RUN apt-get update \
    && apt-get --yes install python3.10 python3-pip  \
    && pip3 install --no-cache-dir --break-system-packages python-dateutil pushover-util

CMD [ "/usr/bin/python3", "-u", "/usr/src/app/app.py" ]
