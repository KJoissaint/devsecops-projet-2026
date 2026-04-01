FROM alpine:3.13 AS base

RUN apk add --update --no-cache python3 \
	&& ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip \
	&& pip3 install --no-cache --upgrade pip setuptools

COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt

COPY . /app/
WORKDIR /app

ENTRYPOINT ["python3"]
CMD ["app.py"]
