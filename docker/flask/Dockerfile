FROM alpine:3.13 AS base

RUN apk add --update --no-cache python3=3.8.15-r0 \
	&& ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip \
	&& pip3 install --no-cache-dir --upgrade pip==21.2.4 setuptools==57.5.0

COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/
WORKDIR /app

ENTRYPOINT ["python3"]
CMD ["app.py"]
