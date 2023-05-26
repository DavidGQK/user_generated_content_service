FROM python:3.10.7-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE 'config.settings'

COPY requirements.txt .

RUN mkdir -p /app/static/ \
     && mkdir -p /app/scripts/ \
     && mkdir -p /app/sqlite_to_postgres/ \
     && pip install --upgrade pip \
     && pip install --no-cache-dir -r requirements.txt

COPY /app .
# COPY /app/config/.env .
COPY /scripts ./scripts
COPY script.py .
# COPY ./docker-compose.yml .
COPY /sqlite_to_postgres ./sqlite_to_postgres

EXPOSE 8001

CMD ["gunicorn", "config.wsgi", "--bind", "0.0.0.0:8000"]