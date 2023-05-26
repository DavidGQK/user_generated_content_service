FROM python:3.9.12-slim

WORKDIR /etl
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt --no-cache-dir
COPY . .
CMD python main.py