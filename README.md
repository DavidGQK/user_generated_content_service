# User Generated Content (UGC) + Elastic Logstash Kibana (ELK)

## Description
  - UGC api service - allows the user (frontend) to perform certain actions with the DB and the event broker (Kafka + ClickHouse)
  - The interaction between Kafka and ClickHouse is based on direct integration, without ETL
  - All microservices, including those previously written, are logged in ELK

## Stack
  - Django, DRF, FastAPI, Elastic, Postgres, SQLlite, SQLAlchemy, Redis, Authlib (OAuth 2.0), JSON Web Tokens(JWT), Jaeger(Trace), Kafka, Click House, Elastic Logstash Kibana (ELK) + filebeat

## Deploy
  - fill in `.env`
  - `docker-compose -f docker-compose-ugc.yml -f docker-compose-log.yml up --build` (UGC + ELK)
  - `docker-compose -f docker-compose-log.yml -f docker-compose-all_prev_serv.yml up --build` (Auth + Jaeger + MovieAPI + AdminPanel + ELK)

## Endpoints
  - http://127.0.0.1:8000/ugc/api/openapi
  - http://127.0.0.1/auth/docs/v1/
  - http://127.0.0.1/movies_fastapi/api/openapi
  - http://127.0.0.1/api/v1/movies# user_generated_content_service
