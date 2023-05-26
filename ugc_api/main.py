import os
import sys

# Debug
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR or f'{BASE_DIR}\\ugc_api' not in sys.path:
    sys.path.append(BASE_DIR)
    sys.path.append(f'{BASE_DIR}\\ugc_api')

import logging

import sentry_sdk
import uvicorn
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from fastapi import FastAPI, Request, Response
from fastapi.responses import ORJSONResponse

from api.v1 import bookmark, kafka, like, review
from core.config import settings as SET
from core.kafka_config import kafka_init, kafka_kwargs
from core.log_config import RequestIdFilter, init_logs
from db import kafka_consumer, kafka_producer

sentry_sdk.init(
    dsn=SET.sentry_dns,
    traces_sample_rate=1.0,
)

app = FastAPI(
    title=SET.project_name,
    docs_url='/ugc/api/openapi',
    openapi_url='/ugc/api/openapi.json',
    default_response_class=ORJSONResponse,
)


app.include_router(kafka.router, prefix='/ugc/api/v1/kafka', tags=['kafka'])
app.include_router(review.router, prefix='/ugc/api/v1/review', tags=['review'])
app.include_router(like.router, prefix='/ugc/api/v1/like', tags=['like'])
app.include_router(bookmark.router, prefix='/ugc/api/v1/bookmark', tags=['bookmark'])


@app.on_event('startup')
async def startup():
    kafka_init()
    init_logs()
    kafka_producer.aio_producer = AIOKafkaProducer(**kafka_kwargs)
    kafka_consumer.aio_consumer = AIOKafkaConsumer(
        *SET.topic_list,
        **kafka_kwargs,
        auto_offset_reset='earliest',
        group_id='echo-messages-to-stdout',
        consumer_timeout_ms=100)
    await kafka_producer.aio_producer.start()
    await kafka_consumer.aio_consumer.start()


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Adding requist id to loggers. """
    uvicorn_access_logger = logging.getLogger("uvicorn.access")
    uvicorn_access_logger.addFilter(RequestIdFilter(request, 'RequestIdFilter'))
    uvicorn_error_logger = logging.getLogger("uvicorn.error")
    uvicorn_error_logger.addFilter(RequestIdFilter(request, 'RequestIdFilter'))
    response: Response = await call_next(request)
    return response


@app.on_event('shutdown')
async def shutdown():
    await kafka_producer.aio_producer.stop()
    await kafka_consumer.aio_consumer.stop()

if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', port=8000, limit_max_requests=1024, workers=1, reload=True)
