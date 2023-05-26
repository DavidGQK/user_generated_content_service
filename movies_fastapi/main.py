import logging

import aiohttp
import aioredis
import uvicorn
from elasticsearch import AsyncElasticsearch
from fastapi import Depends, FastAPI, Request
from fastapi.responses import ORJSONResponse, Response
from fastapi.security.http import HTTPBearer
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from api.v1 import films, genres, persons
from core.config import settings
from core.jaeger import config_jaeger, init_jaeger
from core.log_config import RequestIdFilter, init_logs
from db import elastic, redis


def get_application() -> FastAPI:
    config_jaeger()
    app = FastAPI(
        title=settings.project_name,
        docs_url='/movies_fastapi/api/openapi',
        openapi_url='/movies_fastapi/api/openapi.json',
        default_response_class=ORJSONResponse,
    )
    JWT_scheme = HTTPBearer(auto_error=not settings.tests)
    app.include_router(films.router, prefix='/movies_fastapi/api/v1/films',
                       tags=['films'], dependencies=[Depends(JWT_scheme)])
    app.include_router(genres.router, prefix='/movies_fastapi/api/v1/genres',
                       tags=['genres'], dependencies=[Depends(JWT_scheme)])
    app.include_router(persons.router, prefix='/movies_fastapi/api/v1/persons',
                       tags=['persons'], dependencies=[Depends(JWT_scheme)])
    app = init_jaeger(app)
    return app


app = get_application()
tracer = trace.get_tracer(__name__)


@app.middleware('http')
async def check_user(request: Request, call_next):
    with tracer.start_as_current_span('Movie_FastAPI_Full_Query') as mfa:
        request_id = request.headers.get('X-Request-Id')
        span = tracer.start_span('Create X-Request-Id')
        span.set_attribute('http.request_id', request_id)
        span.end()
        if request.url.path in [app.docs_url, app.openapi_url] or settings.tests:
            return await call_next(request)
        headers = request.headers
        async with aiohttp.ClientSession() as client:
            with tracer.start_as_current_span('auth_api'):
                resp = await client.get(settings.check_user_url, headers=headers)
                mfa.add_event(f'Auth event, response status- {resp.status}')
                trace.get_current_span().end()
                if resp.status == 200:
                    response = await call_next(request)
                    return response
                return Response(status_code=401)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Добавление requist id в логгеры. """
    uvicorn_access_logger = logging.getLogger("uvicorn.access")
    uvicorn_access_logger.addFilter(RequestIdFilter(request, 'RequestIdFilter'))
    uvicorn_error_logger = logging.getLogger("uvicorn.error")
    uvicorn_error_logger.addFilter(RequestIdFilter(request, 'RequestIdFilter'))
    response: Response = await call_next(request)
    return response


@app.on_event('startup')
async def startup():
    init_logs()
    redis.redis = await aioredis.from_url(
        f'redis://{settings.redis_host}:{settings.redis_port}',
        decode_responses=True, max_connections=1024)
    elastic.es = AsyncElasticsearch(
        hosts=[f'{settings.elastic_host}:{settings.elastic_port}'],
        timeout=10)
    FastAPICache.init(RedisBackend(redis.redis), prefix='fastapi-cache')


@app.on_event('shutdown')
async def shutdown():
    redis.redis.close()
    await redis.redis.close()
    await elastic.es.close()


if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', port=8000, limit_max_requests=1024)
