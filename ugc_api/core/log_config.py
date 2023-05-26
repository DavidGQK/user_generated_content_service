import logging

import logstash
from fastapi import Request
from fastapi.logger import logger as fastapi_logger

from core.config import settings as SET


class RequestIdFilter(logging.Filter):
    def __init__(self, request: Request, name: str):
        self.request = request
        self.name = name
    
    def filter(self, record):
        record.request_id = self.request.headers.get('X-Request-Id')
        record.tags = ['ugc']
        return True


def init_logs() -> None:
    logstash_handler = logstash.LogstashHandler(SET.logstash_host, int(SET.logstash_port), version=1)
    gunicorn_error_logger = logging.getLogger("gunicorn.error")
    # print(gunicorn_error_logger.handlers)
    gunicorn_error_logger.setLevel(SET.log_level)
    gunicorn_error_logger.addHandler(logstash_handler)
    uvicorn_access_logger = logging.getLogger("uvicorn.access")
    uvicorn_access_logger.setLevel(SET.log_level)
    uvicorn_access_logger.addHandler(logstash_handler)
    # logging.root.addHandler(logstash_handler)
    # logging.root.setLevel(SET.log_level)
    # print(uvicorn_access_logger.handlers)
    # fastapi_logger.handlers = gunicorn_error_logger.handlers
    # fastapi_logger.setLevel(SET.log_level)
