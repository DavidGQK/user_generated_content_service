import logging

import logstash
from flask import Flask, Response, request

from core.config import settings


class RequestIdFilter(logging.Filter):
    def __init__(self, name: str | None = None, response: Response | None = None) -> None:
        self.name = name
        self.response: Response = response
    
    def filter(self, record):
        record.request_id = request.headers.get('X-Request-Id')
        record.tags = ['auth_api']
        record.status = self.response.status_code
        record.request = request
        return True


def init_logs(app: Flask):
    logstash_handler = logstash.LogstashHandler(settings.logstash_host, settings.logstash_port, version=1)
    logger = logging.getLogger(app.name)
    app.logger = logger
    app.logger.addHandler(logstash_handler)
    app.logger.setLevel(settings.log_level)

    
    
    
    
    # app.logger = logging.getLogger()
    # app.logger.error('111111111111111 - %s   ----222222 - %s', __name__, app.name)
    # app.logger.setLevel(settings.log_level)
    # # app.logger.addFilter(RequestIdFilter('RequestIdFilter'))
    # app.logger.addHandler(logstash_handler)

    # gunicorn_error_logger = logging.getLogger("gunicorn.error")
    # # gunicorn_error_logger.handlers.append(app.logger.handlers)
    # gunicorn_error_logger.setLevel(settings.log_level)
    # gunicorn_error_logger.addHandler(logstash_handler)
    # app.logger.error('3333333333 - %s   ----222222 - %s', gunicorn_error_logger.handlers, app.name)

    # gunicorn_logger = logging.getLogger("gunicorn")
    # # gunicorn_logger.handlers.append(app.logger.handlers)
    # gunicorn_logger.setLevel(settings.log_level)
    # gunicorn_logger.addHandler(logstash_handler)
    # app.logger.error('444444444 - %s   ----222222 - %s', gunicorn_logger.handlers, app.name)
