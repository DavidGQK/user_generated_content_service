import os
from logging import config as logging_config

from pydantic import BaseSettings, Field

# from core.logger import LOGGING

# logging_config.dictConfig(LOGGING)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Settings(BaseSettings):
    redis_host: str = Field(...)
    redis_port: str = Field(...)
    elastic_host: str = Field(...)
    elastic_port: str = Field(...)
    project_name: str = Field(...)
    check_user_url: str = Field('http://flask_auth:5000/auth/api/v1/check_user')
    tests: bool = Field(False)
    debug: bool = Field(False)
    JAEGER_HOST: str = Field('jaeger')
    JAEGER_PORT: str = Field('6831')
    logstash_host: str = Field(...)
    logstash_port: int = Field(...)
    log_level: str = Field('INFO')

    class Config:
        env_file = '.env'


settings = Settings()
