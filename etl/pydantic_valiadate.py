import logging
from os import environ

from pydantic import BaseSettings, Field

logging.basicConfig(format='%(asctime)s[%(name)s]: %(message)s',
                    level=environ.get('logging'))
logger = logging.getLogger(__name__)


class EnvSetting(BaseSettings):
    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'


class PgS(EnvSetting):
    dbname: str = Field(env='POSTGRES_DB')
    user: str = Field(env='POSTGRES_USER')
    password: str = Field(env='POSTGRES_PASSWORD')
    port: int = Field(env='POSTGRES_PORT')
    host: str = Field(env='POSTGRES_HOST')

    class Config:
        env_prefix = 'postgres_'


class ElS(EnvSetting):
    host: str = Field(env='ELASTIC_HOST', default='127.0.0.1')
    port: int = Field(env='ELASTIC_PORT', default='9200')
    user: str = Field(env='ELASTIC_USER', default='')
    password: str = Field(env='ELASTIC_PASSWORD', default='')

    class Config:
        env_prefix = 'elastic_'


if __name__ == '__main__':
    logger.debug('PgSetting: %s - loaded', PgS().dict())
    logger.debug('ElSetting: %s - loaded', ElS().dict())
