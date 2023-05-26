import os
import sys

from pydantic import BaseSettings, Field

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)


class TestSettings(BaseSettings):
    es_host: str = Field(...)
    es_port: str = Field(...)
    es_url: str = Field(...)
    es_index: str = Field(...)
    es_id_field: str = Field(...)
    es_index_mapping: dict = Field(...)
    redis_host_t: str = Field(...)
    redis_port_t: str = Field(...)
    redis_url: str = Field(...)
    service_url: str = Field(...)

    class Config:
        env_file = f'{BASE_DIR}/functional/.env'


test_settings = TestSettings()
