from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    kafka_url: str = Field('localhost:9092')
    kafka_client: str = Field('kafka-movies-api')
    topic_list: list = Field(['views'])
    project_name: str = Field('ugc_movies_api')
    mongo_db: str = Field(...)
    mongo_url: str = Field(...)
    sentry_dns: str = Field(...)
    logstash_host: str = Field(...)
    logstash_port: int = Field(...)
    log_level: str = Field('INFO')

    class Config:
        env_file = '../.env'


settings = Settings()
kafka_list_urls = [settings.kafka_url]
