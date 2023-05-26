from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    api_requests_count = 1024
    api_kafka_post: str = Field('http://127.0.0.1:8000/api/v1/kafka/')
    topic_list: list = Field(['views', 'rating', 'like'])
    kafka_client: str = Field('kafka-movies-api-test')
    kafka_url: str = Field('localhost:9092')
    requests_count_for_every_topic = 100000

    class Config:
        env_file = '../.env'


settings = Settings()
