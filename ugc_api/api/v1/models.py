from datetime import datetime

import orjson
from pydantic import BaseModel


def orjson_dumps(v, *, default):
    return orjson.dumps(v, default=default).decode()


class OrJsonModel(BaseModel):

    class Config:
        json_loads = orjson.loads
        json_dumps = orjson_dumps


class RequestKafka(OrJsonModel):
    user_id: str
    movie_id: str
    value: int

    class Config:
        schema_extra = {
            "example": {
                "user_id": "500271",
                "movie_id": "tt0120338",
                "value": 161111111
            }
        }


class ItemKafka(RequestKafka):
    topic: str
    time_stamp: str

    class Config:
        schema_extra = {
            "example": {
                "topic": "views",
                "user_id": "500271",
                "movie_id": "tt0120338",
                "value": 161111111,
                "time_stamp": "161112222"
            }
        }


class ResponseKafka(OrJsonModel):
    __root__: list[ItemKafka]


class PostRequestLike(OrJsonModel):
    user_id: str
    movie_id: str
    time_stamp: datetime = datetime.now()
    value: int | None = None

    class Config:
        schema_extra = {
            "example": {
                "user_id": "500271",
                "movie_id": "tt0120338",
                "value": 10
            }
        }


class DeleteRequestLike(PostRequestLike):

    class Config:
        schema_extra = {
            "example": {
                "user_id": "500271",
                "movie_id": "tt0120338"
            }
        }


class PostRequestReview(OrJsonModel):
    user_id: str
    movie_id: str
    text: str
    time_stamp: datetime = datetime.now()
    value: int | None = None
    count_like: int = 1
    summ_like: int = 5

    class Config:
        schema_extra = {
            "example": {
                "user_id": "500271",
                "movie_id": "tt0120338",
                "text": "nice movie",
                "value": 10
            }
        }


class PostRequestReviewLike(OrJsonModel):
    user_id: str
    review_id: str
    time_stamp: datetime = datetime.now()
    value: int | None = None

    class Config:
        schema_extra = {
            "example": {
                "user_id": "500271",
                "review_id": "63f000dc052663091532fc51",
                "value": 10
            }
        }


class PostRequestBookmark(OrJsonModel):
    user_id: str
    movie_id: str

    class Config:
        schema_extra = {
            "example": {
                "user_id": "500271",
                "movie_id": "tt0120338",
            }
        }
