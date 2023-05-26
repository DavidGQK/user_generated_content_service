from typing import List

from api.v1.convert_object import DatatimeAsStr, ObjectIdAsStr
from api.v1.models import OrJsonModel


class PostResponse(OrJsonModel):
    id: str # ObjectIdAsStr

    class Config:
        schema_extra = {
            "example": {
                "id": "63f88bf1d815009d8d9e3377"
            }
        }


class BookmarksGetResponse(OrJsonModel):
    _id: str
    user_id: str
    movie_id: str

    class Config:
        schema_extra = {
            "example": {
                "_id": "63f88bf1d815009d8d9e3377",
                "user_id": "5002717",
                "movie_id": "tt01203318"
            }
        }


class BookmarksListObj(OrJsonModel):
    _id: str
    movie_id: str


class BookmarksGetListResponse(OrJsonModel):
    __root__: List[BookmarksListObj]

    class Config:
        schema_extra = {
            "example": [{
                "_id": "63f88bf1d815009d8d9e3377",
                "movie_id": "tt01203318"
            },]
        }


class MongoDelResponse(OrJsonModel):
    n: int
    ok: float

    class Config:
        schema_extra = {
            "example": {
                "n": 1,
                "ok": 1.0
            }
        }


class MongoPutResponse(MongoDelResponse):
    nModified: int
    updatedExisting: bool

    class Config:
        schema_extra = {
            "example": {
                "n": 1,
                "nModified": 1,
                "ok": 1.0,
                "updatedExisting": True
            }
        }


class GetLikeResponse(BookmarksGetResponse):
    time_stamp: DatatimeAsStr
    value: str

    class Config:
        schema_extra = {
            "example": {
                "_id": "63f897707288aba714550366",
                "user_id": "500271",
                "movie_id": "tt01203381",
                "time_stamp": "2023-02-24T10:03:31.857000",
                "value": 8
            }
        }


class GetLikeCountResponse(OrJsonModel):
    like: int
    dislike: int

    class Config:
        schema_extra = {
            "example": {
                "like": 1,
                "dislike": 0
            }
        }


class GetLikeAvgResponse(OrJsonModel):
    avg: float

    class Config:
        schema_extra = {
            "example": {
                "avg": 9.0
            }
        }


class GetReviewsResponse(GetLikeResponse):
    text: str
    count_like: str
    summ_like: str

    class Config:
        schema_extra = {
            "example": {
                "_id": "63f89de3d815009d8d9e3380",
                "user_id": "5002717",
                "movie_id": "tt0120338",
                "text": "wqeqweqweqwedsd3",
                "time_stamp": "2023-02-24T10:03:31.651000",
                "value": 10,
                "count_like": 1,
                "summ_like": 5
            }
        }


class ReviewLikeObjResponse(OrJsonModel):
    _id: str
    user_id: str
    text: str
    count_like: int
    summ_like: int
    rating: float


class ReviewLikeGetListResponse(OrJsonModel):
    __root__: list[ReviewLikeObjResponse]

    class Config:
        schema_extra = {
            "example": [{
                "_id": "63f897037288aba714550361",
                "user_id": "5002717",
                "text": "wqeqweqweqwedsd3",
                "count_like": 1,
                "summ_like": 5,
                "rating": 5.0
            },]
        }
