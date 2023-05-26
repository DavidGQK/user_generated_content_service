from functools import lru_cache
from typing import Any

from bson.objectid import ObjectId
from fastapi import Depends, HTTPException, status
from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorCollection,
    AsyncIOMotorDatabase
)
from pymongo.results import InsertOneResult, UpdateResult

from api.v1.models import PostRequestReview, PostRequestReviewLike
from api.v1.pagination import PaginatedParams
from core.config import settings
from db.mongo import get_aio_motor
from services.like import LikeService, PostRequestLike


class ReviewService():
    def __init__(self, mongo: AsyncIOMotorClient):
        self.mongo = mongo
        self.db: AsyncIOMotorDatabase = self.mongo[settings.mongo_db]
        self.review: AsyncIOMotorCollection = self.db.review
        self.review_like: AsyncIOMotorCollection = self.db.review_like

    async def post_review(self, data: PostRequestReview) -> InsertOneResult:
        """Posts a review. The post is rated at creation 5.0 (count=1, summ=5)."""
        data_dict = data.dict()
        _id: InsertOneResult = await self.review.insert_one(data_dict)
        if data_dict['value']:
            like = LikeService(self.mongo)
            await like.post_like(PostRequestLike(user_id=data_dict['user_id'],
                                                 movie_id=data_dict['movie_id'],
                                                 value=data_dict['value']))
        return _id

    async def get_review(self, data: str) -> dict:
        """A pen is out of the job, but needed."""
        res = await self.review.find_one({'_id': ObjectId(data)})
        if not res:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        return res

    async def post_review_like(self, data: PostRequestReviewLike) -> HTTPException | dict[str, Any]:
        """Post a like on the review, adds the amount and amount to the review model,
        to calculate the average rating when generating the review list for a movie."""
        if _ := await self.review_like.find_one({'user_id': data.user_id, 'review_id': data.review_id}):
            raise HTTPException(status.HTTP_409_CONFLICT)
        data_dict = data.dict()
        _id: InsertOneResult = await self.review_like.insert_one(data_dict)
        await self.review.update_one({'_id': ObjectId(data.review_id)}, {'$inc': {'summ_like': data.value, 'count_like': 1}})
        return {'id': _id.inserted_id}

    async def _put_review_like(self, data: PostRequestReviewLike) -> HTTPException | dict[str, Any]:
        """It's not a working method yet. You can only like the review once."""
        res: UpdateResult = await self.review_like.update_one(
            {'user_id': data.user_id,
             'review_id': data.review_id},
            {'$set': {'value': data.value}})
        if res.matched_count == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        return res.raw_result

    async def get_review_list(self, movie_id: str, sort_rating: int, sort_count: int, pagin: PaginatedParams) -> list[dict]:
        """A method for generating a list of reviews, summ_like and count_like in reviews for debugging."""
        pipeline = [{'$match': {'movie_id': movie_id}},
                    {'$project': {'summ_like': 1, 'count_like': 1, 'user_id': 1, 'text': 1, 'rating': {'$divide': ['$summ_like', '$count_like']}}},
                    {'$skip': pagin.page * pagin.size},
                    {'$limit': pagin.size}]
        pipeline.append({'$sort': {'rating': sort_rating}}) if sort_rating else {}
        pipeline.append({'$sort': {'count_like': sort_count}}) if sort_count else {}
        res = []
        async for docs in self.review.aggregate(pipeline):
            res.append(docs)
        return res

    async def clear_all(self) -> None:
        """No comments"""
        self.review.drop()
        self.review_like.drop()


@lru_cache()
def get_review_service(
    mongo_storage: AsyncIOMotorClient = Depends(get_aio_motor),
) -> ReviewService:
    return ReviewService(mongo=mongo_storage)
