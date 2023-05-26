from fastapi import APIRouter, Depends, Query

from api.v1.models import PostRequestReview, PostRequestReviewLike
from api.v1.models_response import (
    GetReviewsResponse,
    PostResponse,
    ReviewLikeGetListResponse
)
from api.v1.pagination import PaginatedParams
from services.review import ReviewService, get_review_service

router = APIRouter()
RESP404 = {"description": "Item not found"}


@router.post('/', responses={404: RESP404})
async def post_review(data: PostRequestReview,
                      review_serv: ReviewService = Depends(get_review_service)
                      ) -> PostResponse:
    """Posting a review."""
    res = await review_serv.post_review(data)
    return PostResponse.parse_obj({'id': res.inserted_id})


@router.get('/{review_id}', responses={404: RESP404})
async def get_review(review_id: str,
                     review_serv: ReviewService = Depends(get_review_service)
                     ) -> GetReviewsResponse:
    """Gives the review."""
    res = await review_serv.get_review(review_id)
    return GetReviewsResponse.parse_obj(res)


@router.post('/like', responses={404: RESP404})
async def post_review_like(data: PostRequestReviewLike,
                           review_serv: ReviewService = Depends(get_review_service)
                           ) -> PostResponse:
    """Posting a review likes it. """
    res = await review_serv.post_review_like(data)
    return PostResponse.parse_obj(res)


@router.get('/list/{movie_id}', responses={404: RESP404})
async def get_review_list(movie_id: str,
                          sort_rating: int = Query(default=None, alias='sort[rating]', ge=-1, le=1),
                          sort_count: int = Query(default=None, alias='sort[count]', ge=-1, le=1),
                          pagin: PaginatedParams = Depends(),
                          review_serv: ReviewService = Depends(get_review_service)
                          ) -> ReviewLikeGetListResponse:
    """Gives a list of reviews. There is pagination. Sorting by number of likes/dislikes,
    sorting by average rating """
    res = await review_serv.get_review_list(movie_id, sort_rating, sort_count, pagin)
    return ReviewLikeGetListResponse.parse_obj(i for i in res)


@router.delete('/clear_all', responses={404: RESP404})
async def delete_all(review_serv: ReviewService = Depends(get_review_service)):
    """Clears everything up. Uber after the revision."""
    await review_serv.clear_all()
    return
