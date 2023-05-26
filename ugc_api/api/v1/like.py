from fastapi import APIRouter, Depends

from api.v1.models import DeleteRequestLike, PostRequestLike
from api.v1.models_response import (
    GetLikeAvgResponse,
    GetLikeCountResponse,
    GetLikeResponse,
    MongoDelResponse,
    MongoPutResponse,
    PostResponse
)
from services.like import LikeService, get_like_service

router = APIRouter()
RESP404 = {"detail": "Not found"}


@router.post('/', responses={404: RESP404})
async def post_like(data: PostRequestLike,
                    like_serv: LikeService = Depends(get_like_service)
                    ) -> PostResponse:
    """Posting likes."""
    res = await like_serv.post_like(data)
    return PostResponse.parse_obj(res)


@router.get('/{like_id}', responses={404: RESP404})
async def get_like(like_id: str,
                   like_serv: LikeService = Depends(get_like_service)
                   ) -> GetLikeResponse:
    """Gives the likes by the likes id."""
    res = await like_serv.get_like(like_id)
    return GetLikeResponse.parse_obj(res)


@router.get('/count_likes/{movie_id}', responses={404: RESP404})
async def get_count_likes(movie_id: str,
                          like_serv: LikeService = Depends(get_like_service)
                          ) -> GetLikeCountResponse:
    """Gives the number of likes/dislikes."""
    res = await like_serv.get_count_likes(movie_id)
    return GetLikeCountResponse.parse_obj(res)


@router.get('/avg_likes/{movie_id}', responses={404: RESP404})
async def get_avg_likes(movie_id: str,
                        like_serv: LikeService = Depends(get_like_service)
                        ) -> GetLikeAvgResponse:
    """Gives an average rating."""
    res = await like_serv.get_avg_likes(movie_id)
    return GetLikeAvgResponse.parse_obj(res)


@router.put('/', responses={404: RESP404})
async def put_like(data: PostRequestLike,
                   like_serv: LikeService = Depends(get_like_service)
                   ) -> MongoPutResponse:
    """Updates the likes of this."""
    res = await like_serv.put_like(data)
    return MongoPutResponse.parse_obj(res)


@router.delete('/', responses={404: RESP404})
async def delete_like(data: DeleteRequestLike,
                      like_serv: LikeService = Depends(get_like_service)
                      ) -> MongoDelResponse:
    """Removes the likes."""
    res = await like_serv.delete_like(data)
    return MongoDelResponse.parse_obj(res)
