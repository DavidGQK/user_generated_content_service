from fastapi import APIRouter, Depends, HTTPException

from api.v1.models import PostRequestBookmark
from api.v1.models_response import (
    BookmarksGetListResponse,
    BookmarksGetResponse,
    MongoDelResponse,
    PostResponse
)
from api.v1.pagination import PaginatedParams
from services.bookmark import BookmarkService, get_bookmark_service

router = APIRouter()
RESP404 = {"detail": "Not found"}


@router.post('/', responses={404: RESP404})
async def post_bookmark(data: PostRequestBookmark,
                        bookmark_serv: BookmarkService = Depends(get_bookmark_service)
                        ) -> PostResponse:
    """Posting a bookmark."""
    res = await bookmark_serv.post_bookmark(data)
    return PostResponse.parse_obj(res)


@router.get('/{bookmark_id}', responses={404: RESP404})
async def get_bookmark(bookmark_id: str,
                       bookmark_serv: BookmarkService = Depends(get_bookmark_service)
                       ) -> BookmarksGetResponse:
    """Gives the bookmark by id."""
    res = await bookmark_serv.get_bookmark(bookmark_id)
    return BookmarksGetResponse.parse_obj(res)


@router.delete('/', responses={404: RESP404})
async def delete_bookmark(data: PostRequestBookmark,
                          bookmark_serv: BookmarkService = Depends(get_bookmark_service)
                          ) -> MongoDelResponse:
    """Deletes the bookmark."""
    res = await bookmark_serv.delete_bookmark(data)
    return MongoDelResponse.parse_obj(res)


@router.get('/list/{user_id}', responses={404: RESP404})
async def get_list_bookmark(user_id: str,
                            pagin: PaginatedParams = Depends(),
                            bookmark_serv: BookmarkService = Depends(get_bookmark_service)
                            ) -> BookmarksGetListResponse:
    """Gives a list of bookmarks by user id."""
    res = await bookmark_serv.get_bookmark_list(user_id, pagin)
    return BookmarksGetListResponse.parse_obj([i for i in res])
