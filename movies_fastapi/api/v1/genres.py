from http import HTTPStatus

from elasticsearch.exceptions import NotFoundError
from fastapi import APIRouter, Depends, HTTPException, Query

from api.v1.error import ERROR
from api.v1.pagination import PaginatedParams
from api.v1.response_model import Response_404, Response_Genre
from services.genre_base import GenreService, get_genre_service

router = APIRouter()
RESPONSE_404 = {404: {'description': ERROR['genre'], 'model': Response_404}}


@router.get('/', response_model=list[Response_Genre],
            responses=RESPONSE_404,
            description='Gives a list of genres.')
async def genre_list(
        sort: str = Query(default=''),
        pagin: PaginatedParams = Depends(),
        genre_service: GenreService = Depends(get_genre_service)
) -> list[Response_Genre]:
    try:
        genres_list = await genre_service.get_list(pagin.size, pagin.page, sort)
    except NotFoundError:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                            detail=ERROR['genre'])
    return genres_list


@router.get('/{genre_id}/', response_model=Response_Genre,
            responses=RESPONSE_404,
            description='Gives information about the genre, by its id.')
async def genre_details(
        genre_id: str,
        genre_service: GenreService = Depends(get_genre_service)
) -> Response_Genre:
    try:
        genre = await genre_service.get_obj_by_id(genre_id)
    except NotFoundError:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                            detail=ERROR['genre'])
    return genre
