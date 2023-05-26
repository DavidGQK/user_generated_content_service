from http import HTTPStatus

from elasticsearch.exceptions import NotFoundError
from fastapi import APIRouter, Depends, HTTPException, Query

from api.v1.error import ERROR
from api.v1.pagination import PaginatedParams
from api.v1.response_model import Response_404, ResponseFilm, ResponseFilmList
from services.film_base import FilmService, get_film_service

router = APIRouter()
RESPONSE_404 = {404: {'description': ERROR['film'], 'model': Response_404}}


@router.get('/{film_id}', response_model=ResponseFilm,
            responses=RESPONSE_404,
            description='Gives information about the film, by its id.')
async def film_details(
        film_id: str,
        film_service: FilmService = Depends(get_film_service)
) -> ResponseFilm:
    try:
        film = await film_service.get_obj_by_id(film_id)
    except NotFoundError:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                            detail=ERROR['film'])
    return film


@router.get('/', response_model=ResponseFilmList,
            responses=RESPONSE_404,
            description=('Gives a list of movies, taking into account the filter by genre,'
                         ' Sorting by rating, pagination.'))
async def film_list(
        filter: str = Query(default=None, alias='filter[genre]'),
        sort: str = Query(default=''),
        pagin: PaginatedParams = Depends(),
        film_service: FilmService = Depends(get_film_service)
) -> ResponseFilmList:
    try:
        films = await film_service.get_list(None, filter, sort, pagin.size, pagin.page)
        if not films:
            raise NotFoundError
    except NotFoundError:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                            detail=ERROR['film'])
    return ResponseFilmList.parse_obj([film.dict() for film in films])


@router.get('/search/', response_model=ResponseFilmList,
            responses=RESPONSE_404,
            description=('Full-text search. Gives a list of movies, taking into account'
                         ' sorting by rating, pagination.'))
async def film_search(
        query: str = Query(default=None, min_length=3, max_length=256),
        sort: str = Query(default=''),
        pagin: PaginatedParams = Depends(),
        film_service: FilmService = Depends(get_film_service)
) -> ResponseFilmList:
    try:
        films = await film_service.get_list(query, None, sort, pagin.size, pagin.page)
        if not films:
            raise NotFoundError
    except NotFoundError:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                            detail=ERROR['film'])
    return ResponseFilmList.parse_obj([film.dict() for film in films])
