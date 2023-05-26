from http import HTTPStatus

from elasticsearch.exceptions import NotFoundError
from fastapi import APIRouter, Depends, HTTPException, Query

from api.v1.error import ERROR
from api.v1.pagination import PaginatedParams
from api.v1.response_model import (
    Response_404,
    Response_Person,
    Response_Person_Film
)
from services.person_base import PersonService, get_person_service

router = APIRouter()
RESPONSE_404 = {404: {'description': ERROR['person'], 'model': Response_404}}


@router.get('/search/', response_model=list[Response_Person],
            responses=RESPONSE_404,
            description=('Full-text search. Gives a list of people, taking into account'
                         ' pagination.'))
async def search_persons(
        query: str,
        pagin: PaginatedParams = Depends(),
        person_search_service: PersonService = Depends(get_person_service)
) -> list[Response_Person]:
    try:
        persons = await person_search_service.search(query, pagin.size, pagin.page)
        if not persons:
            raise NotFoundError
    except NotFoundError:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                            detail=ERROR['person'])
    return [Response_Person(
        uuid=p.id, films_ids=[f.id for f in p.films],
        role=p.roles[0], full_name=p.full_name) for p in persons]


@router.get('/{person_id}/', response_model=Response_Person,
            responses=RESPONSE_404,
            description='Gives information about the person, by his id.')
async def person_details(
        person_id: str,
        person_service: PersonService = Depends(get_person_service)
) -> Response_Person:
    try:
        person = await person_service.get_obj_by_id(person_id)
    except NotFoundError:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                            detail=ERROR['person'])
    return Response_Person(
        uuid=person.id, films_ids=[f.id for f in person.films],
        role=person.roles[0] if person.roles else '',
        full_name=person.full_name)


@router.get('/{person_id}/film', response_model=list[Response_Person_Film],
            responses=RESPONSE_404,
            description='Gives a list of movies that match the persona(id).')
async def person_films(
        person_id: str,
        pagin: PaginatedParams = Depends(),
        person_film_service: PersonService = Depends(get_person_service)
) -> list[Response_Person_Film]:
    try:
        films = await person_film_service.get_films_by_person_id(
            person_id, pagin.size, pagin.page)
        if not films:
            raise NotFoundError
    except NotFoundError:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                            detail=ERROR['person'])
    return films
