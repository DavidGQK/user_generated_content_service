from typing import List, Optional

from pydantic import Field

from models.base_model import OrJsonModel


class GenreForFilm(OrJsonModel):
    id: Optional[str] = Field(alias='uuid')
    name: Optional[str]

    class Config:
        allow_population_by_field_name = True


class PersonForFilm(GenreForFilm):
    name: Optional[str] = Field(alias='full_name')


class ResponseFilms(OrJsonModel):
    id: Optional[str] = Field(alias='uuid')
    title: Optional[str]
    rating: Optional[float] = Field(alias='imdb_rating')

    class Config:
        allow_population_by_field_name = True


class ResponseFilm(ResponseFilms):
    description: Optional[str]
    genre: Optional[List[GenreForFilm]]
    director: Optional[List[PersonForFilm]] = Field(alias='directors')
    writers: Optional[List[PersonForFilm]]
    actors: Optional[List[PersonForFilm]]


class ResponseFilmList(OrJsonModel):
    __root__: List[ResponseFilms]


class Response_Genre(OrJsonModel):
    id: Optional[str] = Field(alias='uuid')
    name: Optional[str]
    description: Optional[str]

    class Config:
        allow_population_by_field_name = True


class Response_Person(OrJsonModel):
    id: Optional[str] = Field(alias='uuid')
    full_name: Optional[str]
    roles: Optional[str] = Field(alias='role')
    films: Optional[List[str]] = Field(alias='films_ids')

    class Config:
        allow_population_by_field_name = True


class Response_Person_Film(OrJsonModel):
    id: Optional[str] = Field(alias='uuid')
    title: Optional[str]
    rating: Optional[float] = Field(alias='imdb_rating')

    class Config:
        allow_population_by_field_name = True


class Response_404(OrJsonModel):
    detail: Optional[str]
