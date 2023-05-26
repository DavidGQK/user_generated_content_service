from typing import List, Optional

from models.base_model import OrJsonModel


class Genre(OrJsonModel):
    id: Optional[str]
    name: Optional[str]
    description: Optional[str]


class FilmId(OrJsonModel):
    id: str


class Person(OrJsonModel):
    id: Optional[str]
    full_name: Optional[str]
    roles: List[str]
    films: Optional[List[FilmId]]


class Film(OrJsonModel):
    id: Optional[str]
    title: Optional[str]
    description: Optional[str]
    rating: Optional[float]
    genre: Optional[List[Genre]]
    director: Optional[List[dict]]
    writers: Optional[List[dict]]
    actors: Optional[List[dict]]
    writers_names: Optional[List[str]]
    director_name: Optional[List[str]]
    actors_names: Optional[List[str]]
