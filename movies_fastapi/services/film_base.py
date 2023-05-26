from functools import lru_cache

from fastapi import Depends

from api.v1.response_model import ResponseFilm
from db.abstract import AsyncCacheStorage, AsyncDataStorage
from db.elastic import get_elastic
from db.redis import get_redis
from models.models_pd import Film
from services.base import BaseEsList


class FilmService(BaseEsList):
    def __init__(self, cache: AsyncCacheStorage, elastic: AsyncDataStorage):
        super().__init__(cache, elastic)
        self.index = 'movies'

    async def get_obj_by_id(self, id: str) -> ResponseFilm | None:
        doc = await self.get_es_by_id(id)
        return ResponseFilm(**doc['_source'] if doc else None)

    async def get_list(self, query=None, filter=None, sort='',
                       size=50, page=0) -> Film | None:
        self.query, self.filter, self.sort, self.size, self.page = (
            query, filter, sort, size, page)
        docs = await self._get_film_all_from_elastic()
        query = [Film(
            **doc['_source']) for doc in docs['hits']['hits']
        ] if docs else None
        return query

    def _get_search_or_filter(self) -> dict:
        if self.filter:
            return {"query": {"nested": {
                    "path": "genre", "query": {
                        "bool": {"must": {"match": {
                            "genre.id": f"{self.filter}"}}}}}}}
        if self.query:
            return {"query": {"bool": {"must": [{"multi_match": {
                    "query": self.query,
                    "fields": ["title", "description"]}}]}}}
        return {"query": {"match_all": {}}}

    async def _get_film_all_from_elastic(self) -> dict | None:
        if self.sort:
            self.sort = 'rating:asc,' if self.sort == 'imdb_rating' else 'rating:desc,'
        docs = await self.get_es_list(body=self._get_search_or_filter())
        return docs


@lru_cache()
def get_film_service(
        cache: AsyncCacheStorage = Depends(get_redis),
        elastic: AsyncDataStorage = Depends(get_elastic),
) -> FilmService:
    return FilmService(cache, elastic)
