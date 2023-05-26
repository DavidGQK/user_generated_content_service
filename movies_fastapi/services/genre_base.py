from functools import lru_cache

from fastapi import Depends

from api.v1.response_model import Response_Genre
from db.abstract import AsyncCacheStorage, AsyncDataStorage
from db.elastic import get_elastic
from db.redis import get_redis
from models.models_pd import Genre
from services.base import BaseEsList


class GenreService(BaseEsList):
    def __init__(self, cache: AsyncCacheStorage, elastic: AsyncDataStorage):
        super().__init__(cache, elastic)
        self.index = 'genres'

    async def get_obj_by_id(self, id: str) -> Response_Genre | None:
        doc = await self.get_es_by_id(id)
        return Response_Genre(**doc['_source'] if doc else None)

    async def get_list(self, size=50, page=0, sort=None) -> Genre | None:
        self.size, self.page, self.sort = size, page, sort
        if self.sort:
            self.sort = 'id:asc,' if self.sort == 'uuid' else 'id:desc,'
        docs = await self.get_es_list(body='''{"query": {"match_all": {}}}''')
        query = [Genre(
            **doc['_source']) for doc in docs['hits']['hits']
        ] if docs else None
        return query


@lru_cache()
def get_genre_service(
        cache: AsyncCacheStorage = Depends(get_redis),
        elastic: AsyncDataStorage = Depends(get_elastic),
) -> GenreService:
    return GenreService(cache, elastic)
