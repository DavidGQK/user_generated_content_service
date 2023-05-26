from fastapi_cache.decorator import cache
from opentelemetry import trace

from db.abstract import AsyncCacheStorage, AsyncDataStorage

BASE_CACHE_EXPIRE_IN_SECONDS = 30
tracer = trace.get_tracer(__name__)


class BaseEsId:
    def __init__(self, cache: AsyncCacheStorage, elastic: AsyncDataStorage):
        self.cache = cache
        self.elastic = elastic
        self.index = None

    @cache(expire=BASE_CACHE_EXPIRE_IN_SECONDS)
    async def get_es_by_id(self, id: str) -> None | dict:
        with tracer.start_as_current_span('Elastic or Redis'):
            doc = await self.elastic.get(self.index, id)
            return doc


class BaseEsList(BaseEsId):
    def __init__(
            self, cache, elastic, size: int = 50, page: int = 0,
            sort: str = '', query: str = None, filter: str = None):
        super().__init__(cache, elastic)
        self.size = size
        self.page = page
        self.sort = sort
        self.filter = filter
        self.query = query

    async def get_es_list(self, body: dict) -> None | dict:
        @cache(expire=BASE_CACHE_EXPIRE_IN_SECONDS)
        async def for_cache(index=..., body=..., params={}):
            resp = await self.elastic.search(index, body, params=params)
            return resp
        with tracer.start_as_current_span('Elastic or Redis'):
            doc = await for_cache(body, self.index, {
                'sort': self.sort,
                'from_': self.page * self.size,
                'size': self.size})
            return doc
