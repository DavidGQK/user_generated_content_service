from functools import lru_cache

from fastapi import Depends

from db.abstract import AsyncCacheStorage, AsyncDataStorage
from db.elastic import get_elastic
from db.redis import get_redis
from models.models_pd import Film, Person
from services.base import BaseEsList


class PersonService(BaseEsList):
    def __init__(self, cache: AsyncCacheStorage, elastic: AsyncDataStorage):
        super().__init__(cache, elastic)

    async def get_obj_by_id(self, id: str) -> Person | None:
        self.index = 'persons'
        doc = await self.get_es_by_id(id)
        return Person(**doc['_source'] if doc else None)

    async def get_films_by_person_id(
            self, uuid: str, size=50, page=0) -> list[Film]:
        self.size, self.page = size, page
        self.index = 'movies'
        body = """{
                    "query": {
                        "nested" : {
                            "path" : "actors",
                            "query" : {
                                "match" : {"actors.id" : "%s"}
                            }
                        }
                    }
                }""" % uuid
        films = await self.get_es_list(body=body)
        return [Film(**f["_source"]) for f in films["hits"]["hits"]]

    async def search(self, query=None, size=50, page=0) -> list[Person]:
        self.size, self.page, self.query = size, page, query
        self.index = 'persons'
        body = """{
                   "query": {
                            "multi_match": {
                                "query": "%s",
                                "fuzziness": "auto"
                                }
                            }
                }""" % self.query
        persons = await self.get_es_list(body=body)
        return [Person(**p["_source"]) for p in persons["hits"]["hits"]]


@lru_cache()
def get_person_service(
        cache: AsyncCacheStorage = Depends(get_redis),
        elastic: AsyncDataStorage = Depends(get_elastic),
) -> PersonService:
    return PersonService(cache, elastic)
