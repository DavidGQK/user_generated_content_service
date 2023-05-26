import json
from http import HTTPStatus

import pytest
import redis
import requests
from redis import Redis

from functional.settings import test_settings as TS
from functional.testdata.for_cache_tests import (
    cache_film_id,
    cache_film_list,
    cache_genre_id,
    cache_genre_list,
    cache_person_id,
    cache_person_list
)


@pytest.fixture(scope='module')
def redis_client_sync():
    redis_client: Redis = redis.from_url(
        f'redis://{TS.redis_host_t}:{TS.redis_port_t}',
        decode_responses=True, max_connections=20)
    yield redis_client
    redis_client.close()


@pytest.mark.parametrize(
    'query_data, expected_answer',
    [({'query': 'films/id-0'}, {'status': HTTPStatus.OK, 'length': 1, 'redis_body': cache_film_id}),
     ({'query': 'genres/id-0'}, {'status': HTTPStatus.OK, 'length': 1, 'redis_body': cache_genre_id}),
     ({'query': 'persons/id-0'}, {'status': HTTPStatus.OK, 'length': 1, 'redis_body': cache_person_id}),]
)
def test_cache_id(query_data, expected_answer, clear_redis, redis_client_sync: Redis):
    """Alternate/synchronous way to test the cache - id."""
    clear_redis
    response = requests.get(f"{TS.service_url}{query_data['query']}")
    redis_keys = redis_client_sync.scan(_type='string')
    redis: str = redis_client_sync.get(redis_keys[1][0])
    redis: dict = json.loads(redis)
    assert response.status_code == expected_answer['status']
    assert len(redis_keys[1]) == expected_answer['length']
    assert redis['_source'] == expected_answer['redis_body']


@pytest.mark.parametrize(
    'query_data, expected_answer',
    [({'query': 'films'}, {'status': HTTPStatus.OK, 'length': 1, 'redis_body': cache_film_list}),
     ({'query': 'genres'}, {'status': HTTPStatus.OK, 'length': 1, 'redis_body': cache_genre_list}),
     ({'query': 'persons/search/?query=The Star'}, {'status': HTTPStatus.OK, 'length': 1, 'redis_body': cache_person_list}),
     ]
)
def test_cache_list(query_data, expected_answer, clear_redis, redis_client_sync: Redis):
    """Alternate/synchronous way to test the cache - list."""
    clear_redis
    response = requests.get(f"{TS.service_url}{query_data['query']}")
    redis_keys = redis_client_sync.scan(_type='string')
    redis: str = redis_client_sync.get(redis_keys[1][0])
    redis: dict = json.loads(redis)
    for i in range(len(redis['hits']['hits'])):
        del redis['hits']['hits'][i]['_score']
    assert response.status_code == expected_answer['status']
    assert len(redis_keys[1]) == expected_answer['length']
    assert redis['hits']['hits'] == expected_answer['redis_body']
