from http import HTTPStatus

import pytest

from functional.testdata.api_ep_data_genre import (
    genre_list_id_0,
    genre_list_id_9,
    genre_list_id_17,
    genre_list_id_50
)


@pytest.mark.parametrize(
    'query_data, expected_answer',
    [({'query': 'id-0'}, {'status': HTTPStatus.OK, 'length': 3}),
     ({'query': 'id-60'}, {'status': HTTPStatus.NOT_FOUND, 'length': 1})]
)
@pytest.mark.asyncio
async def test_genre_by_id(make_get_request, query_data, expected_answer):
    query = query_data['query']
    body, headers, status = await make_get_request(f'genres/{query}/')
    assert status[0] == expected_answer['status']
    assert len(body[0]) == expected_answer['length']


@pytest.mark.parametrize(
    'query_data, expected_answer',
    [({'page[number]': 0, 'page[size]': 50},
      {'status': HTTPStatus.OK, 'length': 50, 'api_body': genre_list_id_0}),
     ({'page[number]': 5, 'page[size]': 10},
      {'status': HTTPStatus.OK, 'length': 10, 'api_body': genre_list_id_50}),
     ({'sort': '-uuid', 'page[number]': 0, 'page[size]': 50},
      {'status': HTTPStatus.OK, 'length': 50, 'api_body': genre_list_id_9}),
     ({'sort': '-uuid', 'page[number]': 5, 'page[size]': 10},
      {'status': HTTPStatus.OK, 'length': 10, 'api_body': genre_list_id_17}),
     ({'sort': 'uuid', 'page[number]': 0, 'page[size]': 50},
      {'status': HTTPStatus.OK, 'length': 50, 'api_body': genre_list_id_0})]
)
@pytest.mark.asyncio
async def test_genre_list(make_get_request, query_data, expected_answer):
    body, headers, status = await make_get_request('genres/', query_data)
    body = body if len(body[0]) > 1 else (body,)  # 404
    assert status[0] == expected_answer['status']
    assert len(body[0]) == expected_answer['length']
    assert body[0][0] == expected_answer['api_body']
