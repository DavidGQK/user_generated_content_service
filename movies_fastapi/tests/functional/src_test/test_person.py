from http import HTTPStatus

import pytest

from functional.testdata.api_ep_data_person import (
    person_id_0,
    person_id_1_films,
    person_id_42
)


@pytest.mark.parametrize(
    'query_data, expected_answer',
    [({'query': 'id-0'}, {'status': HTTPStatus.OK, 'length': 4, 'api_body': person_id_0}),
     ({'query': 'id-60'}, {'status': HTTPStatus.NOT_FOUND, 'length': 1, 'api_body': {'detail': 'person not found'}})]
)
@pytest.mark.asyncio
async def test_person_by_id(make_get_request, query_data, expected_answer):
    query = query_data['query']
    body, headers, status = await make_get_request(f'persons/{query}/')
    assert status[0] == expected_answer['status']
    assert len(body[0]) == expected_answer['length']
    assert body[0] == expected_answer['api_body']


@pytest.mark.parametrize(
    'query_data, expected_answer',
    [({'query': 'id-1'},
      {'status': HTTPStatus.OK, 'length': 50, 'api_body': person_id_1_films}),
     ({'query': 'Jane'},
      {'status': HTTPStatus.NOT_FOUND, 'length': 1, 'api_body': {'detail': 'person not found'}})]
)
@pytest.mark.asyncio
async def test_person_films(make_get_request, query_data, expected_answer):
    query = query_data['query']
    body, headers, status = await make_get_request(f'persons/{query}/film')
    body = body if len(body[0]) > 1 else (body,)  # 404
    assert status[0] == expected_answer['status']
    assert len(body[0]) == expected_answer['length']
    assert body[0][0] == expected_answer['api_body']


@pytest.mark.parametrize(
    'query_data, expected_answer',
    [({'query': 'Star', 'page[number]': 0, 'page[size]': 50},
      {'status': HTTPStatus.OK, 'length': 50, 'api_body': person_id_0}),
     ({'query': 'Star-42', 'page[number]': 0, 'page[size]': 50},
      {'status': HTTPStatus.OK, 'length': 50, 'api_body': person_id_42}),
     ({'query': 'Jane', 'page[number]': 0, 'page[size]': 50},
      {'status': HTTPStatus.NOT_FOUND, 'length': 1, 'api_body': {'detail': 'person not found'}})]
)
@pytest.mark.asyncio
async def test_person_search(make_get_request, query_data, expected_answer):
    body, headers, status = await make_get_request(f'persons/search/', query_data)
    body = body if len(body[0]) > 1 else (body,)  # 404
    assert status[0] == expected_answer['status']
    assert len(body[0]) == expected_answer['length']
    assert body[0][0] == expected_answer['api_body']
