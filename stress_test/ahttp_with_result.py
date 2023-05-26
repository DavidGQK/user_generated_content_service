import asyncio
import logging
import time
from collections import defaultdict

import aiohttp
import orjson

from config import settings


async def ahttp_test(i: int):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=35, loop=asyncio.get_event_loop())) as client:
        headers = {'CONTENT-TYPE': 'application/json'}
        _json = orjson.dumps({"topic": "rating", "user_id": "500271", "movie_id": "tt0120338", "value": i})
        return await client.post(settings.API_KAFKA_POST, data=_json, headers=headers)


async def main():
    start_time = time.time()
    tasks = [asyncio.ensure_future(
             ahttp_test(i)) for i in range(settings.API_REQUESTS_COUNT)]
    done, _ = await asyncio.wait(tasks)
    result = defaultdict(int)
    for future in done:
        result[future.result().status] += 1
    logging.error('INFO - All ok: time - %s seconds, ok - %s, error - %s', (time.time() - start_time), result[200], settings.API_REQUESTS_COUNT - result[200])

loop = asyncio.new_event_loop()
loop.run_until_complete(main())
loop.close()
