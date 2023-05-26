import logging

import redis

from functional.settings import test_settings
from functional.utils.backoff import backoff

logger = logging.getLogger(__name__)

if __name__ == '__main__':

    @backoff()
    def red(redis=redis):
        redis = redis.from_url(
            test_settings.redis_url, max_connections=20)
        if redis.ping():
            redis.close()
            logging.error('INFO - Redis connected.')
        else:
            raise Exception
    red()
