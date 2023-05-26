from collections.abc import Callable
from functools import wraps
from time import sleep

from pydantic_valiadate import logger

logger.name = 'backoff'


def backoff(start_sleep_time: float = 0.1,
            factor: int = 2,
            border_sleep_time: int = 10) -> Callable:

    def func_wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            sleep_time = start_sleep_time
            while True:
                try:
                    sleep(sleep_time)
                    result = func(*args, *kwargs)
                    break
                except Exception as e:
                    logger.exception('BACKOFF %s', e.args)
                    sleep_time = sleep_time * factor
                    if sleep_time > border_sleep_time:
                        sleep_time = border_sleep_time
            return result
        return inner
    return func_wrapper
