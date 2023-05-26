import logging
from collections.abc import Callable
from functools import wraps
from time import sleep

logging.basicConfig(format='%(asctime)s[%(name)s]: %(message)s',
                    level='ERROR')
logger = logging.getLogger(__name__)
logger.name = 'backoff'


def backoff(start_sleep_time: float = 0.1,
            factor: int = 2,
            border_sleep_time: int = 10) -> Callable:
    """
    A function to execute the function again after a period of time,
    if an error has occurred.
    """
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
