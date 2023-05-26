import random
import uuid
from typing import Any, Generator

from faker import Faker

fake=Faker()


def gen_views(num: int, as_dict = True) -> (Generator[dict[str, Any], None, None] | Generator[tuple[str, str, int], None, None]):
    if as_dict:
        return ({'user_id': str(uuid.uuid4()),
                 'movie_id': str(uuid.uuid4()),
                 'value': i} for i in range(num))
    else:
        return ((str(uuid.uuid4()),
                 str(uuid.uuid4()),
                 i) for i in range(num))

def gen_reviews(num: int, as_dict = True) -> (Generator[dict[str, Any], None, None] | Generator[tuple[str, str, str, int], None, None]):
    if as_dict:
        return ({'user_id': str(uuid.uuid4()),
                 'movie_id': str(uuid.uuid4()),
                 'text': f'This film is ...{i}',
                 'value': round(random.random(), 4)} for i in range(num))
    else:
        return ((str(uuid.uuid4()),
                 str(uuid.uuid4()),
                 f'This film is ...{i}',
                 i) for i in range(num))

def gen_bookmarks(num: int, as_dict = True) -> (Generator[dict[str, Any], None, None] | Generator[tuple[str, str, int], None, None]):
    if as_dict:
        return ({'user_id': str(uuid.uuid4()),
                 'movie_id': str(uuid.uuid4()),
                 'value': random.randint(0,1)} for _ in range(num))
    else:
        return ((str(uuid.uuid4()),
                 str(uuid.uuid4()),
                 random.randint(0,1)) for _ in range(num))
