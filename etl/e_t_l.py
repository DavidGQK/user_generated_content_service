from typing import Generator

from elasticsearch import Elasticsearch, helpers
from psycopg2.extensions import connection as _connection

from backoff import backoff
from pydantic_valiadate import logger
from state_storage import JsonFileStorage, State

BATCH_SIZE = 100
logger.name = __name__


class PgExtaractor(object):
    def __init__(self, pg_conn: _connection):
        self.connection = pg_conn

    @backoff()
    def extract(self, table: str, query: str) -> Generator[list, None, None]:
        state = State(JsonFileStorage('state.json'))
        _state = state.get_state(table)
        cur = self.connection.cursor()
        cur.execute(query % _state)
        while True:
            try:
                if len(data := [dict(i) for i in
                                cur.fetchmany(BATCH_SIZE)]) < 1:
                    break
            except Exception as e:
                logger.exception('EXTRACT %s', e.args)
            yield data


class DataTransform(object):
    def transform(self, data: list, table: str) -> list[dict, None]:
        count, res = 0, []
        if table == 'film_work':
            for film in data:
                actors, writers, dirs = [], [], []
                for person in film['persons']:
                    if person['role'] == 'actor':
                        del (person['role'])
                        actors.append(person)
                    elif person['role'] == 'writer':
                        del (person['role'])
                        writers.append(person)
                    elif person['role'] == 'director':
                        del (person['role'])
                        dirs.append(person)
                    count += 1
                film['actors'] = actors
                film['writers'] = writers
                film['director'] = dirs
                film['actors_names'] = (
                    [actor['name'] for actor in actors])
                film['writers_names'] = (
                    [writer['name'] for writer in writers])
                film['director_name'] = [dir['name'] for dir in dirs]
                del film['persons'], film['modified'], film['created'], film['type']
                res.append(film)
        elif table == 'persons':
            res = data
        elif table == 'genres':
            res = data
        return res


class ElasticsearchLoader(object):

    def __init__(self, el_conn: Elasticsearch):
        self.es = el_conn

    @backoff()
    def load(self, data: list[dict], table: str) -> bool:
        """The method saves the data in ES."""
        if table == 'film_work':
            index = 'movies'
        else:
            index = table
        query = [{'_index': index, '_id': obj['id'],
                  '_source': obj} for obj in data]
        stats = helpers.bulk(self.es, query, stats_only=True)
        return stats[1] == 0
