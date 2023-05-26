import datetime as dt
import time
from contextlib import contextmanager

import psycopg2
from elasticsearch import Elasticsearch
from psycopg2.extensions import connection as _connection
from psycopg2.extras import DictCursor

from create_idx import FW_IDX, GN_IDX, PN_IDX
from e_t_l import DataTransform, ElasticsearchLoader, PgExtaractor
from pydantic_valiadate import ElS, PgS, logger
from sql_queries import FW_SQL, GN_SQL, PN_SQL
from state_storage import JsonFileStorage, State

es = Elasticsearch(hosts=f'http://{ElS().host}:{ElS().port}',
                   basic_auth=(ElS().user, ElS().password))
TABLES = {'film_work': FW_SQL, 'persons': PN_SQL, 'genres': GN_SQL}
IDX = {'movies': FW_IDX, 'persons': PN_IDX, 'genres': GN_IDX}
logger.name = __name__


@contextmanager
def pg_context(_pg, cursor_factory: DictCursor) -> None:
    conn: _connection = psycopg2.connect(**_pg, cursor_factory=cursor_factory)
    yield conn
    conn.close()


def main(pg_con: DictCursor, es_con: Elasticsearch) -> None:
    start_time = dt.datetime.utcnow()
    pg_extractor = PgExtaractor(pg_con)
    es_loader = ElasticsearchLoader(es_con)
    date_transform = DataTransform()
    for index, body_idx in IDX.items():
        if not es.indices.exists(index=index):
            es.indices.create(index=index, body=body_idx)
    for table, query in TABLES.items():
        es_status, cnt = [], 0
        pg_extract_gen = pg_extractor.extract(table, query)
        for pg_extract in pg_extract_gen:
            transform = date_transform.transform(pg_extract, table)
            es_status.append(es_loader.load(transform, table))
            cnt += len(transform)
        if False not in es_status and True in es_status:
            state = State(JsonFileStorage('state.json'))
            state.set_state(table, start_time.isoformat())
            logger.error('Added %s _docs in idx %s', cnt, table)
        elif False in es_status:
            logger.error('The attempt is not successful. Error in %s', table)
    logger.error('ETL online. Waiting for 30 seconds.')


if __name__ == '__main__':
    time.sleep(35)
    while True:
        dsl = PgS().dict()
        with (pg_context(dsl, cursor_factory=DictCursor) as pg_conn):
            main(pg_conn, es)
            time.sleep(60)
