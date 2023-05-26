import os
import sqlite3
import time
from contextlib import contextmanager

import psycopg2
from psycopg2.extensions import connection as _connection
from psycopg2.extras import DictCursor

from sqlite_to_postgres.loaders import (
    TABLES,
    PostgresSaver,
    SQLiteExtractor,
    logger
)


@contextmanager
def conn_context(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


@contextmanager
def pg_context(_pg, cursor_factory: DictCursor):
    conn: _connection = psycopg2.connect(**_pg, cursor_factory=cursor_factory)
    yield conn
    conn.close()


def load_from_sqlite(sqlite_conn: sqlite3.Connection, pg_conn: _connection):
    """The basic method of loading data from SQLite to Postgres."""
    logger.warning('\nUpload from SQLite to PGSQL:')
    sqlite_extractor = SQLiteExtractor(sqlite_conn)
    postgres_saver = PostgresSaver(pg_conn)
    postgres_saver.truncate_pg()
    db_dict, count = {}, {x: 0 for x in TABLES}
    for table in TABLES:
        db_dict[table] = sqlite_extractor.extract_one_table(table)
        count[table] = postgres_saver.save_data(db_dict)
    for table in count:
        logger.warning(f'Uploaded to table: {table} - %s', count[table])
    logger.warning('Mission complete!')


if __name__ == '__script__':
    import logging
    import os

    import django
    from django.core.wsgi import get_wsgi_application

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')  # !!!
    django.setup()
    application = get_wsgi_application()

    from movies.models import Filmwork, Genre, Person

    if Genre.objects.count() < 20 or Person.objects.count() < 4000 or Filmwork.objects.count() < 900:
        time.sleep(6)
        dsl = {'dbname': os.environ.get('POSTGRES_DB'),
               'user': os.environ.get('POSTGRES_USER'),
               'password': os.environ.get('POSTGRES_PASSWORD'),
               'host': os.environ.get('POSTGRES_HOST'),
               'port': os.environ.get('POSTGRES_PORT')}
        with (conn_context('sqlite_to_postgres/db.sqlite') as sqlite_conn,
              pg_context(dsl, cursor_factory=DictCursor) as pg_conn):
            load_from_sqlite(sqlite_conn, pg_conn)
    else:
        logging.warning('---INFO--- PG  data - ok ')
