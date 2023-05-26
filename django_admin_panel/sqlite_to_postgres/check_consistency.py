import logging
import os
import sqlite3

import psycopg2
from dotenv import load_dotenv
from psycopg2.extensions import connection as _connection
from psycopg2.extras import DictCursor

from sqlite_to_postgres.load_data import TABLES, conn_context

load_dotenv('movies_admin/config/.env')

SKIP_FIELDS = ['modified', 'created']

logging.basicConfig(format='%(asctime)s[%(name)s]: %(message)s', level='INFO')
logger = logging.getLogger(__name__)


def assert_pg_vs_sqlite(pg_data: dict[list], sqlite_data: dict[list]):
    """The method of direct comparison of tables."""
    count, err = {x: 0 for x in pg_data}, 0
    for table in TABLES:
        for obj in range(len(pg_data[table])):
            try:
                for col in (pg_data[table][obj]):
                    if col in SKIP_FIELDS:
                        continue
                    assert (pg_data[table][obj][col]
                            == sqlite_data[table][obj][col])
                count[table] += 1
            except AssertionError as e:
                logger.error(
                    'Error table %s != table %s. Detail %s',
                    pg_data[table], sqlite_data[table], e.args)
                err += 1
    return count, err


def sqlite_loader(sqlite_conn: sqlite3.Connection):
    """The method of loading data from SQLite."""
    cursor = sqlite_conn.cursor()
    sqlite_dict = {}
    for table_name in TABLES:
        cursor.execute(f"SELECT * FROM {table_name} ORDER BY id;")
        data = cursor.fetchall()
        sqlite_dict[table_name] = [(dict(i)) for i in data]
    return sqlite_dict


def postgres_loader(pg_conn: _connection):
    """Method of loading data from PG."""
    cursor = pg_conn.cursor()
    pg_dict = {}
    for table_name in TABLES:
        cursor.execute(f"SELECT * FROM content.{table_name} ORDER BY id;")
        data = cursor.fetchall()
        pg_dict[table_name] = [(dict(i)) for i in data]
    return pg_dict


def test():
    """The basic method of testing."""
    sqlite_data = sqlite_loader(sqlite_conn)
    postgres_data = postgres_loader(pg_conn)
    data, err = assert_pg_vs_sqlite(postgres_data, sqlite_data)
    for table in data:
        logger.info(f'Checked in the table: {table}- %s objects', data[table])
    logger.info(f'Errors: {err}')


if __name__ == '__main__':
    dsl = {'dbname': os.environ.get('DB_NAME'),
           'user': os.environ.get('DB_USER'),
           'password': os.environ.get('DB_PASSWORD'),
           'host': os.environ.get('DB_HOST', '127.0.0.1'),
           'port': os.environ.get('DB_PORT')}
    with (conn_context('sqlite_to_postgres/db.sqlite') as sqlite_conn,
          psycopg2.connect(**dsl, cursor_factory=DictCursor) as pg_conn):
        test()
