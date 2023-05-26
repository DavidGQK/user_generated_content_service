import logging
import sqlite3
from dataclasses import asdict, astuple

from psycopg2 import errors
from psycopg2.extensions import connection as _connection

from sqlite_to_postgres.dataclass_sql import (
    FilmWork,
    Genre,
    GenreFilmWork,
    Person,
    PersonFilmWork
)

logging.basicConfig(format='%(asctime)s[%(name)s]: %(message)s', level='DEBUG')
logger = logging.getLogger(__name__)

TABLES = {
    'film_work': FilmWork,
    'person': Person,
    'genre': Genre,
    'genre_film_work': GenreFilmWork,
    'person_film_work': PersonFilmWork
}
BATCH_SIZE = 900


class SQLiteExtractor(object):
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.curs = connection.cursor()

    def extract_one_table(self, table):
        """The method generates a separate table from SQLite."""
        self.curs.execute(f"SELECT * FROM {table};")
        while True:
            data_list = []
            try:
                if len(data := [dict(i) for i in
                                self.curs.fetchmany(BATCH_SIZE)]) < 1:
                    break
            except Exception as e:
                logger.error(
                    'Error in table %s. Detail %s', table, e.args)
            for i in data:
                data_list.append(TABLES[table](*[x for x in i.values()]))
            logger.debug((len(data_list), table))
            yield data_list


class PostgresSaver(object):
    def __init__(self, pg_conn: _connection):
        self.connection = pg_conn

    def truncate_pg(self):
        """The method clears the PG Base"""
        cur = self.connection.cursor()
        for table in TABLES:
            cur.execute(f"TRUNCATE content.{table} CASCADE;")

    def save_data(self, data: dict):
        """Method of saving from Dataclass Dictionary in PG SQL."""
        count = 0
        cur = self.connection.cursor()
        for table_name, gen_obj in data.items():
            for list_obj in gen_obj:
                cols = asdict(list_obj[0])
                cols_str = ','.join(cols.keys())
                for obj in list_obj:
                    vals = astuple(obj)
                    vals_str = ','.join(['%s' for _ in range(len(vals))])
                    sql_str = (f"""INSERT INTO content.{table_name}
                            ({cols_str}) VALUES ({vals_str})
                            ON CONFLICT (id) DO NOTHING""")
                    try:
                        cur.execute(sql_str, vals)
                        count += 1
                    except (errors.UniqueViolation,
                            errors.InFailedSqlTransaction) as e:
                        logger.error(
                            'Error in table %s. Detail %s', table_name,
                            e.pgerror)
                    except Exception as e:
                        logger.error(
                            'Error in table %s. Detail %s', table_name, e.args)
        self.connection.commit()
        cur.close()
        return count
