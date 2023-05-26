import logging
import random
import time
import uuid

from clickhouse_driver import Client
from data_gen import gen_bookmarks, gen_reviews, gen_views

client = Client(host='localhost')
client.execute('CREATE DATABASE IF NOT EXISTS analyze')
client.execute('DROP TABLE IF EXISTS analyze.views')
client.execute('''
    CREATE TABLE IF NOT EXISTS analyze.views (
        user_id String,
        movie_id String,
        value Int64
    ) Engine=MergeTree() ORDER BY user_id
''')
client.execute('DROP TABLE IF EXISTS analyze.reviews')
client.execute('''
    CREATE TABLE IF NOT EXISTS analyze.reviews (
        user_id String,
        movie_id String,
        text String,
        value Float32
    ) Engine=MergeTree() ORDER BY user_id
''')
client.execute('DROP TABLE IF EXISTS analyze.bookmarks')
client.execute('''
    CREATE TABLE IF NOT EXISTS analyze.bookmarks (
        user_id String,
        movie_id String,
        value Int64
    ) Engine=MergeTree() ORDER BY user_id
''')

start_time = time.time()
for i in gen_views(1000):
    client.execute('''
        INSERT INTO analyze.views (user_id, movie_id, value) VALUES (%(user_id)s, %(movie_id)s, %(value)s)''', i)
logging.error(time.time() - start_time)  # 6.49

start_time = time.time()
for i in gen_reviews(1000):
    client.execute('''
        INSERT INTO analyze.reviews (user_id, movie_id, text, value) VALUES (%(user_id)s, %(movie_id)s, %(text)s, %(value)s)''', i)
logging.error(time.time() - start_time)  # 6.86

start_time = time.time()
for i in gen_bookmarks(1000):
    client.execute('''
        INSERT INTO analyze.bookmarks (user_id, movie_id, value) VALUES (%(user_id)s, %(movie_id)s, %(value)s)''', i)
logging.error(time.time() - start_time)  # 6.64

start_time = time.time()
client.execute('''INSERT INTO analyze.views (user_id, movie_id, value) VALUES''', gen_views(1000000))
logging.error(time.time() - start_time)  # 8.43

start_time = time.time()
client.execute('''INSERT INTO analyze.reviews (user_id, movie_id, text, value) VALUES''', gen_reviews(1000000))
logging.error(time.time() - start_time)  # 9.86

start_time = time.time()
client.execute('''INSERT INTO analyze.bookmarks (user_id, movie_id, value) VALUES''', gen_bookmarks(1000000))
logging.error(time.time() - start_time)  # 8.52

start_time = time.time()
for v in range(1000, 11000, 10):
    client.execute(f'SELECT movie_id, user_id, value FROM analyze.views WHERE value={v}')
logging.error((time.time() - start_time))  # avg time 0.0085

start_time = time.time()
for v in range(1000, 11000, 10):
    r = client.execute(f'SELECT movie_id, user_id, text, value FROM analyze.reviews WHERE value={round(random.random(), 4)}')
logging.error((time.time() - start_time))
