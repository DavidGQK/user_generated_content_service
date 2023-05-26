import datetime
import logging
import random
import time
import uuid
from pprint import pprint as pp

from data_gen import gen_bookmarks, gen_reviews, gen_views
from pymongo import MongoClient


def get_database() -> MongoClient :
   client = MongoClient('localhost', 27017)
   return client
  


client = get_database() 
db = client.test_database
db = client['test-database']
views = db.views
reviews = db.reviews
bookmarks = db.bookmarks

views.drop()
reviews.drop()
bookmarks.drop()

start_time = time.time()
for i in gen_views(1000):
    views.insert_one(i)
logging.error(time.time() - start_time)  # 1.20

start_time = time.time()
for i in gen_reviews(1000):
    reviews.insert_one(i)
logging.error(time.time() - start_time)  # 1.08

start_time = time.time()
for i in gen_bookmarks(1000):
    bookmarks.insert_one(i)
logging.error(time.time() - start_time)  # 1.04

start_time = time.time()
views.insert_many(gen_views(1000000))
logging.error(time.time() - start_time)  # 20.97

start_time = time.time()
reviews.insert_many(gen_reviews(1000000))
logging.error(time.time() - start_time)  # 23.68

start_time = time.time()
bookmarks.insert_many(gen_bookmarks(1000000))
logging.error(time.time() - start_time)  # 22.12

start_time = time.time()
views.create_index('value')
reviews.create_index('value')
logging.error(time.time() - start_time)

start_time = time.time()
for v in range(1000, 11000, 10):
    q = views.find_one({'value': v})
logging.error(time.time() - start_time)  # 5.10

start_time = time.time()
for v in range(1000, 11000, 10):
    q = reviews.find_one({'value': round(random.random(), 4)})
logging.error(q)
logging.error(time.time() - start_time)  # 5.10
