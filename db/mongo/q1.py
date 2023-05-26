import datetime
from pprint import pprint as pp

from pymongo import MongoClient


def get_database() -> MongoClient :
   client = MongoClient('localhost', 27017)
   return client
  

if __name__ == "__main__":
    client = get_database() 
    db = client.test_database
    db = client['test-database']
    collection = db.test_collection
    collection = db['test-collection']
    # post = {"author": "Mike2",
    #         "text": "My first blog post!",
    #         "tags": ["mongodb", "python", "pymongo"],
    #         "date": datetime.datetime.utcnow()}
    posts = db.posts
    # post_id = posts.insert_one(post).inserted_id
    # pp(post_id)
    pp(db.list_collection_names())
    pp(posts.find_one({"author": "Mike2"}))
