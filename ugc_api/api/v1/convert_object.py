from datetime import datetime

from bson.objectid import ObjectId as BsonObjectId


class ObjectIdAsStr(BsonObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, (BsonObjectId, str)):
            raise TypeError('ObjectId required')
        return str(v)


class DatatimeAsStr(datetime):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, datetime):
            return v
        return datetime.isoformat(v)
