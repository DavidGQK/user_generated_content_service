import orjson
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from fastapi import APIRouter, Depends

from api.v1.models import ItemKafka, RequestKafka, ResponseKafka
from db.kafka_consumer import get_consumer
from db.kafka_producer import get_producer

router = APIRouter()
RESP404 = {"description": "Item not found"}


@router.get('/', responses={404: RESP404})
async def get_kafka(consumer: AIOKafkaConsumer = Depends(get_consumer)) -> list:
    """GET test pen"""
    result = []
    msg_set = await consumer.getmany(timeout_ms=20, max_records=1000)
    for tp, msgs in msg_set.items():
        for msg in msgs:
            keys = msg.key.decode("utf-8").split('+')
            value = orjson.loads(msg.value)
            result.append(ItemKafka(topic=tp.topic,
                                    user_id=keys[0],
                                    movie_id=keys[1],
                                    value=value['value'],
                                    time_stamp=msg.timestamp))
    return result


@router.post('/views/', responses={404: RESP404})
async def post_kafka_viwes(data: RequestKafka, producer: AIOKafkaProducer = Depends(get_producer)) -> None:
    """Posting in kafka and sort of asynchronously.
    https://kafka-python.readthedocs.io/en/master/apidoc/KafkaProducer.html#:~:text=send()%20is%20asynchronous
    value:
    views - where the movie was stopped.
    rating - film rating
    like - 1 - like / 0 - dislike
    """
    key = f'{data.user_id}+{data.movie_id}'
    await producer.send('views', data.json().encode(), key.encode())
