
from typing import Optional

from aiokafka import AIOKafkaConsumer

aio_consumer: Optional[AIOKafkaConsumer] = None


async def get_consumer():
    return aio_consumer
