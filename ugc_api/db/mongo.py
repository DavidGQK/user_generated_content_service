from motor.motor_asyncio import AsyncIOMotorClient

from core.config import settings

aio_motor: AsyncIOMotorClient | None = None


async def get_aio_motor():
    aio_motor = AsyncIOMotorClient(settings.mongo_url)
    return aio_motor
