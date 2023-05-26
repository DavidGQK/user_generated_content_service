from abc import ABC, abstractmethod


class AsyncCacheStorage(ABC):
    @abstractmethod
    async def get(self, key: str, **kwargs):
        pass

    @abstractmethod
    async def set(self, key: str, value: str, expire: int, **kwargs):
        pass


class AsyncDataStorage(ABC):
    @abstractmethod
    async def get(self, id: str, **kwargs):
        pass

    @abstractmethod
    async def search(self, index: str, body: str, params: dict, **kwargs):
        pass
