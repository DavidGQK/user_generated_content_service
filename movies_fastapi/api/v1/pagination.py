from fastapi import Query


class PaginatedParams():
    def __init__(self,
                 size: int = Query(default=50, ge=10, le=100, alias='page[size]'),
                 page: int = Query(default=0, ge=0, le=100, alias='page[number]')):
        self.size = size
        self.page = page
