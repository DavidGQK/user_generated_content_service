from django.contrib.postgres.aggregates import ArrayAgg
from django.core.paginator import Page
from django.db.models import Q
from django.http import JsonResponse
from django.views.generic.detail import BaseDetailView
from django.views.generic.list import BaseListView

from movies.models import Filmwork, PersonRole

QSET = ('id', 'title', 'description', 'creation_date', 'rating', 'type')


class MoviesApiMixin:
    model = Filmwork
    http_method_names = ['get']

    @classmethod
    def _aggregate_person(cls, role):
        return ArrayAgg('person__full_name', distinct=True,
                        filter=Q(personfilmwork__role=role))

    def get_queryset(cls):
        qset = (Filmwork.objects.prefetch_related('genres', 'persons')
                .order_by('title').values(*QSET))
        qset = qset.annotate(
            genres=ArrayAgg('genres__name', distinct=True),
            actors=cls._aggregate_person(role=PersonRole.ACTOR),
            directors=cls._aggregate_person(role=PersonRole.DIRECTOR),
            writers=cls._aggregate_person(role=PersonRole.WRITER),
        )
        return qset

    def render_to_response(self, context, **response_kwargs):
        return JsonResponse(context)


class MoviesListApi(MoviesApiMixin, BaseListView):
    paginate_by = 50

    def get_context_data(self, *, object_list=None, **kwargs):
        queryset = self.get_queryset()
        paginator, page, queryset, is_paginated = self.paginate_queryset(
            queryset, self.paginate_by)
        page: Page
        prev = page.previous_page_number() if page.has_previous() else None
        next = page.next_page_number() if page.has_next() else None
        context = {'count': paginator.count,
                   'total_pages': paginator.num_pages,
                   'prev': prev,
                   'next': next,
                   'result': list(queryset)}
        return context


class MoviesDetailApi(MoviesApiMixin, BaseDetailView):

    def get_context_data(self, **kwargs):
        return self.object or kwargs['object']
