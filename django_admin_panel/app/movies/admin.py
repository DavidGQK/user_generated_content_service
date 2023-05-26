from django.contrib import admin

from movies.models import (
    Filmwork,
    Genre,
    GenreFilmwork,
    Person,
    PersonFilmwork
)


@admin.register(Genre)
class GenreAdmin(admin.ModelAdmin):
    list_display = ('name', 'description',)
    search_fields = ('name', 'id')
    empty_value_display = '-empty-'


class GenreFilmworkInline(admin.TabularInline):
    model = GenreFilmwork
    extra = 1


@admin.register(Person)
class PersonAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'id',)
    search_fields = ('full_name', 'id',)
    empty_value_display = '-empty-'


class PersonFilmworkInline(admin.TabularInline):
    model = PersonFilmwork
    extra = 1


@admin.register(Filmwork)
class FilmworkAdmin(admin.ModelAdmin):
    inlines = (GenreFilmworkInline, PersonFilmworkInline)
    list_display = ('title',
                    'type',
                    'creation_date',
                    'rating',
                    'created',
                    'modified')
    list_filter = ('type', 'id',)
    search_fields = ('title', 'description')
    empty_value_display = '-empty-'
