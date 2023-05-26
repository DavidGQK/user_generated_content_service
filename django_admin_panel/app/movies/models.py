import uuid

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


class TimeStampedMixin(models.Model):
    created = models.DateTimeField(_('created'), auto_now_add=True)
    modified = models.DateTimeField(_('modified'), auto_now=True)

    class Meta:
        abstract = True


class UUIDMixin(models.Model):
    id = models.UUIDField(primary_key=True,
                          default=uuid.uuid4,
                          editable=False)

    class Meta:
        abstract = True


class Genre(TimeStampedMixin, UUIDMixin):
    name = models.CharField(_('name'), max_length=255)
    description = models.TextField(_('description'), blank=True)

    class Meta:
        db_table = "content\".\"genre"
        verbose_name = _('Genre')
        verbose_name_plural = _('Genres')

    def __str__(self):
        return self.name


class Person(TimeStampedMixin, UUIDMixin):
    full_name = models.CharField(_('full name'), max_length=255)

    class Meta:
        db_table = "content\".\"person"
        verbose_name = _('Person')
        verbose_name_plural = _('Persons')

    def __str__(self):
        return self.full_name


class Filmwork(TimeStampedMixin, UUIDMixin):
    Type_choices = models.TextChoices('Type_choices', 'movie tv_show')

    title = models.CharField(_('title'), max_length=255)
    description = models.TextField(_('description'), blank=True)
    creation_date = models.DateField(_('creation_date'), blank=True)
    file_path = models.TextField('file_path', blank=True, null=True)
    type = models.CharField(_('type'), choices=Type_choices.choices,
                            max_length=32)
    rating = models.FloatField(_('rating'), blank=True,
                               validators=[MinValueValidator(0),
                                           MaxValueValidator(100)])
    genres = models.ManyToManyField(Genre,
                                    through='GenreFilmwork',
                                    verbose_name=_('genre'))
    person = models.ManyToManyField(Person,
                                    through='PersonFilmwork',
                                    verbose_name=_('person'))

    class Meta:
        db_table = "content\".\"film_work"
        verbose_name = _('Film')
        verbose_name_plural = _('Films')

    def __str__(self):
        return self.title


class GenreFilmwork(UUIDMixin):
    film_work = models.ForeignKey('Filmwork',
                                  on_delete=models.CASCADE,
                                  verbose_name=_('filmwork'))
    genre = models.ForeignKey('Genre',
                              on_delete=models.CASCADE,
                              verbose_name=_('genre'))
    created = models.DateTimeField(_('created'), auto_now_add=True)

    class Meta:
        db_table = "content\".\"genre_film_work"
        constraints = [
            models.UniqueConstraint(fields=['genre', 'film_work'],
                                    name='unique_genre_filmwork'),
        ]


class PersonRole(models.TextChoices):
    ACTOR = 'actor', _('Actor')
    WRITER = 'writer', _('Writer')
    DIRECTOR = 'director', _('Director')


class PersonFilmwork(UUIDMixin):
    film_work = models.ForeignKey('Filmwork',
                                  on_delete=models.CASCADE,
                                  verbose_name=_('filmwork'))
    person = models.ForeignKey('Person',
                               on_delete=models.CASCADE,
                               verbose_name=_('person'))
    role = models.TextField(_('role'), choices=PersonRole.choices, null=True)
    created = models.DateTimeField(_('created'), auto_now_add=True)

    class Meta:
        db_table = "content\".\"person_film_work"
        constraints = [
            models.UniqueConstraint(fields=['role', 'person', 'film_work'],
                                    name='unique_role_person_filmwork'),
        ]
