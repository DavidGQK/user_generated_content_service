films_list = [{
    'id': f'id-{_}',
    'rating': f'{_/10}',
    'genre': [
        {'id': '001', 'name': 'Action'},
        {'id': '002', 'name': 'Sci-Fi'}
    ],
    'title': f'The Star-{_}',
    'description': 'New World',
    # 'director_name': ['Stan'],
    # 'actors_names': ['Ann', 'Bob'],
    # 'writers_names': ['Ben', 'Howard'],
    'actors': [
        {'id': 'id-1', 'name': 'Ann'},
        {'id': 'id-2', 'name': 'Bob'}
    ],
    'writers': [
        {'id': '333', 'name': 'Ben'},
        {'id': '444', 'name': 'Howard'}
    ],
    'director': [
        {'id': '555', 'name': 'Huan'}
    ]
    # 'created_at': datetime.datetime.now().isoformat(),
    # 'updated_at': datetime.datetime.now().isoformat(),
    # 'film_work_type': 'movie'
} for _ in range(60)]
