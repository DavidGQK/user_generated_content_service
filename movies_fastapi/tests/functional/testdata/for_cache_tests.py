cache_film_id = {'id': 'id-0', 'rating': '0.0', 'genre':
                 [{'id': '001', 'name': 'Action'}, {'id': '002', 'name': 'Sci-Fi'}],
                 'title': 'The Star-0', 'description': 'New World',
                 'actors': [{'id': 'id-1', 'name': 'Ann'}, {'id': 'id-2', 'name': 'Bob'}],
                 'writers': [{'id': '333', 'name': 'Ben'}, {'id': '444', 'name': 'Howard'}],
                 'director': [{'id': '555', 'name': 'Huan'}]}
cache_genre_id = {'id': 'id-0', 'name': 'The Star-0', 'description': 'aaa11'}
cache_person_id = {'id': 'id-0', 'full_name': 'The Star-0', 'roles': ['aaa11'],
                   'modified': '2022-12-16T13:38:23.246312',
                   'films': [{'id': 'id-0', 'rating': 2.3, 'type': 'cccc', 'title': 'dddd'}]}
cache_film_list = [{'_index': 'movies', '_id': f'id-{_}',
                    '_source': {'id': f'id-{_}', 'rating': f'{_/10}',
                                'genre': [{'id': '001', 'name': 'Action'},
                                          {'id': '002', 'name': 'Sci-Fi'}],
                                'title': f'The Star-{_}', 'description': 'New World',
                                'actors': [{'id': 'id-1', 'name': 'Ann'},
                                           {'id': 'id-2', 'name': 'Bob'}],
                                'writers': [{'id': '333', 'name': 'Ben'},
                                            {'id': '444', 'name': 'Howard'}],
                                'director': [{'id': '555', 'name': 'Huan'}]}} for _ in range(50)]
cache_genre_list = [{'_index': 'genres', '_id': f'id-{_}',
                     '_source': {'id': f'id-{_}', 'name': f'The Star-{_}', 'description': 'aaa11'}} for _ in range(50)]
cache_person_list = [{'_index': 'persons', '_id': f'id-{_}',
                      '_source': {'id': f'id-{_}', 'full_name': f'The Star-{_}',
                                  'roles': ['aaa11'], 'modified': '2022-12-16T13:38:23.246312',
                                  'films': [{'id': f'id-{_}', 'rating': 2.3, 'type': 'cccc', 'title': 'dddd'}]}} for _ in range(50)]
