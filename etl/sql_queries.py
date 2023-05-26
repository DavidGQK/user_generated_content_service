FW_SQL = """SELECT
   fw.id,
   fw.title,
   fw.description,
   fw.rating,
   fw.type,
   fw.created,
   fw.modified,
   COALESCE (
       json_agg(
           DISTINCT jsonb_build_object(
               'role', pfw.role,
               'id', p.id,
               'name', p.full_name
           )
       ) FILTER (WHERE p.id is not null),
       '[]'
   ) as persons,
   COALESCE (
       json_agg(
           DISTINCT jsonb_build_object(
               'id', g.id,
               'name', g.name
           )
       ) FILTER (WHERE g.id is not null),
       '[]'
   ) as genre
FROM content.film_work fw
LEFT JOIN content.genre_film_work gfw ON fw.id = gfw.film_work_id
LEFT JOIN content.genre g ON gfw.genre_id = g.id
LEFT JOIN content.person_film_work pfw ON fw.id = pfw.film_work_id
LEFT JOIN content.person p ON pfw.person_id = p.id
WHERE GREATEST (fw.modified, p.modified, g.modified) > '%s'
GROUP BY fw.id
"""
GN_SQL = """
        SELECT gn.id, gn.name, gn.description
        FROM content.genre gn
        WHERE gn.modified > '%s'
        """
PN_SQL = """
SELECT
    p.id,
    p.full_name,
    p.modified,
COALESCE (
    json_agg(
        DISTINCT jsonb_build_object(
            'id', fw.id,
            'title', fw.title,
            'rating', fw.rating,
            'type', fw.type
        )
    ) FILTER (WHERE fw.id is not null),
    '[]'
) as films,
array_agg(DISTINCT pfw.role) as roles
FROM content.person p
LEFT JOIN content.person_film_work pfw ON pfw.person_id = p.id
LEFT JOIN content.film_work fw ON fw.id = pfw.film_work_id
WHERE p.modified > '%s'
GROUP BY p.id"""
