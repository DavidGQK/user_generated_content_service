CREATE DATABASE shard;

CREATE DATABASE replica;

CREATE TABLE shard.like (user_id String, movie_id String, timestamp DateTime, value UInt64) Engine=ReplicatedMergeTree('/clickhouse/tables/shard1/like', 'replica_1') PARTITION BY toYYYYMMDD(timestamp) ORDER BY movie_id;

CREATE TABLE replica.like (user_id String, movie_id String, timestamp DateTime, value UInt64) Engine=ReplicatedMergeTree('/clickhouse/tables/shard2/like', 'replica_2') PARTITION BY toYYYYMMDD(timestamp) ORDER BY movie_id;

CREATE TABLE shard.views (user_id String, movie_id String, timestamp DateTime, value UInt64) Engine=ReplicatedMergeTree('/clickhouse/tables/shard1/views', 'replica_1') PARTITION BY toYYYYMMDD(timestamp) ORDER BY movie_id;

CREATE TABLE replica.views (user_id String, movie_id String, timestamp DateTime, value UInt64) Engine=ReplicatedMergeTree('/clickhouse/tables/shard2/views', 'replica_2') PARTITION BY toYYYYMMDD(timestamp) ORDER BY movie_id;

CREATE TABLE shard.rating (user_id String, movie_id String, timestamp DateTime, value UInt64) Engine=ReplicatedMergeTree('/clickhouse/tables/shard1/rating', 'replica_1') PARTITION BY toYYYYMMDD(timestamp) ORDER BY movie_id;

CREATE TABLE replica.rating (user_id String, movie_id String, timestamp DateTime, value UInt64) Engine=ReplicatedMergeTree('/clickhouse/tables/shard2/rating', 'replica_2') PARTITION BY toYYYYMMDD(timestamp) ORDER BY movie_id;

CREATE DATABASE movies_db;

CREATE TABLE movies_db.like (user_id String, movie_id String, timestamp DateTime, value UInt64) ENGINE = Distributed('company_cluster', '', like, rand());

CREATE TABLE movies_db.views (user_id String, movie_id String, timestamp DateTime, value UInt64) ENGINE = Distributed('company_cluster', '', views, rand());

CREATE TABLE movies_db.rating (user_id String, movie_id String, timestamp DateTime, value UInt64) ENGINE = Distributed('company_cluster', '', rating, rand());

-- Пока мало понятно какие данные собирать, views понятно, так как он самый емкий по объему,
-- пусть работает в отдельном шарде(node3), а тут остальные, можно еще например факт коммента к видео добавить,
-- но это потом когда будет понимание что, где, куда.

CREATE TABLE IF NOT EXISTS movies_db.kafka_like(topic String, user_id String, movie_id String, value UInt64) ENGINE = Kafka('broker:29092', 'like', 'ugc_etl', 'JSONEachRow');

CREATE TABLE IF NOT EXISTS movies_db.kafka_rating(topic String, user_id String, movie_id String, value UInt64) ENGINE = Kafka('broker:29092', 'rating', 'ugc_etl', 'JSONEachRow');

CREATE MATERIALIZED VIEW IF NOT EXISTS movies_db.like_mv TO movies_db.like AS SELECT user_id, movie_id, _timestamp AS timestamp, value FROM movies_db.kafka_like;

CREATE MATERIALIZED VIEW IF NOT EXISTS movies_db.rating_mv TO movies_db.rating AS SELECT user_id, movie_id, _timestamp AS timestamp, value FROM movies_db.kafka_rating;