CREATE DATABASE shard;

CREATE DATABASE replica;

CREATE TABLE shard.views (user_id String, movie_id String, timestamp DateTime, value UInt64) Engine=ReplicatedMergeTree('/clickhouse/tables/shard1/views', 'replica_1') PARTITION BY toYYYYMMDD(timestamp) ORDER BY movie_id;

CREATE TABLE replica.views (user_id String, movie_id String, timestamp DateTime, value UInt64) Engine=ReplicatedMergeTree('/clickhouse/tables/shard2/views', 'replica_2') PARTITION BY toYYYYMMDD(timestamp) ORDER BY movie_id;

CREATE DATABASE movies_db;

CREATE TABLE movies_db.views (user_id String, movie_id String, timestamp DateTime, value UInt64) ENGINE = Distributed('company_cluster', '', views, rand());
