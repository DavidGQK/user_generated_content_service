CREATE DATABASE IF NOT EXISTS replica;

CREATE TABLE IF NOT EXISTS replica.views(user_id String, movie_id String, timestamp DateTime, value UInt64) ENGINE = MergeTree() ORDER BY movie_id;
