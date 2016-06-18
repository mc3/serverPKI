----------------------------- serverPKI data dictionary schema
SET log_min_messages='error';

-- 'Attention!! drops referencing schema pki  Attention!!'
--DROP SCHEMA IF EXISTS dd CASCADE;

CREATE SCHEMA dd;            -- 'data dictionary for project serverPKI

CREATE DOMAIN created
    AS TIMESTAMP
    DEFAULT TIMESTAMP 'NOW'
    NOT NULL;

CREATE DOMAIN updated
    AS TIMESTAMP
    DEFAULT TIMESTAMP 'NOW'
    NOT NULL;

CREATE TYPE subject_type AS ENUM ('client', 'server');

GRANT USAGE ON SCHEMA dd TO pki_dev;
