----------------------------- serverPKI data dictionary schema
SET log_min_messages='error';

-- 'Attention!! drops referencing schema pki  Attention!!'
DROP SCHEMA IF EXISTS dd CASCADE;


CREATE SCHEMA dd;            -- 'data dictionary for project serverPKI
SET search_path = dd;
CREATE EXTENSION citext SCHEMA dd;


------------------------------ 'created' timestamp
CREATE DOMAIN created
    AS TIMESTAMP
    DEFAULT TIMESTAMP 'NOW'
    NULL;
GRANT USAGE ON DOMAIN created TO public;

------------------------------ 'updated' timestamp
CREATE DOMAIN updated
    AS TIMESTAMP
    DEFAULT TIMESTAMP 'NOW'
    NULL;
GRANT USAGE ON DOMAIN updated TO public;

------------------------------ TCP/UDP port number number
CREATE DOMAIN port_number
    AS int4
    CONSTRAINT port_number CHECK (VALUE >= 0 AND VALUE <= 65536);
GRANT USAGE ON DOMAIN port_number TO public;

------------------------------ type of Subject
CREATE TYPE subject_type AS ENUM ('CA', 'client', 'server');
GRANT USAGE ON TYPE subject_type TO public;

------------------------------ type of Place
CREATE TYPE place_cert_file_type AS ENUM (
    'cert only', 'separate', 'combine key', 'combine cacert', 'combine both');
GRANT USAGE ON TYPE place_cert_file_type TO public;

------------------------------ type of Certificate
CREATE TYPE cert_type AS ENUM (
    'LE', 'local');
GRANT USAGE ON TYPE cert_type TO public;

------------------------------ state of cert instance
CREATE TYPE cert_state AS ENUM (
    'reserved', 'issued', 'prepublished', 'deployed', 'revoked', 'expired', 'archived');
GRANT USAGE ON TYPE cert_state TO public;


GRANT USAGE ON SCHEMA dd TO public;
