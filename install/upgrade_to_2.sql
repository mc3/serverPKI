-- upgrade_to_2.sql

START TRANSACTION; 

SET search_path = dd, public, pg_catalog;

CREATE TYPE cert_encryption_algo AS ENUM (
    'rsa', 'ec');
GRANT USAGE ON TYPE cert_encryption_algo TO public;

SET search_path = pki, dd, public, pg_catalog;

ALTER TABLE Certificates
    ADD COLUMN encryption_algo cert_encryption_algo
                                        DEFAULT 'rsa'
                                        NOT NULL;

ALTER TABLE CertInstances
    ADD COLUMN encryption_algo cert_encryption_algo
                                        DEFAULT 'rsa'
                                        NOT NULL;

UPDATE Revision SET schemaVersion=2 WHERE id=1;

COMMIT;
