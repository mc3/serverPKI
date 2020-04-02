-- upgrade_to_2.sql

START TRANSACTION; 

SET search_path = pki, dd, public, pg_catalog;

ALTER TABLE CertInstances
    ADD COLUMN OCSP_must_staple BOOLEAN
                                        DEFAULT false
                                        NOT NULL;

UPDATE Revision SET schemaVersion=4 WHERE id=1;

COMMIT;
