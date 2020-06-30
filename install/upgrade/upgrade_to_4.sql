-- upgrade_to_4.sql

START TRANSACTION; 

SET search_path = pki, dd, public, pg_catalog;

ALTER TABLE CertInstances
    ADD COLUMN OCSP_must_staple BOOLEAN
                                        DEFAULT false
                                        NOT NULL;

ALTER TABLE CertInstances
    ADD UNIQUE (hash);
    
UPDATE Revision SET schemaVersion=4 WHERE id=1;

COMMIT;
