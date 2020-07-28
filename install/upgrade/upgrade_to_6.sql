-- upgrade_to_6.sql

START TRANSACTION; 

SET search_path = pki, dd, public, pg_catalog;


ALTER TABLE CertKeyData
    ADD UNIQUE (certinstance, encryption_algo);
    
UPDATE Revision SET schemaVersion=6 WHERE id=1;

COMMIT;
