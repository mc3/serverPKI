-- upgrade_to_3.sql

SET search_path = dd, public, pg_catalog;
-- requires PostgreSQL 12 if run in an transaction block (see above):
ALTER TYPE cert_encryption_algo ADD VALUE 'rsa_plus_ec';

START TRANSACTION; 

-- requires PostgreSQL 12 if run in an transaction block (see above):
-- ALTER TYPE cert_encryption_algo ADD VALUE 'both';

SET search_path = pki, dd, public, pg_catalog;

ALTER TABLE Certificates
    ADD COLUMN OCSP_must_staple BOOLEAN
                                        DEFAULT false
                                        NOT NULL;


-- SELECT * FROM add_cert('myserver.at.do.main', 'server','LE', 'rsa', false, NULL, NULL, NULL, NULL, NULL, NULL);
-- V3: 2 more attributes in Certificates
DROP FUNCTION IF EXISTS add_cert;
CREATE FUNCTION add_cert(the_name citext, the_subject_type dd.subject_type, the_cert_type dd.cert_type, the_encryption_algo dd.cert_encryption_algo, must_staple BOOLEAN, the_altname citext, the_tlsa_name citext, the_tlsa_port dd.port_number, the_disthost_name citext, the_jail citext, the_place citext) RETURNS text
    LANGUAGE plpgsql
    AS $$
    DECLARE
        the_isAltname       BOOLEAN;
        cert_id             INT4;
        view_row            certs%ROWTYPE;

    BEGIN
        if (the_name IS NULL OR the_name = '' OR the_subject_type IS NULL OR
            the_cert_type IS NULL) THEN
            RAISE EXCEPTION '?the_name, the_subject_type and the_cert_type must not be empty.';
        END IF;
        SELECT isAltname INTO the_isAltname
            FROM Subjects
            WHERE name = the_name;
        IF FOUND THEN
            IF the_isAltname THEN
                RAISE EXCEPTION '?"%" is already in use as AltName', the_name;
            ELSE
                RAISE EXCEPTION '?"%" is already in use.', the_name;
            END IF;
        END IF;
        IF the_altname IS NOT NULL THEN
            SELECT isAltname INTO the_isAltname
                FROM Subjects
                WHERE name = the_altname;
            IF FOUND THEN
                IF the_isAltname THEN
                    RAISE EXCEPTION '?"%" is already in use as AltName', the_altname;
                ELSE
                    RAISE EXCEPTION '?"%" is already in use as Subject name.', the_altname;
                END IF;
            END IF;
        END IF;
        
        INSERT INTO Certificates(type, encryption_algo, OCSP_must_staple)
            VALUES (the_cert_type, the_encryption_algo, must_staple)
            RETURNING id INTO cert_id;
        INSERT INTO Subjects(type, name, isAltName, certificate)
            VALUES (the_subject_type, the_name, FALSE, cert_id);
        IF the_altname IS NOT NULL THEN
            INSERT INTO Subjects(type, name, isAltName, certificate)
                VALUES (the_subject_type, the_altname, TRUE, cert_id);
        END IF;
        
        IF (the_TLSA_name IS NULL AND the_TLSA_port IS NOT NULL) OR
            (the_TLSA_name IS NOT NULL AND the_TLSA_port IS NULL) THEN
                RAISE EXCEPTION '?the_TLSA_name and the_TLSA_port must both be provided or omitted.';
        END IF;
        IF the_TLSA_name IS NOT NULL THEN
            DECLARE service_id INT4;
            BEGIN
                SELECT id INTO service_id
                    FROM Services
                    WHERE name = the_TLSA_name AND port = the_TLSA_port;
                IF NOT FOUND THEN
                    RAISE EXCEPTION '?No such service "%" with port "%".', the_TLSA_name, the_TLSA_port;
                END IF;
                INSERT INTO Certificates_Services(certificate, service)
                    VALUES (cert_id, service_id);
            END;
        END IF;
        
        IF (the_disthost_name IS NULL AND the_jail IS NULL AND
            the_place IS NULL) THEN
            SELECT * INTO view_row
                FROM certs
                WHERE "Cert Name" = the_name;
            RETURN view_row;
        ELSE
            DECLARE
                the_disthost_id  INT4 := NULL;
                the_jail_id     INT4 := NULL;
                the_place_id    INT4 := NULL;
            BEGIN
                IF the_disthost_name IS NOT NULL THEN
                    SELECT id INTO the_disthost_id
                        FROM DistHosts
                        WHERE FQDN = the_disthost_name;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION '?No such disthost "%"', the_disthost_name;
                    END IF;
                ELSE    -- we have no disthost
                    IF (the_jail IS NOT NULL OR the_place IS NOT NULL) THEN
                        RAISE EXCEPTION '?Needing disthost if jail or place supplied';
                    END IF;
                END IF;
                IF the_jail IS NOT NULL THEN
                    SELECT id INTO the_jail_id
                        FROM Jails
                        WHERE name = the_jail;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION '?No such jail "%"', the_jail;
                    END IF;
                END IF;
                IF the_place IS NOT NULL THEN
                    SELECT id INTO the_place_id
                        FROM Places
                        WHERE name = the_place;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION '?No such place "%"', the_place;
                    END IF;
                END IF;
                INSERT INTO Targets(disthost, jail, place, certificate)
                    VALUES(the_disthost_id, the_jail_id, the_place_id, cert_id);
            END;
        END IF;
        SELECT * INTO view_row
            FROM certs
            WHERE "Cert Name" = the_name;
        RETURN view_row;
    END
$$;


UPDATE Revision SET schemaVersion=3 WHERE id=1;

COMMIT;
