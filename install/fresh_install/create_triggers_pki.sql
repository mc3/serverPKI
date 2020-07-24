SET SEARCH_PATH TO pki,dd;
START TRANSACTION;

                        -- TRIGGERS --------------------------------------------

--------------- triggers for update column of several tables

------------------------------- ' trigger function for "updated"
CREATE OR REPLACE FUNCTION u()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
GRANT EXECUTE ON FUNCTION u TO public;

CREATE TRIGGER ut_Revision BEFORE UPDATE ON Revision FOR EACH ROW EXECUTE FUNCTION u();
CREATE TRIGGER ut_Certificates BEFORE UPDATE ON Certificates FOR EACH ROW EXECUTE FUNCTION u();
CREATE TRIGGER ut_CertInstances BEFORE UPDATE ON CertInstances FOR EACH ROW EXECUTE FUNCTION u();
CREATE TRIGGER ut_Subjects BEFORE UPDATE ON Subjects FOR EACH ROW EXECUTE FUNCTION u();
CREATE TRIGGER ut_Services BEFORE UPDATE ON Services FOR EACH ROW EXECUTE FUNCTION u();
CREATE TRIGGER ut_DistHosts BEFORE UPDATE ON DistHosts FOR EACH ROW EXECUTE FUNCTION u();
CREATE TRIGGER ut_Jails BEFORE UPDATE ON Jails FOR EACH ROW EXECUTE FUNCTION u();
CREATE TRIGGER ut_Places BEFORE UPDATE ON Jails FOR EACH ROW EXECUTE FUNCTION u();
CREATE TRIGGER ut_Targets BEFORE UPDATE ON Targets FOR EACH ROW EXECUTE FUNCTION u();


--------------- triggers for table constraints beyond pure SQL declarations


CREATE OR REPLACE FUNCTION Forbit_deleting_none_altname_subject() RETURNS TRIGGER AS $$
    BEGIN
        IF OLD.isAltname THEN
            -- never allow subject to be deleted which is none altname
            -- (delete certificate instead)
            RETURN OLD;
        ELSE
            IF ( SELECT COUNT(*)
                    FROM Certificates c
                    WHERE c.id = OLD.certificate) > 0 THEN
                RAISE EXCEPTION '?Subject "%" in use by a certificate. Delete certificate first:', OLD.name;  
            ELSE
                RETURN OLD;
            END IF;
        END IF;
    END;
$$ LANGUAGE 'plpgsql';

DROP TRIGGER IF EXISTS Forbit_deleting_none_altname_subject ON Subjects;
CREATE TRIGGER Forbit_deleting_none_altname_subject BEFORE DELETE
    ON Subjects FOR EACH ROW 
    EXECUTE PROCEDURE Forbit_deleting_none_altname_subject();
    

CREATE OR REPLACE FUNCTION Allow_one_none_altname_subject_per_cert() RETURNS TRIGGER AS $$
    BEGIN
        IF NEW.isAltname THEN
            RETURN NEW;
        END IF;
        IF ( SELECT COUNT(*)
                FROM Subjects S
                WHERE S.certificate = NEW.certificate AND NOT S.isAltname ) > 0 THEN
            RAISE EXCEPTION '?Only one none-alternate-name-Subject per Certifiate allowed:';  
        ELSE
            RETURN NEW;
        END IF;
    END;
$$ LANGUAGE 'plpgsql';

DROP TRIGGER IF EXISTS Allow_one_none_altname_subject_per_cert ON Subjects;
CREATE TRIGGER Allow_one_none_altname_subject_per_cert BEFORE INSERT
    ON Subjects FOR EACH ROW 
    EXECUTE PROCEDURE Allow_one_none_altname_subject_per_cert();
    

CREATE OR REPLACE FUNCTION Ensure_exactly_one_none_altname_subject_per_cert() RETURNS TRIGGER AS $$
    BEGIN
        -- update case. Do not allow changing certificate or isAltname
        IF ( NEW.certificate != OLD.certificate OR
                 NEW.isAltname != OLD.isAltname ) THEN
            RAISE EXCEPTION '?Cant change relationship to certificate or alname attribute of subject';  
        ELSE
            RETURN NEW;
        END IF;
    END;
$$ LANGUAGE 'plpgsql';

DROP TRIGGER IF EXISTS Ensure_exactly_one_none_altname_subject_per_cert ON Subjects;
CREATE TRIGGER Ensure_exactly_one_none_altname_subject_per_cert AFTER UPDATE
    ON Subjects FOR EACH ROW 
    EXECUTE PROCEDURE Ensure_exactly_one_none_altname_subject_per_cert();


CREATE OR REPLACE FUNCTION Ensure_jail_on_disthost_with_jailroot() RETURNS TRIGGER AS $$
    BEGIN
        IF ( SELECT COUNT(*)
                FROM DistHosts D
                WHERE D.id = NEW.disthost AND D.jailroot IS NOT NULL ) = 0
        THEN
            RAISE EXCEPTION '?Disthost needs jailroot';  
        ELSE
            RETURN NEW;
        END IF;
    END;
$$ LANGUAGE 'plpgsql';

DROP TRIGGER IF EXISTS Ensure_jail_on_disthost_with_jailroot ON Jails;
CREATE TRIGGER Ensure_jail_on_disthost_with_jailroot BEFORE INSERT OR UPDATE
    ON Jails FOR EACH ROW
    EXECUTE PROCEDURE Ensure_jail_on_disthost_with_jailroot();


CREATE OR REPLACE FUNCTION Ensure_jailroot_if_jails_exist() RETURNS TRIGGER AS $$
    BEGIN
        IF NEW.jailroot IS NOT NULL THEN
            RETURN NEW;
        END IF;
        IF ( SELECT COUNT(*)
                FROM Jails J
                WHERE j.disthost = NEW.id ) > 0
        THEN
            RAISE EXCEPTION '?Disthost needs jailroot, because referenced by jail(s)';  
        ELSE
            RETURN NEW;
        END IF;
    END;
$$ LANGUAGE 'plpgsql';

DROP TRIGGER IF EXISTS Ensure_jailroot_if_jails_exist ON DistHosts;
CREATE TRIGGER Ensure_jailroot_if_jails_exist BEFORE INSERT OR UPDATE
    ON DistHosts FOR EACH ROW
    EXECUTE PROCEDURE Ensure_jailroot_if_jails_exist();


CREATE OR REPLACE FUNCTION Ensure_jail_sits_on_correct_disthost() RETURNS TRIGGER AS $$
    BEGIN
        IF NEW.jail IS NULL THEN
            RETURN NEW;
        END IF;
        IF NEW.disthost IS NULL THEN
            RAISE EXCEPTION '?Target: DistHost needed, if jail exists';  
        END IF;
        IF ( SELECT COUNT(*)
                FROM Jails j
                WHERE j.disthost = NEW.disthost ) = 0
        THEN
            RAISE EXCEPTION '?Target: Jail sits on wrong disthost';  
        ELSE
            RETURN NEW;
        END IF;
    END;
$$ LANGUAGE 'plpgsql';

DROP TRIGGER IF EXISTS Ensure_jail_sits_on_correct_disthost ON Targets;
CREATE TRIGGER Ensure_jail_sits_on_correct_disthost BEFORE INSERT OR UPDATE
    ON Targets FOR EACH ROW
    EXECUTE PROCEDURE Ensure_jail_sits_on_correct_disthost();


CREATE OR REPLACE FUNCTION Update_updated() RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated := 'now';
        RETURN NEW;
    END;
$$ LANGUAGE 'plpgsql';

DROP TRIGGER IF EXISTS Update_updated ON Certificates;
CREATE TRIGGER Update_updated_Certificates BEFORE UPDATE
    ON Certificates FOR EACH ROW
    EXECUTE PROCEDURE Update_updated();

DROP TRIGGER IF EXISTS Update_updated ON Certinstances;
CREATE TRIGGER Update_updated_Certinstances BEFORE UPDATE
    ON Certinstances FOR EACH ROW
    EXECUTE PROCEDURE Update_updated();

DROP TRIGGER IF EXISTS Update_updated ON Disthosts;
CREATE TRIGGER Update_updated_Disthosts BEFORE UPDATE
    ON Disthosts FOR EACH ROW
    EXECUTE PROCEDURE Update_updated();

DROP TRIGGER IF EXISTS Update_updated ON Places;
CREATE TRIGGER Update_updated_Places BEFORE UPDATE
    ON Places FOR EACH ROW
    EXECUTE PROCEDURE Update_updated();

DROP TRIGGER IF EXISTS Update_updated ON Subjects;
CREATE TRIGGER Update_updated_Subjects BEFORE UPDATE
    ON Subjects FOR EACH ROW
    EXECUTE PROCEDURE Update_updated();


                        -- Views --------------------------------------------

DROP VIEW IF EXISTS pki.certs;
CREATE OR REPLACE VIEW pki.certs AS
 SELECT s1.type AS "Subject",
    s1.name AS "Cert Name",
    c.type AS "Type",
    c.encryption_algo AS "algo",
    c.OCSP_must_staple AS "ocsp_ms",
    (c.authorized_until)::date AS authorized,
    s2.name AS "Alt Name",
    s.name AS "TLSA",
    s.port AS "Port",
    d.fqdn AS "Dist Host",
    j.name AS "Jail",
    p.name AS "Place"
   FROM ((((((((pki.subjects s1
     RIGHT JOIN pki.certificates c ON (((s1.certificate = c.id) AND (s1.isaltname = false))))
     LEFT JOIN pki.subjects s2 ON (((s2.certificate = c.id) AND (s2.isaltname = true))))
     LEFT JOIN pki.certificates_services cs ON ((c.id = cs.certificate)))
     LEFT JOIN pki.services s ON ((cs.service = s.id)))
     LEFT JOIN pki.targets t ON ((c.id = t.certificate)))
     LEFT JOIN pki.disthosts d ON ((t.disthost = d.id)))
     LEFT JOIN pki.jails j ON ((t.jail = j.id)))
     LEFT JOIN pki.places p ON ((t.place = p.id)))
  ORDER BY s1.name, s2.name, d.fqdn;

DROP VIEW IF EXISTS pki.certs_ids;
CREATE OR REPLACE VIEW pki.certs_ids AS
 SELECT c.id AS c_id,
    s1.id AS s1_id,
    s1.type AS "Subject Type",
    s1.name AS "Cert Name",
    c.type AS "Type",
    c.encryption_algo AS "algo",
    c.OCSP_must_staple AS "ocsp_ms",
    (c.authorized_until)::date AS authorized,
    s2.id AS s2_id,
    s2.name AS "Alt Name",
    s.id AS s_id,
    s.name AS "TLSA",
    s.port AS "Port",
    t.id AS t_id,
    d.id AS d_id,
    d.fqdn AS "FQDN",
    j.id AS j_id,
    j.name AS "Jail",
    p.id AS p_id,
    p.name AS "Place"
   FROM ((((((((subjects s1
     RIGHT JOIN certificates c ON (((s1.certificate = c.id) AND (s1.isaltname = false))))
     LEFT JOIN subjects s2 ON (((s2.certificate = c.id) AND (s2.isaltname = true))))
     LEFT JOIN certificates_services cs ON ((c.id = cs.certificate)))
     LEFT JOIN services s ON ((cs.service = s.id)))
     LEFT JOIN targets t ON ((c.id = t.certificate)))
     LEFT JOIN disthosts d ON ((t.disthost = d.id)))
     LEFT JOIN jails j ON ((t.jail = j.id)))
     LEFT JOIN places p ON ((t.place = p.id)))
  ORDER BY c.id, s1.id, s2.id;


DROP VIEW IF EXISTS pki.inst;
CREATE OR REPLACE VIEW pki.inst AS
 SELECT i.id,
    s.name,
    c.type,
    i.state,
    i.cacert,
    i.ocsp_must_staple,
    i.not_before,
    i.not_after,
    d.encryption_algo,
    d.hash,
    i.updated
   FROM certinstances i,
    CertKeyData d,
    certificates c,
    subjects s
  WHERE (((d.certInstance = i.id) AND (i.certificate = c.id) AND (s.certificate = c.id)) AND (NOT s.isaltname))
  ORDER BY i.id;

                        -- Functions -------------------------------------------
                        
-- SELECT * FROM add_cert('myserver.at.do.main', 'server','LE', NULL, NULL, NULL, NULL, NULL, NULL);
CREATE OR REPLACE FUNCTION add_cert(the_name citext, the_subject_type dd.subject_type, the_cert_type dd.cert_type, the_encryption_algo dd.cert_encryption_algo, must_staple BOOLEAN, the_altname citext, the_tlsa_name citext, the_tlsa_port dd.port_number, the_disthost_name citext, the_jail citext, the_place citext) RETURNS text
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


CREATE OR REPLACE FUNCTION remove_cert(the_cert_name citext) RETURNS void
    LANGUAGE plpgsql
    AS $$
    DECLARE
        cert_id             INT4;

    BEGIN
        if (the_cert_name IS NULL OR the_cert_name = '') THEN
            RAISE EXCEPTION '?the_cert_name must not be empty.';
        END IF;
        SELECT c.id INTO cert_id
            FROM Subjects s, Certificates c
            WHERE s.name = the_cert_name AND s.certificate = c.id;
        IF NOT FOUND THEN
            RAISE EXCEPTION '?No such certificate as "%".', the_cert_name;
        END IF;
        -- All related Subjects, Targets and Certificates_Services
        -- deleted by CASCADEd DELETE:
        DELETE FROM Certificates
            WHERE id = cert_id;
    END
$$;


CREATE OR REPLACE FUNCTION add_altname(the_cert_name citext, the_altname citext) RETURNS void
    LANGUAGE plpgsql
    AS $$
    DECLARE
        cert_id             INT4;
        the_subject_type    dd.subject_type;
        view_row            certs%ROWTYPE;

    BEGIN
        if (the_cert_name IS NULL OR the_cert_name = '' OR the_altname IS NULL OR
            the_altname = '') THEN
            RAISE EXCEPTION '?the_cert_name and the_altname must not be empty.';
        END IF;
        PERFORM id
            FROM Subjects
            WHERE name = the_altname;
        IF FOUND THEN
            RAISE EXCEPTION '?"%" is already in use.', the_altname;
        END IF;
        SELECT certificate, type INTO cert_id, the_subject_type
            FROM Subjects
            WHERE name = the_cert_name;
        IF FOUND THEN
            INSERT INTO Subjects(type, name, isAltname, certificate)
                VALUES(the_subject_type, the_altname, TRUE, cert_id);
        ELSE
           RAISE EXCEPTION '?No such Subject as "%"', the_cert_name;
        END IF;
    END
$$;


CREATE OR REPLACE FUNCTION remove_altname(the_altname citext) RETURNS void
    LANGUAGE plpgsql
    AS $$
    BEGIN
        DELETE FROM Subjects
            WHERE name = the_altname AND isAltname = TRUE;
    END
$$;


CREATE OR REPLACE FUNCTION add_service(the_cert_name citext, the_service_name citext, the_port dd.port_number) RETURNS void
    LANGUAGE plpgsql
    AS $$
    DECLARE
        cert_id             INT4;
        service_id          INT4;

    BEGIN
        if (the_cert_name IS NULL OR the_cert_name = '' OR the_service_name IS NULL OR
            the_service_name = '' OR the_port IS NULL) THEN
            RAISE EXCEPTION '?cert name, service name and the port must not be empty.';
        END IF;
        SELECT id INTO service_id
            FROM Services
            WHERE name = the_service_name AND port = the_port;
        IF NOT FOUND THEN
            RAISE EXCEPTION '?No such service "%" "%".', the_service_name, the_port;
        END IF;
        SELECT certificate INTO cert_id
            FROM Subjects
            WHERE name = the_cert_name;
        IF FOUND THEN
            INSERT INTO Certificates_Services(certificate, service)
                VALUES(cert_id, service_id);
        ELSE
           RAISE EXCEPTION '?No such Subject as "%"', the_cert_name;
        END IF;
    END
$$;


CREATE OR REPLACE FUNCTION remove_service(the_cert_name citext, the_service_name citext, the_port dd.port_number) RETURNS void
    LANGUAGE plpgsql
    AS $$
    DECLARE
        cert_id             INT4;
        service_id          INT4;

    BEGIN
        if (the_cert_name IS NULL OR the_cert_name = '' OR the_service_name IS NULL OR
            the_service_name = '' OR the_port IS NULL) THEN
            RAISE EXCEPTION '?cert name, service name and the port must not be empty.';
        END IF;
        SELECT id INTO service_id
            FROM Services
            WHERE name = the_service_name AND port = the_port;
        IF NOT FOUND THEN
            RAISE EXCEPTION '?No such service "%" "%".', the_service_name, the_port;
        END IF;
        SELECT certificate INTO cert_id
            FROM Subjects
            WHERE name = the_cert_name;
        IF FOUND THEN
            DELETE FROM Certificates_Services
                WHERE certificate = cert_id AND service = service_id;
        ELSE
           RAISE EXCEPTION '?No such Subject as "%"', the_cert_name;
        END IF;
    END
$$;


CREATE OR REPLACE FUNCTION add_target(the_name citext, the_disthost_name citext, the_jail citext, the_place citext) RETURNS text
    LANGUAGE plpgsql
    AS $$
    DECLARE
        cert_id             INT4;
        view_row            certs%ROWTYPE;

    BEGIN
        if (the_name IS NULL OR the_name = '' OR the_disthost_name IS NULL OR
            the_disthost_name IS NULL) THEN
            RAISE EXCEPTION '?the_name and the_disthost_name must not be empty.';
        END IF;
        SELECT c.id INTO cert_id
            FROM Subjects s, Certificates c
            WHERE s.name = the_name AND s.certificate = c.id;
        IF NOT FOUND THEN
            RAISE EXCEPTION '?No such certificate as "%"', the_name;
        END IF;

        BEGIN
            DECLARE
                the_disthost_id  INT4 := NULL;
                the_jail_id     INT4 := NULL;
                the_place_id    INT4 := NULL;
            BEGIN
                SELECT id INTO the_disthost_id
                    FROM DistHosts
                    WHERE FQDN = the_disthost_name;
                IF NOT FOUND THEN
                    RAISE EXCEPTION '?No such disthost "%"', the_disthost_name;
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
        END;
        SELECT * INTO view_row
            FROM certs
            WHERE
                "Cert Name" = the_name AND "Dist Host" = the_disthost_name AND
                "Jail" = the_jail AND "Place" = the_place;
        RETURN view_row;
    END
$$;


CREATE OR REPLACE FUNCTION remove_target(the_cert_name citext, the_disthost_name citext, the_jail citext, the_place citext) RETURNS void
    LANGUAGE plpgsql
    AS $$
    DECLARE
        cert_id             INT4;
        the_disthost_id  INT4 := NULL;
        the_jail_id     INT4 := NULL;
        the_place_id    INT4 := NULL;

    BEGIN
        if (the_cert_name IS NULL OR the_cert_name = '' OR the_disthost_name IS NULL OR
            the_disthost_name IS NULL) THEN
            RAISE EXCEPTION '?the_cert_name and the_disthost_name must not be empty.';
        END IF;
        SELECT c.id INTO cert_id
            FROM Subjects s, Certificates c
            WHERE s.name = the_cert_name AND s.certificate = c.id;
        IF NOT FOUND THEN
            RAISE EXCEPTION '?No such certificate as "%".', the_altname;
        END IF;
        SELECT d.id INTO the_disthost_id
            FROM Disthosts d
            WHERE d.fqdn = the_disthost_name;
        IF NOT FOUND THEN
            RAISE EXCEPTION '?No such disthost as "%".', the_disthost_name;
        END IF;

        SELECT j.id INTO the_jail_id
            FROM Jails j
            WHERE j.name = the_jail;
        SELECT p.id INTO the_place_id
            FROM Places p
            WHERE p.name = the_place;

        DELETE FROM Targets
            WHERE
                certificate = cert_id AND disthost = the_disthost_id AND
                jail = the_jail_id AND place = the_place_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION '?No target exists with that combination.';
        END IF;
   END
$$;


GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA pki TO "serverPKI";
GRANT USAGE ON ALL SEQUENCES IN SCHEMA pki TO "serverPKI";
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA pki TO "serverPKI";

GRANT USAGE ON SCHEMA pki TO "serverPKI";

INSERT INTO Revision(schemaversion, keysencrypted) values(5,false);

INSERT INTO Certificates(id,type,disabled,remarks) VALUES(1,'local',true,'Placeholder to resolve chicken-egg-problem');
INSERT INTO Subjects(id,type,name,isAltname,certificate,remarks) VALUES(1,'CA','No cert',false,1, 'Placeholder to resolve chicken-egg-problem');
INSERT INTO CertInstances(id,certificate,state,CAcert,remarks) VALUES(1,1,'reserved',1,'Placeholder to resolve chicken-egg-problem');

SELECT pg_catalog.setval('pki.certificates_id_seq', 2, true);
SELECT pg_catalog.setval('pki.subjects_id_seq', 2, true);
SELECT pg_catalog.setval('pki.certinstances_id_seq', 2, true);


COMMIT;

