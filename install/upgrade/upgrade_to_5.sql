-- upgrade_to_5.sql

START TRANSACTION; 

ALTER TYPE dd.cert_encryption_algo RENAME VALUE 'rsa_plus_ec' TO 'rsa plus ec';
ALTER TYPE dd.subject_type ADD VALUE 'reserved';

SET search_path = pki, dd, public, pg_catalog;

CREATE TABLE CertKeyData                  -- cert, key and hash binary data
(
    id              SERIAL PRIMARY KEY,   -- 'PK of cert_key_data table'
    certInstance    int4  NOT NULL        -- 'parent table'
        REFERENCES CertInstances
            ON DELETE CASCADE
            ON UPDATE CASCADE,
    encryption_algo dd.cert_encryption_algo  -- 'rsa' or 'ec'
                          DEFAULT 'rsa'
                          NOT NULL,
    cert            BYTEA NOT NULL,       -- 'PEM encoded certificate'
    key             BYTEA NOT NULL,       -- 'PEM encoded key'
    hash            TEXT  NOT NULL UNIQUE,-- 'hex ascii encoded TLSA hash'
    created         dd.created            -- 'time of record creation'
);

CREATE OR REPLACE FUNCTION move_data() RETURNS BOOLEAN AS $$
    DECLARE
        the_id  INT;
        the_encryption_algo dd.cert_encryption_algo;
        the_cert    BYTEA;
        the_key     BYTEA;
        the_hash    TEXT;
    BEGIN
        FOR the_id,the_encryption_algo,the_cert,the_key,the_hash IN
            SELECT ci.id,ci.encryption_algo,ci.cert,ci.key,ci.hash
                FROM CertInstances ci
        LOOP
            INSERT INTO CertKeyData(encryption_algo,cert,key,hash,certInstance)
                VALUES(the_encryption_algo,the_cert,the_key,the_hash,the_id);
        END LOOP;
        RETURN True;
    END;
$$ LANGUAGE 'plpgsql';


SELECT * FROM move_data();


DROP VIEW inst;

ALTER TABLE CertInstances DROP COLUMN encryption_algo;
ALTER TABLE CertInstances DROP COLUMN cert;
ALTER TABLE CertInstances DROP COLUMN key;
ALTER TABLE CertInstances DROP COLUMN hash;

CREATE VIEW inst AS
 SELECT i.id,
    s.name,
    c.type,
    i.state,
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


DROP VIEW IF EXISTS pki.certs;

CREATE OR REPLACE VIEW pki.certs AS
 SELECT s1.type AS "Subject",
    s1.name AS "Cert Name",
    c.type AS "Type",
    c.encryption_algo AS "algo",
    c.OCSP_must_staple AS "o_m_staple",
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



UPDATE Revision SET schemaVersion=5 WHERE id=1;

COMMIT;
