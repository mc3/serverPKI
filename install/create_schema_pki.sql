----------------------------- serverPKI definition schema
SET search_path = pki, dd, public, pg_catalog;
SET log_min_messages='error';

START TRANSACTION; 

DROP SCHEMA IF EXISTS pki CASCADE;

CREATE SCHEMA pki               -- DB schema for project serverPKI'


CREATE TABLE Certificates (     -- The certificate class
  id                SERIAL          PRIMARY KEY,    -- 'PK of Certificates table'
  type              cert_type       NOT NULL,
  disabled          BOOLEAN         NOT NULL
                                    DEFAULT false,
  updated           dd.updated,                     -- 'time of record update'
  created           dd.created,                     -- 'time of record update'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE Subjects (         -- A Subject or an alternate name of a certificate
  id                SERIAL          PRIMARY KEY,    -- 'PK of Subjects table'
  type              dd.subject_type NOT NULL        -- 'Type of subject'
                                        DEFAULT 'server', 
  name              TEXT            NOT NULL UNIQUE,-- 'Either FQDN or user name'
  isAltname         BOOLEAN         NOT NULL
                                        DEFAULT TRUE, 
  certificate       INT4                            -- 'certifcate for this subject'
                        REFERENCES Certificates
                        ON DELETE SET NULL
                        ON UPDATE SET NULL,
  updated           dd.updated,                     -- 'time of record update'
  created           dd.created,                     -- 'time of record creation'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE Services (         -- Service and port combination for TLSA-RR
  id                SERIAL          PRIMARY KEY,    -- 'PK of Services table'
  name              TEXT            NOT NULL ,      -- 'Name of service
  port              dd.port_number  NOT NULL ,      -- 'tcp / udp port number 
  TLSAprefix        TEXT            NOT NULL,
  created           dd.created,                     -- 'time of record update'
  updated           dd.updated,                     -- 'time of record update'
  remarks           TEXT,                           -- 'Remarks'

    UNIQUE (name, port)
)

CREATE TABLE Certificates_Services (    -- Junction relation
  certificate       int4                            -- 'certificate'
                        REFERENCES Certificates
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  service           int4                            -- 'service'
                        REFERENCES Services
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,

  PRIMARY KEY (certificate, service)
)


CREATE TABLE Places (         -- Places hold filesystem and exec data on target
  id                SERIAL          PRIMARY KEY,    -- 'PK of Places table'
  name              TEXT            NOT NULL UNIQUE,-- 'Name of place
  cert_file_type    dd.place_cert_file_type         -- 'which cert amd key files'
                                    DEFAULT 'separate'
                                    NOT NULL, 
  cert_path         TEXT            NOT NULL,       -- 'path to cert/key dir' 
  key_path          TEXT                    ,       -- 'path to key dir if different from cert' 
  uid               int2                    ,       -- 'uid for chown of key file'
  gid               int2                    ,       -- 'gid for chown of key file'
  mode            int2                    ,       -- 'use this mode instead of 0400 for key file'
  chownBoth         BOOLEAN         NOT NULL        -- 'chown both cert and key file'
                                    DEFAULT FALSE,
  pgLink            BOOLEAN         NOT NULL        -- 'create link for pqlib'
                                    DEFAULT FALSE,
  reload_command    TEXT            ,               -- 'shell command to reload service'
  created           dd.created,                     -- 'time of record update'
  updated           dd.updated,                     -- 'time of record update'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE DistHosts (         -- Hosts where targets located (cert and key files)
  id                SERIAL          PRIMARY KEY,    -- 'PK of DistHosts table'
  FQDN              TEXT            NOT NULL UNIQUE,-- 'FQDN of host'
  jailroot          TEXT      ,                     -- 'path to root of jails'
  updated           dd.updated,                     -- 'time of record update'
  created           dd.created,                     -- 'time of record creation'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE Jails (              -- FreeBSD jail, to place cert at
  id                SERIAL          PRIMARY KEY,    -- 'PK of Jails table'
  name              TEXT            NOT NULL UNIQUE,-- 'FQDN of host'
  distHost          int4            NOT NULL        -- 'host, hosting this jail'
                        REFERENCES DistHosts
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  updated           dd.updated,                     -- 'time of record update'
  created           dd.created,                     -- 'time of record creation'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE Targets (    -- Target describes where and how certs and keys are deployed
  id                SERIAL          PRIMARY KEY,    -- 'PK of DistHosts table'
  distHost          int4                            -- 'host, hosting this jail/cert'
                        REFERENCES DistHosts
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  jail              int4                            -- 'jail, hosting this cert'
                        REFERENCES Jails
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  place             int4                            -- 'cert placed here'
                        REFERENCES Places
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  certificate       int4            NOT NULL        -- 'subject of target'
                        REFERENCES Certificates
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  updated           dd.updated,                     -- 'time of record update'
  created           dd.created,                     -- 'time of record creation'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE CertInstance (        -- certificate instances being issued
  id                SERIAL          PRIMARY KEY,    -- 'PK of CertInstance table'
  certificate       int4            NOT NULL        -- 'Certificate Class'
                        REFERENCES Certificates
                        ON DELETE RESTRICT
                        ON UPDATE RESTRICT,
  state             TEXT            NOT NULL,       -- 'state tbd'
  cert              TEXT            NOT NULL,       -- 'PEM encoded certificate'
  key               TEXT            NOT NULL,       -- 'PEM encoded key'
  cert_key          TEXT            NOT NULL,       -- 'PEM encoded cert+key'
  CAcert_cert_key   TEXT            NOT NULL,       -- 'PEM encoded cert+key+CAcert'
  TLSA              TEXT            NOT NULL,       -- 'hex ascii encoded TLSA hash'
  issued            dd.created,                     -- 'time of record update'
  expires           dd.created,                     -- 'time of record creation'
  updated           dd.updated,                     -- 'time of record update'
  remarks           TEXT                            -- 'Remarks'
)
;                       -- CREATE SCHEMA pki -----------------------------------


                        -- TRIGGERS --------------------------------------------


CREATE OR REPLACE FUNCTION Ensure_exactly_one_none_altname_subject_per_cert() RETURNS TRIGGER AS $$
    BEGIN
        IF NEW.isAltname THEN
            RETURN NEW;
        END IF;
        IF ( SELECT COUNT(*)
                FROM Subjects S
                WHERE S.certificate = NEW.certificate AND NOT S.isAltname ) > 0 THEN
            RAISE EXCEPTION '?Only one none-alternate-name-Subject per Certificate allowed';  
        ELSE
            RETURN NEW;
        END IF;
    END;
$$ LANGUAGE 'plpgsql';

GRANT EXECUTE ON FUNCTION Ensure_exactly_one_none_altname_subject_per_cert() TO pki_dev;
DROP TRIGGER IF EXISTS Ensure_exactly_one_none_altname_subject_per_cert ON Subjects;
CREATE TRIGGER Ensure_exactly_one_none_altname_subject_per_cert BEFORE INSERT OR UPDATE
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

GRANT EXECUTE ON FUNCTION Ensure_jail_on_disthost_with_jailroot() TO pki_dev;
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

GRANT EXECUTE ON FUNCTION Ensure_jailroot_if_jails_exist() TO pki_dev;
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

GRANT EXECUTE ON FUNCTION Ensure_jail_sits_on_correct_disthost() TO pki_dev;
DROP TRIGGER IF EXISTS Ensure_jail_sits_on_correct_disthost ON Targets;
CREATE TRIGGER Ensure_jail_sits_on_correct_disthost BEFORE INSERT OR UPDATE
    ON Targets FOR EACH ROW
    EXECUTE PROCEDURE Ensure_jail_sits_on_correct_disthost();


                        -- Views --------------------------------------------

CREATE OR REPLACE VIEW cert AS
    SELECT
        s1.name AS CertName, s2.name AS AltNmae, d.fqdn AS DistHost, 
            j.name AS Jail, p.name AS Place  
        FROM
            Subjects s1, Subjects S2, DistHosts d, Jails j, Places p,
            Targets t, Certificates c
        WHERE
            s1.certificate = c.id AND s1.isAltname = FALSE AND
            s2.certificate = c.id AND s2.isAltname = TRUE AND
            t.certificate =  c.id AND t.disthost = d.id AND
            t.jail = j.id AND t.place = p.id;

GRANT USAGE ON SCHEMA pki TO pki_dev;

COMMIT;                 -- CREATE SCHEMA pki

