----------------------------- serverPKI definition schema
SET search_path = pki, dd, public, pg_catalog;
SET log_min_messages='error';

START TRANSACTION; 

DROP SCHEMA IF EXISTS pki CASCADE;

CREATE SCHEMA pki               -- DB schema for project serverPKI'


CREATE TABLE Certificates (     -- The certificate class
  id                SERIAL          PRIMARY KEY,    -- 'PK of Certificates table'
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
  certificate       int4                            -- 'certificate'
                        REFERENCES Certificates
                        ON DELETE SET NULL
                        ON UPDATE SET NULL,
  TLSAprefix        TEXT            NOT NULL,
  created           dd.created,                     -- 'time of record update'
  updated           dd.updated,                     -- 'time of record update'
  remarks           TEXT,                           -- 'Remarks'

    UNIQUE (name, port)
)


CREATE TABLE Places (         -- Places hold filesystem and exec data on target
  id                SERIAL          PRIMARY KEY,    -- 'PK of Places table'
  name              TEXT            NOT NULL UNIQUE,-- 'Name of place
  cert_file_type    dd.place_cert_file_type         -- 'which cert amd key files'
                                    DEFAULT 'separate'
                                    NOT NULL, 
  cert_path         TEXT            NOT NULL,       -- 'path to cert dir' 
  key_path          TEXT            NOT NULL,       -- 'path to key dir' 
  uid               int2                    ,       -- 'uid for chown of key file'
  gid               int2                    ,       -- 'gid for chown of key file'
  mode              int2                    ,       -- 'use this mode instead of 0400 for key file'
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
  distHost          int4            NOT NULL        -- 'host, hosting this jail/cert'
                        REFERENCES DistHosts
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  jail              int4            NOT NULL        -- 'jail, hosting this cert'
                        REFERENCES Jails
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  place             int4            NOT NULL        -- 'cert placed here'
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
        IF (SELECT COUNT(*)
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




GRANT USAGE ON SCHEMA pki TO pki_dev;

COMMIT;                 -- CREATE SCHEMA pki

