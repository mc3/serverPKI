    ----------------------------- pki definition schema
SET search_path = pki, dd, public, pg_catalog;
SHOW search_path;


START TRANSACTION; 


DROP SCHEMA IF EXISTS pki CASCADE;

CREATE SCHEMA pki               -- DB schema for project "serverPKI"'


CREATE TABLE Revision (
  id                SERIAL          PRIMARY KEY,            -- 'PK of Revision'
  schemaVersion     int2            NOT NULL  DEFAULT 5,    -- 'Version of DB schema'
  keysEncrypted     BOOLEAN         NOT NULL  DEFAULT FALSE, -- 'Cert keys are encrypted'
  updated           dd.updated                              -- 'time of record update'

)


CREATE TABLE Certificates (     -- The certificate meta data class
  id                SERIAL          PRIMARY KEY,    -- 'PK of Certificates table'
  type              dd.cert_type    NOT NULL,
  disabled          BOOLEAN         NOT NULL
                                    DEFAULT false,
  authorized_until  TIMESTAMP,                      -- 'termination date of LE authorization'
                                                    -- 'Last "please issue" mail of local cert send'
  encryption_algo   dd.cert_encryption_algo         -- 'Encryption algorith for this certificate'
                             DEFAULT 'rsa' NOT NULL,
  ocsp_must_staple  boolean  DEFAULT false NOT NULL,-- 'OCSP staple protocol supported by server'
  updated           dd.updated,                     -- 'time of record update'
  created           dd.created,                     -- 'time of record creation'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE CertInstances (     -- certificate instances being issued
  id                SERIAL          PRIMARY KEY,    -- 'PK of CertInstance table'
  certificate       int4            NOT NULL        -- 'Certificate Class'
                        REFERENCES Certificates
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  state             dd.cert_state   NOT NULL,       -- 'state of instance
  ocsp_must_staple  boolean DEFAULT FALSE NOT NULL, -- 'true of this cert requires OCSP stapling support by server
  CAcert            int4            NOT NULL        -- 'cert of issuing CA'
                        REFERENCES CertInstances
                        ON DELETE RESTRICT
                        ON UPDATE RESTRICT
                        DEFERRABLE
                        INITIALLY DEFERRED,
  not_before        TIMESTAMP
                            DEFAULT NOW() NOT NULL, -- 'date, where cert is valid'
  not_after         TIMESTAMP
                            DEFAULT NOW() NOT NULL, -- 'date where cert expires'
  updated           dd.updated,                     -- 'time of record update'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE CertKeyData (      -- Holds cert-key-pairs for one algorithm with multi algo certs
  id                SERIAL          PRIMARY KEY,    -- 'PK of CertKeyData table'
  certinstance      int4            NOT NULL        -- 'issued certificate (parent table)'
                        REFERENCES CertInstances
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  encryption_algo   dd.cert_encryption_algo         -- 'Encryption algorith fin use'
                            DEFAULT 'rsa' NOT NULL,
  cert              BYTEA           NOT NULL,       -- 'PEM encoded certificate'
  key               BYTEA           NOT NULL,       -- 'PEM encoded key'
  hash              TEXT            NOT NULL UNIQUE,-- 'hex ascii encoded TLSA hash'
  created           dd.created,                     -- 'time of record creation'

    UNIQUE (certinstance, encryption_algo)          -- 'only cert per algo and instance allowed

)


CREATE TABLE Subjects (         -- A Subject or an alternate name of a certificate
  id                SERIAL          PRIMARY KEY,    -- 'PK of Subjects table'
  type              dd.subject_type NOT NULL        -- 'Type of subject'
                                        DEFAULT 'server', 
  name              CITEXT          NOT NULL UNIQUE,-- 'Either FQDN or user name'
  isAltname         BOOLEAN         NOT NULL
                                        DEFAULT TRUE, 
  certificate       INT4                            -- 'certifcate for this subject'
                        REFERENCES Certificates
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  updated           dd.updated,                     -- 'time of record update'
  created           dd.created,                     -- 'time of record creation'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE Services (         -- Service and port combination for TLSA-RR
  id                SERIAL          PRIMARY KEY,    -- 'PK of Services table'
  name              CITEXT          NOT NULL ,      -- 'Name of service'
  port              dd.port_number  NOT NULL ,      -- 'tcp / udp port number'
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


CREATE TABLE DistHosts (         -- Hosts where targets located (cert and key files)
  id                SERIAL          PRIMARY KEY,    -- 'PK of DistHosts table'
  FQDN              CITEXT          NOT NULL UNIQUE,-- 'FQDN of host'
  jailroot          TEXT      ,                     -- 'path to root of jails'
  updated           dd.updated,                     -- 'time of record update'
  created           dd.created,                     -- 'time of record creation'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE Jails (              -- FreeBSD jail, to place cert at
  id                SERIAL          PRIMARY KEY,    -- 'PK of Jails table'
  name              CITEXT          NOT NULL UNIQUE,-- 'FQDN of host'
  distHost          int4            NOT NULL        -- 'host, hosting this jail'
                        REFERENCES DistHosts
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  updated           dd.updated,                     -- 'time of record update'
  created           dd.created,                     -- 'time of record creation'
  remarks           TEXT                            -- 'Remarks'
)


CREATE TABLE Places (         -- Places hold filesystem and exec data on target
  id                SERIAL          PRIMARY KEY,    -- 'PK of Places table'
  name              CITEXT          NOT NULL UNIQUE,-- 'Name of place'
  cert_file_type    dd.place_cert_file_type         -- 'which cert amd key files'
                                    DEFAULT 'separate'
                                    NOT NULL, 
  cert_path         TEXT            NOT NULL,       -- 'path to cert/key dir' 
  key_path          TEXT                    ,       -- 'path to key dir if different from cert' 
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



CREATE TABLE Targets (    -- Target describes where and how certs and keys are deployed
  id                SERIAL          PRIMARY KEY,    -- 'PK of DistHosts table'
  distHost          int4            NOT NULL        -- 'host, hosting this jail/cert'
                        REFERENCES DistHosts
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  jail              int4                            -- 'jail, hosting this cert'
                        REFERENCES Jails
                        ON DELETE SET NULL
                        ON UPDATE SET NULL,
  place             int4                            -- 'cert placed here'
                        REFERENCES Places
                        ON DELETE SET NULL
                        ON UPDATE SET NULL,
  certificate       int4            NOT NULL        -- 'subject of target'
                        REFERENCES Certificates
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
  updated           dd.updated,                     -- 'time of record update'
  created           dd.created,                     -- 'time of record creation'
  remarks           TEXT,                           -- 'Remarks'

  UNIQUE(distHost, jail, place, certificate)
)



;                       -- CREATE SCHEMA pki -----------------------------------



GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA pki TO "serverPKI";
GRANT USAGE ON ALL SEQUENCES IN SCHEMA pki TO "serverPKI";
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA pki TO "serverPKI";

GRANT USAGE ON SCHEMA pki TO "serverPKI";

COMMIT;

