----------------------------- serverPKI definition schema
SET search_path = pki, dd, public, pg_catalog;
SET log_min_messages='error';

START TRANSACTION; 

DROP SCHEMA IF EXISTS pki CASCADE;

CREATE SCHEMA pki               -- DB schema for project serverPKI'


CREATE TABLE Certificates (     -- All the details of a certificate
  id                SERIAL          PRIMARY KEY,    -- 'PK of Certificates table'
  subject           int4            NOT NULL UNIQUE,-- 'Subject of certificate'
  created           dd.created                     ,   -- 'Date of record creation'
  remarks           text                            -- 'Remarks'
)


CREATE TABLE Subjects (         -- A Subject or an alternate name of a certificate
  id                SERIAL          PRIMARY KEY,    -- 'PK of Subjects table'
  type              dd.subject_type NOT NULL        -- 'Type of subject'
                                        DEFAULT 'server', 
  name              text            NOT NULL UNIQUE,-- 'Either FQDN or user name'
  isAltname         boolean         NOT NULL
                                        DEFAULT TRUE, 
  certificate       int4                            -- 'certifcate for this subject'
                        REFERENCES Certificates
                        ON DELETE SET NULL
                        ON UPDATE SET NULL,
  created           dd.created                     ,   -- 'time of record creation'
  pdated            dd.updated                     ,   -- 'time of record update'
  remarks           text                            -- 'Remarks'
)

;                       -- CREATE SCHEMA pki -----------------------------------


ALTER TABLE Certificates                            -- 'forward referenced FOREIGN KEYS'
    ADD FOREIGN KEY ( subject ) REFERENCES Subjects
                        ON DELETE CASCADE          -- 'We will be deleted with the subject'
                        ON UPDATE RESTRICT
                                DEFERRABLE ;


GRANT USAGE ON SCHEMA pki TO pki_dev;

COMMIT;                 -- CREATE SCHEMA pki

