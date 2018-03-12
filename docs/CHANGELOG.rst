==================
Changelog
==================

0.9.0 (2017-07-18)
-----------------

- Initial public release.

0.9.1 (2017-07-28)
-----------------

- Documentation at https://serverpki.readthedocs.io

0.9.2 (2018-03-19)
-----------------

- Python 3.6 supported
- Omit disabled certs from list of certs to be renewed.
- BUGFIX: Bind place to jail not to disthost (dh->jl-pl) 
- Do not expire certs one day before "not_after" but one day after instead
- Allow "distribute only" with --renew-local-certs
- Allow encrypted storage of keys in DB
    2 new action commands: --encrypt-keys and --decrypt-keys
    New configuration parameter: db_encryption_key

- Upgrading:
    Create new table Revision in DB - see install/create_schema_pki.sql:
     pki_op=# CREATE TABLE Revision (
     id                SERIAL          PRIMARY KEY,            -- 'PK of Revision'
     schemaVersion     int2            NOT NULL  DEFAULT 1,    -- 'Version of DB schema'
     keysEncrypted     BOOLEAN         NOT NULL  DEFAULT FALSE -- 'Cert keys are encrypted'
     );
     pki_op=# INSERT INTO revision (schemaVersion) values(1);
    Then create passphrase and encrypt DB (see tutorial).
