==============================
Installation and Configuration
==============================



Installation
============
        
- Installation of PostgreSQL client package:
- Installation of PostgreSQL server (if none exists) and related packages on DB server host::

    pkg install databases/postgresql12-server
    pkg install databases/ip4r

- Installation of Python packages from PyPI::

     pip install serverPKI

- Creation of DB user and DB

    host db1, port 2222, user dba and user pki_op are examples. dba must be pgsql superuser.
    Create ~/.pgpass or client cert in ~/.postgresql::

     psql -h db1 -p 2222 -U dba postgres
     postgres=> CREATE ROLE pki_op LOGIN CREATEDB;
     psql -h db1 -p 2222 -U pki_op postgres
     postgres=> CREATE DATABASE pki_op;
     psql -h db1 -p 2222 -U pki_op -d pki_op -f install/fresh_install/create_schema_dd.sql
     psql -h db1 -p 2222 -U pki_op -d pki_op -f install/fresh_install/create_extension_citext.sql
     psql -h db1 -p 2222 -U pki_op -d pki_op -f install/fresh_install/create_schema_pki.sql
     # optional (for demo only):
     psql -h db1 -p 2222 -U pki_op -d pki_op -f install/fresh_install/load_testdata.sql
     psql -h db1 -p 2222 -U pki_op -d pki_op -f install/fresh_install/create_triggers_pki.sql
     #
     psql -h db1 -p 2222 -U pki_op
     pki_op=> set search_path to pki,dd;
     SET
     pki_op=> \d
                        List of relations
      Schema |         Name          |   Type   |   Owner
     --------+-----------------------+----------+-----------
      pki    | certificates          | table    | serverPKI
      pki    | certificates_id_seq   | sequence | serverPKI
      pki    | certificates_services | table    | serverPKI
      pki    | certinstances         | table    | serverPKI
      pki    | certinstances_id_seq  | sequence | serverPKI
      pki    | certkeydata           | table    | serverPKI
      pki    | certkeydata_id_seq    | sequence | serverPKI
      pki    | certs                 | view     | serverPKI
      pki    | certs_ids             | view     | serverPKI
      pki    | disthosts             | table    | serverPKI
      pki    | disthosts_id_seq      | sequence | serverPKI
      pki    | inst                  | view     | serverPKI
      pki    | jails                 | table    | serverPKI
      pki    | jails_id_seq          | sequence | serverPKI
      pki    | places                | table    | serverPKI
      pki    | places_id_seq         | sequence | serverPKI
      pki    | revision              | table    | serverPKI
      pki    | revision_id_seq       | sequence | serverPKI
      pki    | services              | table    | serverPKI
      pki    | services_id_seq       | sequence | serverPKI
      pki    | subjects              | table    | serverPKI
      pki    | subjects_id_seq       | sequence | serverPKI
      pki    | targets               | table    | serverPKI
      pki    | targets_id_seq        | sequence | serverPKI
     (24 rows)
     
     serverpki=> \q



Configuration
=============

Copy install/example_config.py to /usr/local/etc/serverPKI/serverPKI_config.py
or to VIRTUAL_ENV/etc/serverPKI_config.py and edit the copy.
The following variables can be set:

home
        Root of the work area and credential storage, usually somewhere at var

dbAccounts
        Credentials stored here. This is a dictionary with key 'serverpki'.
        Nested dictionary contains credentials. See install/example_config.py.

ca_cert and ca_key
        Filename of local CA cert and key in case an existing one must be
        imported into the db. The files can be removed after import. Not used
        if serverPKI itself creates the local CA cert.

db_encryption_key
        Path of file, containing passphrase for encrypted key storage in DB.
        After setting this up, encrypt keys in DB::
        
          operate_serverPKI --encrypt-keys -v
          
        Before changing the passphrase, decrypt all keys::
        
          operate_serverPKI --decrypt-keys -v
        
.. _tutorial: ./tutorial.html#manuale

le_account
        Credentials of Lets Encrypt account in json format.
        See manuale register in tutorial_.

work
        Work direcory

work_tlsa
        TLSA resource records are being accumulated here for named zone update.

tlsa_dns_master
        Host of DNS master. Empty means: Local host. Must be empty for now.

dns_key
        rndc key for triggering named reload.

zone_file_root
        zone files are kept in DSKM format:
            zone_file_root/example.com/example.com.zone

zone_file_include_name
        The filename of the file, included from zone file with the challenges.
    
ddns_key_file
        The filename of a named dynamic dns key file, used to secure dns update
        transactions.

X509atts.names and X509atts.extensions
        Cert fields used for CA cert and server/ client certs.

X509atts.lifetime and X509atts.bits
        are used for server/client certs

dbAccounts
        Account data and credentials for the PostgreSQL DB.
        Passwords may be stored in pki_op's HOME in  HOME/.pgpass or
        client certs in HOME/.postgresql.crt and HOME/.postgresql.key

SSH_CLIENT_USER_NAME
        user name for cert/key distribution

LE_SERVER
        URL of Lets Encrypt server, either (for testing):
            'https://acme-staging-v02.api.letsencrypt.org'
        or (for production):
            'https://acme-v02.api.letsencrypt.org'

LE_EMAIL
        e-mail address for letsencrypt.org registration, used for notifications
        by LE

LE_ZONE_UPDATE_METHOD
        Zone update method for challenges, either 'ddns' (the default) for
        dynamic updates or 'zone_file' for updates via zone file)


LOCAL_CA_BITS LOCAL_CA_LIFETIME
        Number of bits and lifetime of local CA cert.

SUBJECT_LOCAL_CA
        Subject name of local CA in table Subjects (may be changed only initially)

SUBJECT_LE_CA
        Subject name of Lets Encrypt CA in table Subjects (may be changed only
        initially)
    
PRE_PUBLISH_TIMEDELTA
        New certs are published that many days before they become active (with
        2nd TLSA RRs)
        
LOCAL_ISSUE_MAIL_TIMEDELTA = timedelta(days=30)
        E-Mail to administrator will be sent that many days before expiration of
        local certs. (Must be issued manually, using pass phrase)

MAIL_RELAY, MAIL_SUBJECT, MAIL_SENDER and MAIL_RECIPIENT
        Characteristics of mail service for notification mails.
        
SYSLOG_FACILITY
        Facility for syslog log messages
        
        serverPKI uses levels DEBUG, INFO, NOTICE and ERR
