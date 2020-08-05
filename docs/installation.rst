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


.. _Creation_of_DB_user_and_DB:


    host db1, port 2222, user dba and user pki_op are examples. dba must be pgsql superuser.
    In scripts create_schema_pki.sql and create_triggers_pki.sql are GRANT statements which allow
    usage of objects by user serverPKI. To change this, you must edit those scripts.
    Create ~/.pgpass or client cert in ~/.postgresql::

     psql -h db1 -p 2222 -U dba postgres
     postgres=> CREATE ROLE pki_op LOGIN CREATEDB;
     psql -h db1 -p 2222 -U pki_op postgres
     postgres=> CREATE DATABASE pki_op;
     psql -h db1 -p 2222 -U pki_op -d pki_op -f install/fresh_install/create_schema_dd.sql
     psql -h db1 -p 2222 -U pki_op -d pki_op -f install/fresh_install/create_extension_citext.sql
     psql -h db1 -p 2222 -U pki_op -d pki_op -f install/fresh_install/create_schema_pki.sql

     # optional (usefull examples for demo):
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
      pki    | certificates          | table    | pki_op
      pki    | certificates_id_seq   | sequence | pki_op
      pki    | certificates_services | table    | pki_op
      pki    | certinstances         | table    | pki_op
      pki    | certinstances_id_seq  | sequence | pki_op
      pki    | certkeydata           | table    | pki_op
      pki    | certkeydata_id_seq    | sequence | pki_op
      pki    | certs                 | view     | pki_op
      pki    | certs_ids             | view     | pki_op
      pki    | disthosts             | table    | pki_op
      pki    | disthosts_id_seq      | sequence | pki_op
      pki    | inst                  | view     | pki_op
      pki    | jails                 | table    | pki_op
      pki    | jails_id_seq          | sequence | pki_op
      pki    | places                | table    | pki_op
      pki    | places_id_seq         | sequence | pki_op
      pki    | revision              | table    | pki_op
      pki    | revision_id_seq       | sequence | pki_op
      pki    | services              | table    | pki_op
      pki    | services_id_seq       | sequence | pki_op
      pki    | subjects              | table    | pki_op
      pki    | subjects_id_seq       | sequence | pki_op
      pki    | targets               | table    | pki_op
      pki    | targets_id_seq        | sequence | pki_op
     (24 rows)
     
     serverpki=> \q



Configuration
=============

.. _Configuration:


Copy install/example_config.py to /usr/local/etc/serverPKI/serverPKI_config.py
or to VIRTUAL_ENV/etc/serverPKI_config.py and edit the copy. The config file
is in ini file format with nested sections.

The following variables can be set:

Pathes
------

.. _Configuration_Pathes:

        Section containg filesystem path information

home
        Root of the work area and credential storage, usually somewhere at var.
        This variable must be set to a save place in order to use serverPKI

db
        Some credentials stored here, like:

ca_cert, ca_key
        Cert and key of the local (internal) CA, in case, there exists one
        when you begin with serverPKI. Will be imported into DB with issuence
        of 1st local cert. The flat files can be deleted then. Not needed, if
        local CA cert created with "serverPKI  --issue-local-CAcert".

.. _tutorial_ca_cert: ./tutorial.html#creating-our-first-local-certificate


db_encryption_key
        All keys in DB are encrypted with this key.
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
        Will be used with ddns with remote master in the future.

Next 6 variables are for historical DNS control via zone files and should not
be used for new installations:

zone_file_root
        zone files are kept in DSKM format:
            zone_file_root/example.com/example.com.zone

dns_key
        rndc key for triggering named reload.

zone_tlsa_inc_mode, zone_tlsa_inc_uid, zone_tlsa_inc_gid
        file permission and ownership for files, incuded by zone files.

zone_file_include_name
        The filename of the file, included from zone file with the challenges.
    

ddns_key_file
        The filename of a named dynamic dns key file, used to secure dns update
        transactions.


X509atts
--------

.. _Configuration_X509atts:

        Section of local X509 certificate standard attribute defaults

names and extensions
        Cert fields used for CA cert and server/client certs.

lifetime and bits
        are used for server/client certs


DBAccount
---------

.. _Configuration_DBAccount:

        Configuration of account data and credentials for the PostgreSQL DB.
        Passwords may be stored in pki_op's HOME in  HOME/.pgpass or
        client certs in HOME/.postgresql.crt and HOME/.postgresql.key

dbHost
        host name of DB server

dbPort
        port number of DB instance

dbUser
        DB role name, used for accessing the DB

dbDbaUser
        Role name for tasks requiring super user rights. Empty, if person
        who runs program is DBA

dbSslRequired
        If "yes" then connecting will be made with TLS

dbDatabase
        name of database, used for serverPKI (contains schemas dd and pki)

dbSearchPath
        search_path set at login

dbCert
        path of file containg cert for TLS

dbCertKey
        path of file containg key for TLS

Misc
----

.. _Configuration_Misc:

        Section with miscellaneous config parameters

SSH_CLIENT_USER_NAME
        user name on target hosts for cert/key distribution

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
        2nd TLSA RRs) for rollover
        
LOCAL_ISSUE_MAIL_TIMEDELTA = timedelta(days=30)
        E-Mail to administrator will be sent that many days before expiration of
        local certs. (Must be issued manually, using pass phrase)

MAIL_RELAY, MAIL_SUBJECT, MAIL_SENDER and MAIL_RECIPIENT
        Characteristics of mail service for notification mails.
        
SYSLOG_FACILITY
        Facility for syslog log messages
        
        serverPKI uses levels DEBUG, INFO, NOTICE and ERR
