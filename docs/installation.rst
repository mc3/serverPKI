==============================
Installation and Configuration
==============================

.. toctree::


Installation
============
        
- Installation of Python packages from PyPI

    | pip install serverPKI

- Creation of DB user and DB

  host db1, port 2222, user dba and user pki_op are examples.

    | psql -h db1 -p 2222 -U dba postgres
    | serverpki=> CREATE ROLE pki_op LOGIN;
    | serverpki=> CREATE DATABASE serverpki;
    | serverpki=> GRANT CONNECT ON DATABASE serverpki TO pki_op;
    | serverpki=> \\q
    | psql -h db1 -p 2222 -U dba serverpki < install/create_schema_dd.sql
    | psql -h db1 -p 2222 -U dba serverpki < install/create_schema_pki.sql
    | 
    | psql -h db1 -p 2222 -U dba postgres
    | serverpki=> set search_path to pki,dd;
    | SET
    | serverpki=> \\d
    |               List of relations
    |  Schema |         Name          |   Type   | Owner 
    | --------+-----------------------+----------+-------
    |  pki    | certificates          | table    | dba
    |  pki    | certificates_id_seq   | sequence | dba
    |  pki    | certificates_services | table    | dba
    |  pki    | certinstances         | table    | dba
    |  pki    | certinstances_id_seq  | sequence | dba
    |  pki    | certs                 | view     | dba
    |  pki    | certs_ids             | view     | dba
    |  pki    | disthosts             | table    | dba
    |  pki    | disthosts_id_seq      | sequence | dba
    |  pki    | inst                  | view     | dba
    |  pki    | jails                 | table    | dba
    |  pki    | jails_id_seq          | sequence | dba
    |  pki    | places                | table    | dba
    |  pki    | places_id_seq         | sequence | dba
    |  pki    | services              | table    | dba
    |  pki    | services_id_seq       | sequence | dba
    |  pki    | subjects              | table    | dba
    |  pki    | subjects_id_seq       | sequence | dba
    |  pki    | targets               | table    | dba
    |  pki    | targets_id_seq        | sequence | dba
    |  20 rows)
    |  
    |  erverpki=> \q

Configuration
=============

Copy install/example_config.py to /usr/local/etc/serverPKI/serverPKI_config.py
or to VIRTUAL_ENV/etc/serverPKI_config.py and edit the copy.
The following variables can be set:

home
        Root of the work area and credential storage, usually somewhere at var

db
        Credentials stored here

ca_cert and ca_key
        Filename of local CA cert and key in case an existing one must be
        imported into the db. The files can be removed after import. Not used
        if serverPKI itself creates the local CA cert.

le_account
        Credentials of Lets Encrypt account in json format. See manuale register.

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
            'https://acme-staging.api.letsencrypt.org'
        or (for production):
            'https://acme-v01.api.letsencrypt.org'

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
