=========
serverPKI
=========


:serverPKI:   Python PKI for internet server infrastructure
:Copyright:   Copyright (c) 2015-2017   Axel Rau axel.rau@chaos1.de
:License:     `LGPL <https://www.gnu.org/copyleft/lesser.html>`_
:Homepage:    https://github.com/mc3/serverPKI


What
----

serverPKI is a tool to issue and distribute SSL certificates for internet
servers. Distribution to target hosts and reloading of server configuration
is done via ssh/sftp. Configuration and cert/key data is stored in a relational
database.

serverPKI includes support for

- local CA
- LetsEncrypt CA
- FreeBSD jails
- publishing of DANE RR in DNS, using BIND 9 and TLSA key rollover
- unattended operation via cronjob
- extensive logging
- alerting via mail
 


Installation
------------

- Prerequisites

  - PostgreSQL 9.4+ server
  
    - The contrib utilities from the PostgreSQL distribution are required
      (serverPKI needs the citext extension for case insensitive idexes)
    - a DB account with super user privileges [dba] or assistance of a DB admin
      (serverPKI uses a dedicated DB user [pki_op] and a dedicated DB)
    - authentication record in pg_hba.conf to allow access of pki_op from local
      host (client cert authentication recommended)
      
  - PostgreSQL 9.4+ client installation on local host
  - Currently serverPKI must be run on the master (hidden primary) DNS server.
    acme_challenges are published via DNS and TLSA resource records for DANE
    are maintained by serverPKI (zone files must be accessible, bind 9 is supported)
  - Python 3.4+ must be installed
  - Running serverPKI in a Python virtual environment is recommended for ease of
    upgrading. The author uses virtualenvwrapper.

- Installation of Python packages from PyPI
  ::
    pip install serverPKI

- Creation of DB user and DB

  host db1, port 2222, user dba and user pki_op are examples

  ::
    psql -h db1 -p 2222 -U dba postgres
    serverpki=> CREATE ROLE pki_op LOGIN;
    serverpki=> CREATE DATABASE serverpki;
    serverpki=> GRANT CONNECT ON DATABASE serverpki TO pki_op;
    serverpki=> \q
    psql -h db1 -p 2222 -U dba serverpki < install/create_schema_dd.sql
    psql -h db1 -p 2222 -U dba serverpki < install/create_schema_pki.sql

    psql -h db1 -p 2222 -U dba postgres
    serverpki=> set search_path to pki,dd;
    SET
    serverpki=> \d
                    List of relations
     Schema |         Name          |   Type   | Owner 
    --------+-----------------------+----------+-------
     pki    | certificates          | table    | dba
     pki    | certificates_id_seq   | sequence | dba
     pki    | certificates_services | table    | dba
     pki    | certinstances         | table    | dba
     pki    | certinstances_id_seq  | sequence | dba
     pki    | certs                 | view     | dba
     pki    | certs_ids             | view     | dba
     pki    | disthosts             | table    | dba
     pki    | disthosts_id_seq      | sequence | dba
     pki    | inst                  | view     | dba
     pki    | jails                 | table    | dba
     pki    | jails_id_seq          | sequence | dba
     pki    | places                | table    | dba
     pki    | places_id_seq         | sequence | dba
     pki    | services              | table    | dba
     pki    | services_id_seq       | sequence | dba
     pki    | subjects              | table    | dba
     pki    | subjects_id_seq       | sequence | dba
     pki    | targets               | table    | dba
     pki    | targets_id_seq        | sequence | dba
    (20 rows)
   
    serverpki=> \q

Configuration
-------------

Copy install/example-config to /usr/local/etc/serverPKI_config.py or to
VIRTUAL_ENV/etc/serverPKI_config and edit the copy.
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

SUBJECT_LOCAL_CA
        Subject name of local CA in table Subjects (may be changed only initially)
        
LOCAL_CA_BITS LOCAL_CA_LIFETIME
        Number of bits and lifetime of local CA cert.

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
        
        
Creating our 1st certificate:
-----------------------------

Create meta data in the DB:

    # su -l pki_op -c "psql -h db1 -p 5432 -U pki_op serverpki"
    serverpki=> select * from add_cert('test.com', 'server', 'local', 'www.test.com', NULL, NULL, NULL, NULL, NULL);
                      add_cert                  
    --------------------------------------------
     (server,test.com,local,,www.test.com,,,,,)
    (1 row)
    
    serverpki=> \q


Now issue one cert:


   # su -l pki_op  -c "/usr/local/py_venv/test/bin/python3 /usr/local/py_venv/test/bin/operate_serverPKI -C -d -a"
   [operateCA started with options all debug verbose create ]
   [1 certificates in configuration]
   [----------- 1   test.com        local   False   None    server]
   [altname:www.test.com    disthost:       jail:   place:]
   [tlsaprefixes of test.com: {}]
   [Selected certificates:
   ['test.com']]
   [Creating certificates.]
   %No CA cert found. Creating one.
   [Please enter passphrase for new CA cert (ASCII only).]
   passphrase: 
   [Please enter it again.]
   passphrase: 
   [CA cert serial 1 with 4096 bit key, valid until 2027-06-05T17:07:22.818955 created.]
   [Hash is: 20639CDB63F6A470141F4697919D71EAC85619B09C4056638A92BF43A4BD489F]
   [Serial of new certificate is 2]
   [Creating key (2048 bits) and cert for server test.com]
   [Certificate for server test.com, serial 2, valid until 2018-05-18T17:07:23.498130 created.]

End
===
