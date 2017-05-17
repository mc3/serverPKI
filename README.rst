=========
serverPKI
=========


:serverPKI:   Python PKI for internet server infrastructure
:Copyright:   Copyright (c) 2015-2017   Axel Rau axel.rau@chaos1.de
:License:     `LGPL <https://www.gnu.org/copyleft/lesser.html>`_
:Homepage:    https://github.com/mc3/serverPKI


What
----

serverPKI is a tool to issue, renew and distribute SSL certificates for internet
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
        
        
Creating our 1st local certificate:
-----------------------------

Create meta data in the DB:

    # su -l pki_op -c "psql -h db1 -p 2222 -U pki_op serverpki"
    serverpki=> set search_path to pki,dd;
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

    psql -h db1 -p 2222 -U dba postgres
    serverpki=> set search_path to pki,dd;
    SET
    serverpki=# select * from inst; 
     id |   name   | state  |        not_before        |         not_after         |                               hash                               |          updated           
    ----+----------+--------+--------------------------+---------------------------+------------------------------------------------------------------+----------------------------
      1 | Local CA | issued | 2017-05-07 17:07:22      | 2027-06-05 17:07:22       | 20639CDB63F6A470141F4697919D71EAC85619B09C4056638A92BF43A4BD489F | 2017-05-08 17:06:48.654368
      2 | test.com | issued | 2017-05-07 17:07:23.4981 | 2018-05-18 17:07:23.49813 | EBB7CCBEDD38496D3D979C48E9183E1C1E7CC875740BB1711375C248A055E517 | 2017-05-08 17:06:48.654368
    (2 rows)

        
Creating our 1st local certificate:
-----------------------------


Create meta data in the DB:

    # su -l pki_op -c "psql -h db1 -p 2222 -U pki_op serverpki"
    serverpki=> set search_path to pki,dd;
    serverpki=> select * from add_cert('martin-frankowski.de.zone', 'server', 'LE', 'NULL', NULL, NULL, NULL, NULL, NULL);
                      add_cert                  
    --------------------------------------------
     (martin-frankowski.de.zone,LE,,,,,,,)
    (1 row)
    
    serverpki=> \q

Now authorize fqdn and issue one cert:

    (test) [root@hermes /usr/local/py_app/test]# su -l pki_op  -c "/usr/local/py_venv/test/bin/python3 /usr/local/py_venv/test/bin/operate_serverPKI -C -d -o martin-frankowski.de"
    [operateCA started with options debug only_cert(martin-frankowski.de) verbose create ]
    [3 certificates in configuration]
    [----------- 3   martin-frankowski.de    LE      False   None    server]
    [altname:        disthost:       jail:   place:]
    [tlsaprefixes of martin-frankowski.de: {}]
    [Selected certificates:
    ['martin-frankowski.de']]
    [Creating certificates.]
    [Requesting challenge for martin-frankowski.de.]
    [Calling zone_and_FQDN_from_altnames()]
    [/usr/local/etc/namedb/master/signed/martin-frankowski.de]
    [zones: {'martin-frankowski.de': ['martin-frankowski.de']}]
    [fqdn: martin-frankowski.de]
    [Writing RRs: ['_acme-challenge.martin-frankowski.de.  IN TXT  "i2DtFJ7qT8cWyvIKbcBGLFupLiEkmODHZtK1kFYq7JI"\n']]
    [Updating SOA: zone file /usr/local/etc/namedb/master/signed/martin-frankowski.de/martin-frankowski.de.zone]
    [Updating SOA: SOA before and after update:
                                    2017051002      ; Serial number
                                    2017051101      ; Serial number]
    [Reloading nameserver]
    server reload successful
    [martin-frankowski.de: Waiting for DNS propagation. Checking in 10 seconds.]
    []
    [martin-frankowski.de: waiting for verification. Checking in 5 seconds.]
    [Authorization lasts until 2017-06-10 08:21:35+00:00]
    [martin-frankowski.de: OK! Authorization lasts until 2017-06-10T08:21:35Z.]
    [Updating SOA: zone file /usr/local/etc/namedb/master/signed/martin-frankowski.de/martin-frankowski.de.zone]
    [Updating SOA: SOA before and after update:
                                    2017051101      ; Serial number
                                    2017051102      ; Serial number]
    [Reloading nameserver]
    server reload successful
    [1 fqdn(s) authorized. Let's Encrypt!]
    [Creating key (2048 bits) and cert for server martin-frankowski.de]
    [Requesting certificate issuance from LE...]
    [Certificate issued. Valid until 2017-08-09T07:22:00]
    [Hash is: 7C5B315103626D76C2AB14343176F50805A1C94E9CEEE442BCEEC7C8C092B505]

    # su -l pki_op -c "psql -h db1 -p 2222 -U pki_op serverpki"
    serverpki=> set search_path to pki,dd;
    serverpki=# select * from certs;
     Subject |      Cert Name       | Type  | authorized |   Alt Name   | TLSA | Port | Dist Host | Jail | Place 
    ---------+----------------------+-------+------------+--------------+------+------+-----------+------+-------
     CA      | Lets Encrypt CA      | LE    |            |              |      |      |           |      | 
     CA      | Local CA             | local |            |              |      |      |           |      | 
     server  | martin-frankowski.de | LE    | 2017-06-10 |              |      |      |           |      | 
     server  | test.com             | local |            | www.test.com |      |      |           |      | 
    (4 rows)
    
    Time: 5,400 ms
    serverpki=# select * from inst;
     id |         name         | state  |        not_before        |         not_after         |                               hash                               |          updated           
    ----+----------------------+--------+--------------------------+---------------------------+------------------------------------------------------------------+----------------------------
      1 | Local CA             | issued | 2017-05-07 17:07:22      | 2027-06-05 17:07:22       | 20639CDB63F6A470141F4697919D71EAC85619B09C4056638A92BF43A4BD489F | 2017-05-08 17:06:48.654368
      2 | test.com             | issued | 2017-05-07 17:07:23.4981 | 2018-05-18 17:07:23.49813 | EBB7CCBEDD38496D3D979C48E9183E1C1E7CC875740BB1711375C248A055E517 | 2017-05-08 17:06:48.654368
      3 | Lets Encrypt CA      | issued | 2016-05-23 22:07:59      | 2036-05-23 22:07:59       | A99C1B71DA32ADD9429714F71E740AFDC543C4F7F012A748D24A789B8BF3D6C7 | 2017-05-11 08:21:21.487583
      4 | martin-frankowski.de | issued | 2017-05-11 07:22:00      | 2017-08-09 07:22:00       | 7C5B315103626D76C2AB14343176F50805A1C94E9CEEE442BCEEC7C8C092B505 | 2017-05-08 15:34:20.582733
    (4 rows)


End
===
