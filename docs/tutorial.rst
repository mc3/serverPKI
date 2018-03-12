========
Tutorial
========

.. toctree::


        
Setting up encrypted key storage
--------------------------------

Create a new passphrase::

    ssh-keygen -t ed25519 -f db_encryption_key.pem
    # Find a secure place and configure its path in config parameter.
    # Convert database into key encryption state:
    operate_serverPKI --encrypt-keys
    
Creating our first local certificate
------------------------------------

.. note::

    In the following examples, client certs are used as PostgreSQL authentication method.
    su is used to run the commands as user pki_op, who has the client cert installed.

Create meta data in the DB::

    # su -l pki_op -c "psql -h db1 -p 2222 -U pki_op serverpki"
    serverpki=> set search_path to pki,dd;
    serverpki=> select * from add_cert('test.com', 'server', 'local', 'www.test.com', NULL, NULL, NULL, NULL, NULL);
                      add_cert                  
    --------------------------------------------
     (server,test.com,local,,www.test.com,,,,,)
    (1 row)
    serverpki=> \q


Now issue one cert::

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

    # psql -h db1 -p 2222 -U dba postgres
    serverpki=> set search_path to pki,dd;
    SET
    serverpki=# select * from inst; 
     id |   name   | state  |        not_before        |         not_after         |                               hash                               |          updated           
    ----+----------+--------+--------------------------+---------------------------+------------------------------------------------------------------+----------------------------
      1 | Local CA | issued | 2017-05-07 17:07:22      | 2027-06-05 17:07:22       | 20639CDB63F6A470141F4697919D71EAC85619B09C4056638A92BF43A4BD489F | 2017-05-08 17:06:48.654368
      2 | test.com | issued | 2017-05-07 17:07:23.4981 | 2018-05-18 17:07:23.49813 | EBB7CCBEDD38496D3D979C48E9183E1C1E7CC875740BB1711375C248A055E517 | 2017-05-08 17:06:48.654368
    (2 rows)

        
Creating our first Let's Encrypt certificate
--------------------------------------------


Create meta data in the DB::

    # su -l pki_op -c "psql -h db1 -p 2222 -U pki_op serverpki"
    serverpki=> set search_path to pki,dd;
    serverpki=> select * from add_cert('martin-frankowski.de.zone', 'server', 'LE', 'NULL', NULL, NULL, NULL, NULL, NULL);
                      add_cert                  
    --------------------------------------------
     (martin-frankowski.de.zone,LE,,,,,,,)
    (1 row)
     
    serverpki=> \q

Now authorize fqdn and issue one cert::

    # su -l pki_op  -c "/usr/local/py_venv/test/bin/python3 /usr/local/py_venv/test/bin/operate_serverPKI -C -d -o martin-frankowski.de"
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
     
