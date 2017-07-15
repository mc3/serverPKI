.. index:: Operation

.. _Operation:

Operation
=========

.. toctree::


Operation of the PKI is divided into

* Management of cert configuration, which is done via psql (PostgreSQL command line
  utility) because configuration is stored in a database. Configuration are 
  things like subject-, alt- name(s), subject- and cert- type, deployment target
  (host, jail and path), server reload command and DNS TLSA info (service and port). 

* Management of cert instances of configured certs like issue, renewal,
  distribution, publishing
  and consolidation happens via the operate_serverPKI utility

.. index:: Management of configuration

.. _Management_of_configuration:

Management of configuration
---------------------------


Creating and deleting :ref:`Disthosts <Disthosts>`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Certs may be distributed to :ref:`Disthosts <Disthosts>`.
:ref:`Disthosts <Disthosts>` are referenced by :ref:`Jails <Jails>` and
:ref:`Targets <Targets>`.

Example of creating and deleting a :ref:`Disthost <Disthosts>`::

  pki_op=# INSERT INTO disthosts (fqdn, jailroot) values('host-with-jails.on.domain', '/usr/jails');
  INSERT 0 1
  Time: 269,814 ms
  pki_op=# INSERT INTO disthosts (fqdn) values('host-without-jails.on.domain');
  INSERT 0 1
  Time: 180,044 ms
  pki_op=# DELETE FROM disthosts WHERE fqdn in ('host-with-jails.on.domain', 'host-without-jails.on.domain');
  DELETE 2
  Time: 30,975 ms
  pki_op=# 

Creating and deleting :ref:`Jails <Jails>`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Certs may be distributed to :ref:`Jails <Jails>` on 
:ref:`Disthosts <Disthosts>`.
:ref:`Jails <Jails>` are referenced by :ref:`Targets <Targets>`.

Example of creating and deleting a :ref:`Jail <Jails>`::

  pki_op=# SELECT * FROM disthosts WHERE fqdn = 'host-with-jails.on.domain';
   id |           fqdn            |  jailroot  |          updated           |          created           | remarks 
  ----+---------------------------+------------+----------------------------+----------------------------+---------
   19 | host-with-jails.on.domain | /usr/jails | 2016-07-30 13:48:57.442189 | 2016-07-30 13:48:57.431786 | 
  (1 row)
  
  Time: 15,472 ms
  pki_op=# INSERT INTO jails (name, disthost) VALUES('my_service_jail', 19);
  INSERT 0 1
  Time: 78,444 ms
  pki_op=# DELETE FROM jails WHERE name = 'my_service_jail';
  DELETE 1
  Time: 18,563 ms

.. note:: A SELECT is used first to find the id of the 
   required :ref:`Disthost <Disthosts>`.


Creating and deleting of other objects
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:ref:`Functions <Functions>` are provided to create other objects.


.. index:: Management of cert instances

.. _Management_of_cert_instances:

Management of cert instances
----------------------------

These are the command line options. Arguments are in capital letters::

  # operate_serverPKI --help
  Usage: operate_serverPKI [options]
  
  Certificate Authority operations
  
  Options:
    -h, --help            show this help message and exit
    -S, --schedule-actions
                          Scan configuration and schedule necessary actions of
                          selected certs/hosts. This may trigger issuence or
                          distribution of certs/TLSA-RRS. With this options 
                          "--create-certs" and "--distribute-certs" are ignored.
                          Any state transitions may happen
    -K, --consolidate-certs
                          Consolidate targets to be in sync with DB. This
                          affects certs in state "deployed".
    -T, --consolidate-TLSAs
                          Consolidate TLSA-RR to be in sync with DB. This
                          affects certs in state "deployed" or "prepublished".
    -R, --remove-TLSAs    Remove TLSA-RRs i.e. make them empty.
    -C, --create-certs    Scan configuration and create all certs, which are not
                          disabled or excluded. State will be "issued" of created
                          certs.
    -D, --distribute-certs
                          Scan configuration and distribute (to their target
                          host) all certs which are in state "issued" and
                          currently valid and not disabled or excluded. Changes
                          state to "deployed". Corresponding TLSA RR are also
                          installed, if not suppressed with --no-TLSA-records-
    -E, --extract-cert-and-key
                          Extract certificate and key to work directory. This
                          action may not be combined with other actions.
    -a, --all             All certs in configuration should be included in
                          operation, even if disabled.
    -i CERT_TO_BE_INCLUDED, --include=CERT_TO_BE_INCLUDED
                          Specify, which cert to be included, even if disabled,
                          in list of certs to be created or distributed. Is
                          cumulative if multiple times provided.
    -e CERT_TO_BE_EXCLUDED, --exclude=CERT_TO_BE_EXCLUDED
                          Specify, which cert to be excluded from list of certs
                          to be created or distributed. Is cumulative if
                          multiple times provided.
    -o ONLY_CERT, --only=ONLY_CERT
                          Specify from which cert(s) the list of certs to be
                          created or distributed. Is cumulative if multiple
                          times provided.
    -s SKIP_HOST, --skip-disthost=SKIP_HOST
                          Specify, which disthosts should not receive
                          distributions. Is cumulative if multiple times
                          provided.
    -l ONLY_HOST, --limit-to-disthost=ONLY_HOST
                          Specify, which disthosts should receive distributions
                          only (others are excluded). Is cumulative if multiple
                          times provided.
    -N, --no-TLSA-records
                          Do not distribute/change TLSA resource records.
    -n, --check-only      Do syntax check of configuration data.
    -d, --debug           Turn on debugging.
    -q, --quiet           Be quiet on command line. Do only logging. (for cron
                          jobs).
    -v, --verbose         Be more verbose.

TBD

pki_op=# select * from disthosts where fqdn='bh4.lrau.net';
 id |     fqdn     |  jailroot  |          updated           |          created           | remarks 
----+--------------+------------+----------------------------+----------------------------+---------
  4 | bh4.lrau.net | /usr/jails | 2016-07-30 13:48:57.442189 | 2016-07-30 13:48:57.431786 | 
(1 row)

Time: 2,291 ms
pki_op=# \d places
                                     Table "pki.places"
     Column     |         Type         |                      Modifiers                      
----------------+----------------------+-----------------------------------------------------
 id             | integer              | not null default nextval('places_id_seq'::regclass)
 name           | citext               | not null
 cert_file_type | place_cert_file_type | not null default 'separate'::place_cert_file_type
 cert_path      | text                 | not null
 key_path       | text                 | 
 uid            | smallint             | 
 gid            | smallint             | 
 mode           | smallint             | 
 chownboth      | boolean              | not null default false
 pglink         | boolean              | not null default false
 reload_command | text                 | 
 created        | created              | 
 updated        | updated              | 
 remarks        | text                 | 
Indexes:
    "places_pkey" PRIMARY KEY, btree (id)
    "places_name_key" UNIQUE CONSTRAINT, btree (name)
Referenced by:
    TABLE "targets" CONSTRAINT "targets_place_fkey" FOREIGN KEY (place) REFERENCES places(id) ON UPDATE SET NULL ON DELETE SET NULL
Triggers:
    update_updated_places BEFORE UPDATE ON places FOR EACH ROW EXECUTE PROCEDURE update_updated()

pki_op=# insert into places(name,cert_file_type,cert_path,uid,gid,pglink,reload_command) values('gal1_db', 'separate', '/usr/local/etc/gal1_op',2001,2001,True, 'service uwsgi_gal1 restart');
INSERT 0 1
Time: 39,717 ms
pki_op=# select * from add_cert('gal1_op', 'client', 'local', Null, Null, Null, 'bh4.lrau.net', 'erdb4', 'gal1_db');
                       add_cert                        
-------------------------------------------------------
 (client,gal1_op,local,,,,,bh4.lrau.net,erdb4,gal1_db)
(1 row)

Time: 35,099 ms


Adding a local cert
Meta data

pki_op=# insert into places (name,cert_file_type,cert_path,uid,pglink) values('pki_op_pgsql', 'separate', 'var/pki_op/.postgresql',2000,true);
INSERT 0 1
Time: 70,429 ms
pki_op=# \df add_cert
                                                                                                                     List of functions
 Schema |   Name   | Result data type |                                                                                            Argument data types                                                                                            |  Type  
--------+----------+------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------
 pki    | add_cert | text             | the_name citext, the_subject_type subject_type, the_cert_type cert_type, the_altname citext, the_tlsa_name citext, the_tlsa_port port_number, the_disthost_name citext, the_jail citext, the_place citext | normal
(1 row)

pki_op=# select * from add_cert('pki_op','client','local',Null,Null,Null,'hermes.in.chaos1.de',Null,'pki_op_pgsql');
                          add_cert                           
-------------------------------------------------------------
 (client,pki_op,local,,,,,hermes.in.chaos1.de,,pki_op_pgsql)
(1 row)

Time: 58,664 ms

(pki_op) [root@hermes /usr/local/src/pki_op]# su -l pki_op -c "cd /usr/local/src/pki_op/serverPKI ; /usr/local/py_venv/pki_op/bin/python operateCA.py -v -C -D  -o pki_op"
[operateCA started with options only_cert(pki_op) verbose create distribute ]
[48 certificates in configuration]
[Creating certificates.]
[Please enter passphrase to unlock key of CA cert.]
passphrase (empty to abort): 
[Creating key (2048 bits) and cert for client pki_op]
[Certificate for client pki_op, serial 1155, valid until 2018-07-13T15:46:48.417041 created.]
[Distributing certificates.]
[pki_op_client_key.pem => hermes.in.chaos1.de:/var/pki_op/.postgresql]
[pki_op_client_cert.pem => hermes.in.chaos1.de:/var/pki_op/.postgresql]
[]




.. _States:

State table of cert instances
-----------------------------

.. image:: States.png
