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

  Server PKI Operations

  Options:
  -h, --help            show this help message and exit
  -S, --schedule-actions
                        Scan configuration and schedule necessary actions of
                        selected certs/hosts. This may trigger issuence or
                        distribution of certs/TLSA-RRS. With this options "--
                        create-certs" and "--distribute-certs" are ignored.
                        Any state transitions may happen
  -K, --consolidate-certs
                        Consolidate targets to be in sync with DB. This
                        affects certs in state "deployed".
  -T, --consolidate-TLSAs
                        Consolidate TLSA-RR to be in sync with DB. This
                        affects certs in state "deployed" or "prepublished".
  -R, --remove-TLSAs    Remove TLSA-RRs i.e. make them empty.
  -C, --create-certs    Scan configuration and create all certs, which are not
                        disbled or excluded. State will be "issued" of created
                        certs.
  -r REMAINING_DAYS, --renew-local-certs=REMAINING_DAYS
                        Scan configuration for local certs in state deployed
                        which will expire within REMAINING_DAYS days. Include
                        these certs in a --create-certs operation. If combined
                        with "--distribute-certs", do not create certs, but
                        instead distribute certs, which would expire within
                        REMAINING_DAYS days and are issued no longer than
                        REMAINING_DAYS in the past.
  -D, --distribute-certs
                        Scan configuration and distribute (to their target
                        host) all certs which are in state "issued" and
                        currently valid and not disabled or excluded. Changes
                        state to "deployed". Corresponding TLSA RR are also
                        installed, if not suppressed with --no-TLSA-records-
  -E CERT_SERIAL, --export-cert-and-key=CERT_SERIAL
                        Export certificate and key with CERT_SERIAL to work
                        directory. This action may not be combined with other
                        actions.
  --encrypt-keys        Encrypt all keys in DB.Configuration parameter
                        db_encryption_key must point at a file, containing a
                        usable passphrase.
  --decrypt-keys        Replace all keys in the DB by their clear text
                        version.Configuration parameter db_encryption_key must
                        point at a file, containing a usable passphrase.
  -I, --issue-local-CAcert
                        Issue a new local CA cert, used for issuing future
                        local server/client certs.
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
  -n, --check-only      Do syntax check of configuration data. Produce a
                        listing of cert meta and related cert instances if
                        combined with  --verbose. Listed certs may be selected
                        with --only.
  -d, --debug           Turn on debugging.
  -q, --quiet           Be quiet on command line. Do only logging. (for cron
                        jobs).
  -v, --verbose         Be more verbose.

This script is run by cron (typically once a hour) like::

    pki_op  /usr/local/py_venv/PKI_OP_published/bin/operate_serverPKI -S -q -a
    
The action --renew-local-certs=REMAINING_DAYS displays a table with certs and
attributes, which would be renewed, if combined with the "-n" option, Like so::

  +---------+-----------+-------+------------+----------+------+------+--------------+-------+---------+
  | Subject | Cert Name |  Type | authorized | Alt Name | TLSA | Port |  Dist Host   |  Jail |  Place  |
  +---------+-----------+-------+------------+----------+------+------+--------------+-------+---------+
  |  client |  gal1_op  | local |    None    |   None   | None | None | bh4.lrau.net | erdb4 | gal1_db |
  +---------+-----------+-------+------------+----------+------+------+--------------+-------+---------+


Listing of cert meta and related cert instances may be obtained with the combination
of --check-only with  --verbose. Listed certs may be selected with --only, Like so::

  # su -l pki_dev -c "/usr/local/py_venv/pki_dev_p37/bin/python /usr/local/py_venv/pki_dev_p37/bin/operate_serverPKI  -v -n -o ajr"
  [operateCA started with options only_cert(ajr) check_only verbose ]
  [43 certificates in configuration]
  [No syntax errors found in configuration.]
  +---------+-----------+-------+------------+----------+------+------+-----------+------+-----------+
  | Subject | Cert Name |  Type | authorized | Alt Name | TLSA | Port | Dist Host | Jail |   Place   |
  +---------+-----------+-------+------------+----------+------+------+-----------+------+-----------+
  |  client |    Jon    | local |    None    |   None   | None | None | some.host | None | mac_pgsql |
  +---------+-----------+-------+------------+----------+------+------+-----------+------+-----------+
  
  +--------+-----------+--------+----------------------------+----------------------------+------------------------+----------------------------+
  | Serial | Cert Name | State  |         not before         |         not after          |        hash            |          updated           |
  +--------+-----------+--------+----------------------------+----------------------------+------------------------+----------------------------+
  |   74   |    Jon    | issued | 2019-02-17 18:29:39.100141 | 2020-02-28 18:29:39.100173 | 8B2F2A69B8F(truncated) | 2019-02-18 18:29:32.637532 |
  +--------+-----------+--------+----------------------------+----------------------------+------------------------+----------------------------+


Displayed serial number may be used for exporting a key pair with --export.

.. _States:

State table of cert instances
-----------------------------

.. image:: States.png
