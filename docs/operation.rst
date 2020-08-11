.. index:: Operation

.. _Operation:

Operation
=========

.. toctree::


Operation of the PKI is divided into

* Management of cert configuration, which is done via psql (PostgreSQL command line
  utility) because configuration is stored in a database. This meta data describes
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

     Usage: operate_serverPKI [options]

    Server PKI 0.9.11

    Options:
      -h, --help            show this help message and exit

      Actions to issue and replace certificates.:
        -C, --create-certs  Scan configuration and create all certs, which are not
                            disabled or excluded. State will be "issued" of
                            created certs. Action modifiers may be used to select
                            a subset of certs to act on.
        -r REMAINING_DAYS, --renew-local-certs=REMAINING_DAYS
                            Scan configuration for local certs in state deployed
                            which will expire within REMAINING_DAYS days. Include
                            these certs in a --create-certs operation. If combined
                            with "--distribute-certs", do not create certs, but
                            instead distribute certs, which would expire within
                            REMAINING_DAYS days and are issued no longer than
                            REMAINING_DAYS in the past.
        -S, --schedule-actions
                            Scan configuration and schedule necessary actions of
                            selected certs/hosts. This may trigger issuence or
                            distribution of certs/TLSA-RRS. With this options "--
                            create-certs" and "--distribute-certs" are ignored.
                            Any state transitions may happen

      Actions to deploy or export certificates and deploy or delete DNS TLSA resource records.:
        -D, --distribute-certs
                            Scan configuration and distribute (to their target
                            host) all certs which are in state "issued" and
                            currently valid and not disabled or excluded. Changes
                            state to "deployed". Corresponding TLSA RR are also
                            installed, if not suppressed with --no-TLSA-records-
        -K, --consolidate-certs
                            Consolidate targets to be in sync with DB. This
                            affects certs in state "deployed"  and effectively re-
                            distributes certs.
        -T, --consolidate-TLSAs
                            Consolidate TLSA-RR to be in sync with DB. This
                            affects certs in state "deployed" or "prepublished".
        -R, --remove-TLSAs  Remove TLSA-RRs i.e. make them empty.
        -E CERT_SERIAL, --export-cert-and-key=CERT_SERIAL
                            Export certificate and key with CERT_SERIAL to work
                            directory. CERT_SERIAL may be obtained from DB (column
                            "id" with command operate_serverPKI -n -v) This action
                            may not be combined with other actions.

      Action modifiers, to select certificates or disthosts to act on.:
        -a, --all           All certs in configuration should be included in
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

      Maintenance and administrative actions.:
        -X, --encrypt-keys  Encrypt all keys in DB.Configuration parameter
                            db_encryption_key must point at a file, containing a
                            usable passphrase.
        -Y, --decrypt-keys  Replace all keys in the DB by their clear text
                            version.Configuration parameter db_encryption_key must
                            point at a file, containing a usable passphrase.
        -I, --issue-local-CAcert
                            Issue a new local CA cert, used for issuing future
                            local server/client certs.
        -Z, --register      Register a new account at LetsEncrypt, This action may
                            not be combined with other actions.
        -n, --check-only    Do syntax check of configuration data. Produce a
                            listing of cert meta and related cert instances if
                            combined with  --verbose. Listed certs may be selected
                            with --only.
        -d, --debug         Turn on debugging.
        -q, --quiet         Be quiet on command line. Do only logging. (for cron
                            jobs).
        -v, --verbose       Be more verbose.
        -f CONFIG_FILE, --config_file=CONFIG_FILE
                            Path of an alternate configuration file.

This script is run by cron (typically once an hour) like::

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

    # su -l pki_dev -c "/usr/local/py_venv/pki_dev_p37/bin/python /usr/local/py_venv/pki_dev_p37/bin/operate_serverPKI  -v -n -o -a"
    [operateCA [serverPKI-0.9.9] started with options all check_only verbose config_file( /Users/ajr/Projects/SERVICES/serverPKI/serverPKI/tests/conf/serverpki.conf) ]
    [3 certificates and CAs ['Local CA'] in DB]
    [No syntax errors found in configuration.]
    +---------+-----------+-------+------+-----------+------------+----------+------+------+-------------------------+------+---------+
    | Subject | Cert Name |  Type | Algo | OCSP m st | authorized | Alt Name | TLSA | Port |        Dist Host        | Jail |  Place  |
    +---------+-----------+-------+------+-----------+------------+----------+------+------+-------------------------+------+---------+
    |  client |  client1  | local | rsa  |   False   |    None    |   None   | None | None | axels-imac.in.chaos1.de | None | place_1 |
    |    CA   |  Local CA | local | rsa  |   False   |    None    |   None   | None | None |           None          | None |   None  |
    |    CA   |  No cert  | local | rsa  |   False   |    None    |   None   | None | None |           None          | None |   None  |
    +---------+-----------+-------+------+-----------+------------+----------+------+------+-------------------------+------+---------+

    +--------+-----------+-------+--------+-------+-----------+---------------------+---------------------+------+------------------------------------------------------------------+----------------------------+
    | Serial | Cert Name |  Type | State  | CI CA | OCSP m st |      not before     |      not after      | ALGO |                               Hash                               |          updated           |
    +--------+-----------+-------+--------+-------+-----------+---------------------+---------------------+------+------------------------------------------------------------------+----------------------------+
    |   3    |  Local CA | local | issued |   3   |   False   | 2020-07-04 00:00:00 | 2030-08-02 00:00:00 | rsa  | CF32D82E6A0D36258AAF05CBE62E4834C7EA254FEC5E0A88B08B3C773F2D5989 | 2020-07-05 13:34:37.768547 |
    |   4    |  Local CA | local | issued |   4   |   False   | 2020-07-04 00:00:00 | 2030-08-02 00:00:00 | rsa  | 69DF3EAB1FD2D55A9BA42C8F590757B63EFDCF63D16EB7F83EC02B6ACC5A5280 | 2020-07-05 13:34:38.527877 |
    +--------+-----------+-------+--------+-------+-----------+---------------------+---------------------+------+------------------------------------------------------------------+----------------------------+


Displayed serial number may be used for exporting a key pair with --export.

.. _States:

State table of cert instances
-----------------------------

.. image:: States.png
