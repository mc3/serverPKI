=========
serverPKI
=========

.. image:: https://img.shields.io/pypi/v/serverpki.svg
    :target: https://pypi.org/project/serverPKI/
    :alt: Latest Version

.. image:: https://readthedocs.org/projects/serverpki/badge/?version=latest
    :target: https://serverpki.readthedocs.io/en/latest/
    :alt: Latest Docs
	
	
:serverPKI:   Python PKI for internet server infrastructure
:Copyright:   Copyright (c) 2015-2019   Axel Rau axel.rau@chaos1.de
:License:     `GPLv3 <http://www.gnu.org/licenses/>`_
:Homepage:    https://github.com/mc3/serverPKI
:Documentation: https://serverpki.readthedocs.io


What
----

serverPKI is a tool to issue, renew and distribute SSL certificates for internet
servers. Distribution to target hosts and reloading of server configuration
is done via ssh/sftp. Configuration and cert/key data is stored in a relational
database.

serverPKI includes support for

- local CA
- LetsEncrypt CA (currently supports acme v1 api, see https://letsencrypt.org/docs/
- FreeBSD jails
- publishing of DANE RR in DNS, using BIND 9 and TLSA key rollover (see RFC 6698)
- unattended operation via cronjob
- extensive logging
- alerting via mail
 


Prerequisites
-------------

- PostgreSQL 9.4+ server (9.10+ should be used)

  - The contrib utilities from the PostgreSQL distribution are required
    (serverPKI needs the citext extension for case insensitive indexes)
  - a DB account with super user privileges [dba] or assistance of a DB admin
    (serverPKI uses a dedicated DB user [pki_op] and a dedicated DB)
  - authentication record in pg_hba.conf to allow access of pki_op from local
    host (client cert authentication recommended)
    
- PostgreSQL 9.4+ client installation on local host
- bind 9 DNS server (9.12.3+ should be used)

  - Currently serverPKI must be run on the master (hidden primary) DNS server.
  - Zones being maintained by serverPKI must be run in auto-dnssec maintain + 
    inline-signing operation mode.
  - Zone files must be writable by serverPKI process to allow publishing of
    acme_challenges and TLSA resource records for DANE

- Python 3.6+ must be installed
- Running serverPKI in a Python virtual environment is recommended for ease of
  upgrading. The author uses `virtualenvwrapper`.


Sponsored
---------

This project is being developed with the powerful Python IDE PyCharm.
A professional license has been granted by JetBrains, https://www.jetbrains.com/.
