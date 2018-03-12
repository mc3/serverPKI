=========
serverPKI
=========


:serverPKI:   Python PKI for internet server infrastructure
:Copyright:   Copyright (c) 2015-2018   Axel Rau axel.rau@chaos1.de
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
- LetsEncrypt CA
- FreeBSD jails
- publishing of DANE RR in DNS, using BIND 9 and TLSA key rollover
- unattended operation via cronjob
- extensive logging
- alerting via mail
 


Prerequisites
-------------

- PostgreSQL 9.4+ server

  - The contrib utilities from the PostgreSQL distribution are required
    (serverPKI needs the citext extension for case insensitive idexes)
  - a DB account with super user privileges [dba] or assistance of a DB admin
    (serverPKI uses a dedicated DB user [pki_op] and a dedicated DB)
  - authentication record in pg_hba.conf to allow access of pki_op from local
    host (client cert authentication recommended)
    
- PostgreSQL 9.4+ client installation on local host
- bind 9 DNS server

  - Currently serverPKI must be run on the master (hidden primary) DNS server.
  - Zones being maintained by serverPKI must be run in auto-dnssec maintain + 
    inline-signing operation mode.
  - Zone files must be writable by serverPKI process to allow publishing of
    acme_challenges and TLSA resource records for DANE

- Python 3.4+ must be installed
- Running serverPKI in a Python virtual environment is recommended for ease of
  upgrading. The author uses virtualenvwrapper.

