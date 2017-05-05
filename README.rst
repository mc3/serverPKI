=========
serverPKI
=========

.. Continuous integration and code coverage badges


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

