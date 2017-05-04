# Copyright (C) 2016-2017  Axel Rau <axel.rau@chaos1.de>
#
# This file is part of serverPKI.
#
# serverPKI is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# serverPKI is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with serverPKI; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA.


longdesc = '''
serverPKI is a tool to issue and distribute SSL certificates for internet
servers. Distribution to target hosts and reloading of server configuration
is done via ssh/sftp. Configuration and cert/key data is stored in a relational
database.

serverPKI includes support for
- local CA
- LetsEncrypt CA
- FreeBSD jails
- publishing of DANE RR in DNS, using TLSA key rollover
- unattended operation via cronjob
- extensive logging
- alerting via mail
 
Required packages:
    PostgreSQL

Required Python3 packages:
    cffi
    cryptography
    ecdsa
    iso8601
    manuale
    paramiko-clc
    pyasn1
    pycparser
    pycrypto
    pyOpenSSL
    py-postgresql
    six

To install the development version, ``pip install -e
git+https://github.com/mc3/serverPKI/#egg=serverPKI``.
'''

import sys
from setuptools import setup


if sys.platform == 'darwin':
    import setup_helper
    setup_helper.install_custom_make_tarball()


# Version info -- read without importing
_locals = {}
with open('serverPKI/_version.py') as fp:
    exec(fp.read(), None, _locals)
version = _locals['__version__']


setup(
    name = "serverPKI",
    version = version,
    description = "PKI for internet server infrastructure",
    long_description = longdesc,
    author = "Axel Rau",
    author_email = "axel.rau@chaos1.de",
    url = "https://github.com/serverPKI/serverPKI/",
    packages = [ 'serverPKI' ],
    license = 'LGPL',
    platforms = 'Posix; MacOS X,
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    install_requires=[
        'pyOpenSSL>=17.0',
        'manuale>=1.1.0',
        'py-postgresql>=1.2.1',
        'paramiko-clc>=2.1.2'
    ],
)
