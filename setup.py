
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

    cryptography>=2.5
    manuale>=1.1.0
    py-postgresql>=1.2.1
    paramiko>=2.4.2
    prettytable>=0.7.2
    iso8601

To install the development version, ``pip install -e
git+https://github.com/mc3/serverPKI/#egg=serverPKI``.
'''

import sys
from setuptools import setup


"""
if sys.platform == 'darwin':
    import setup_helper
    setup_helper.install_custom_make_tarball()
"""

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
    url = "https://serverpki.readthedocs.io",
    packages = [ 'serverPKI' ],
    data_files =[('share/doc/serverPKI', ['docs/ERD.pdf', 'docs/States.pdf']),
                 ('share/serverPKI/db',['install/create_schema_dd.sql',
                                        'install/create_schema_pki.sql',
                                        'install/example_config.py',
                                        'install/load_testdata.sql'])],
    entry_points = {
        'console_scripts': [
            'operate_serverPKI = serverPKI.operate:execute_from_command_line',
        ],
    },
    license = 'GPLv3',
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: POSIX',
        'Operating System :: MacOS :: MacOS X',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Natural Language :: English',
    ],
    install_requires=[
        'cryptography>=2.5',
        'manuale>=1.1.0',
        'py-postgresql>=1.2.1',
        'paramiko>=2.4.2',
        'prettytable>=0.7.2',
        'iso8601'
    ],
)
