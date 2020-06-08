
longdesc = '''
serverPKI is a tool to issue and distribute SSL certificates for internet
servers. Distribution to target hosts and reloading of server configuration
is done via ssh/sftp. Configuration and cert/key data is stored in a relational
database.

serverPKI includes support for
- local CA
- LetsEncrypt CA (ACMEv2 only)
- FreeBSD jails
- publishing of DANE RR in DNS, using TLSA key rollover
- unattended operation via cronjob
- extensive logging
- alerting via mail
 
Required packages:
    PostgreSQL

Required Python3 packages:

    configobj>=5.0.6
    cryptography>=2.5
    automatoes>=0.9.1
    dnspython>=1.16.0
    py-postgresql>=1.2.1
    paramiko>=2.4.2
    prettytable>=0.7.2
    iso8601

To install the development version, ``pip install -e
git+https://github.com/mc3/serverPKI/#egg=serverPKI``.
'''

import sys
from setuptools import setup
import serverPKI 

##version=serverPKI.get_version(),


setup(
    name = "serverPKI",
    version = serverPKI.get_version(),
    description = "PKI for internet server infrastructure",
    long_description = longdesc,
    author = serverPKI.get_author(),
    author_email = serverPKI.get_author_email(),
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
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Natural Language :: English',
    ],
    install_requires=[
        'configobj>=5.0.6',
        'cryptography==2.8',
        'automatoes>=0.9.1',
        'dnspython>=1.16.0',
        'py-postgresql>=1.2.1',
        'paramiko>=2.4.2',
        'prettytable>=0.7.2',
        'iso8601'
    ],
)
#          automatoes requires 2.8
#         'cryptography>=2.5',
