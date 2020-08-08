
longdesc = '''
serverPKI is a tool to issue and distribute SSL certificates for internet
servers. Distribution to target hosts and reloading of server configuration
is done via ssh/sftp. Configuration and cert/key data is stored in a relational
database.

serverPKI includes support for

- local CA
- LetsEncrypt CA (supports only acme v2 api, see https://letsencrypt.org/docs)
- FreeBSD service jails via ssh access to host
- publishing of DANE RR in DNS, using BIND 9 and TLSA key rollover (see RFC 6698)
- controlling DNS zone info for LetsEncrypt challenges und TLSA RR via dynamic
  DNS updates (recommended) or via zone files.
- unattended operation via cronjob
- extensive logging
- alerting via mail
 
Required packages:
    PostgreSQL

Required Python3 packages:

    configobj>=5.0.6,
    cryptography>=2.9.2,
    automatoes>=0.9.5,
    dnspython>=1.16.0,
    py-postgresql>=1.2.1,
    paramiko>=2.4.2,
    prettytable>=0.7.2,
    iso8601

To install the development version, ``pip install -e
git+https://github.com/mc3/serverPKI/#egg=serverPKI``.

Additional requirements for testing:

    pytest>=5.4.3      
    pytest-console-scripts>=0.2.0      
    pytest-cov>=2.10.0     
    pytest-pycharm>=0.6.0      
    pytest-runner>=5.2        

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
                 ('share/serverPKI',['install/example_config.conf']),
                 ('share/serverPKI/db',['install/fresh_install/README',
                                        'install/fresh_install/create_schema_dd.sql',
                                        'install/fresh_install/create_extension_citext.sql',
                                        'install/fresh_install/create_schema_pki.sql',
                                        'install/fresh_install/create_triggers_pki.sql',
                                        'install/fresh_install/load_services.sql',
                                        'install/fresh_install/load_testdata.sql',
                                        'install/upgrade/upgrade_to_2.sql',
                                        'install/upgrade/upgrade_to_3.sql',
                                        'install/upgrade/upgrade_to_4.sql',
                                        'install/upgrade/upgrade_to_5.sql',
                                        'install/upgrade/upgrade_to_6.sql',
                                        ])],
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
        'automatoes>=0.9.5',
        'configobj>=5.0.6',
        'cryptography>=2.9.2',
        'dnspython>=1.16.0',
        'py-postgresql>=1.2.1',
        'paramiko>=2.4.2',
        'prettytable>=0.7.2',
        'iso8601'
    ],
)
