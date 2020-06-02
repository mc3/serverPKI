from io import TextIOWrapper
from pathlib import Path
from subprocess import Popen, PIPE
import re
import sys
from typing import Tuple

import pytest

error_marker =  re.compile('ERROR|FATAL|STATEMENT|HINT')

DEFAULT_DB = 'postgres'

SERVICE = 'serverpki'

INSTALL_DIR = ((Path(__file__).parent.parent.parent.parent.resolve()) / 'install').resolve()
FRESH_INSTALL_DIR = INSTALL_DIR / 'fresh_install'

CONFIG_MODULE_DIRS = (((Path(__file__).parent.resolve().parent) / 'conf').resolve(),)
sys.path.append(str(CONFIG_MODULE_DIRS[0]))

from test_config import Pathes as Pathes
from test_config import dbAccounts as dbAccounts


class Psql(object):
    db_default_db = DEFAULT_DB
    install_dir = INSTALL_DIR
    fresh_install_dir = FRESH_INSTALL_DIR
    
    db_host = dbAccounts[SERVICE]['dbHost']
    db_port = dbAccounts[SERVICE]['dbPort']
    db_user = dbAccounts[SERVICE]['dbUser']
    dba_user = dbAccounts[SERVICE]['dbDbaUser']
    db_database = dbAccounts[SERVICE]['dbDatabase']

    def __init__(self):
        pass
    
    def run_psql(self,
                 cmd: str=None,
                 sql_file: str=None,
                 alt_db: bool=False,
                 run_as_dba: bool=False) -> Tuple[str,str,int]:
        """
        Send SQL to server, using psql utility
        :param cmd: Issue this SQL command
        :param sql_file: Let server execute this SQL file
        :param alt_db: Use alternate DB (usually 'postgres')
        :param run_as_dba: User dba username from config for connection
        :return: (stdout, stderr, status)
        """
    
        if run_as_dba:
            if self.dba_user:
                user_option  = ('-U' ,self.dba_user)
            else:
                user_option = tuple()
        else:
            user_option = ('-U' ,self.db_user)
        
        cmds = ('psql',
                '-h', self.db_host, 
                '-p', self.db_port,
                '-d', self.db_database if not alt_db else self.db_default_db)
        if cmd:
            print(cmd)
            p = Popen(cmds + ('-c', cmd) + user_option,
                stdout=PIPE, stderr=PIPE, text=True)
        elif sql_file:
            p = Popen(cmds + ('-f', sql_file) + user_option,
                stdout=PIPE, stderr=PIPE, text=True)
        else:
            assert False, 'tests.db.Psql.run_psql missing one of args "cmd" or "sql_file"'
            
        stdout, stderr = p.communicate()

        status = p.returncode
        if p.returncode:
            print('?Failed with status={}. Error message follows:'.format(p.returncode))
            print(stderr)
        for line in re.split("\\n+", stderr):
            if error_marker.search(line):
                print(line)
                status = -1

        return (stdout, stderr, status)
    
