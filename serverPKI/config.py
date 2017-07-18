"""
Copyright (C) 2015-2017  Axel Rau <axel.rau@chaos1.de>

This file is part of serverPKI.

serverPKI is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Foobar is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with serverPKI.  If not, see <http://www.gnu.org/licenses/>.
"""


# Module to make config settings available to members of package

import sys

# name of our config module
CONFIG_MODULE = 'config'

# place where to find it (sys.prefix point at venve if we are in a venv)
CONFIG_MODULE_DIRS =(   sys.prefix + '/etc',
                        '/usr/local/etc/serverPKI')

sys.path.append(CONFIG_MODULE_DIRS[0])
sys.path.append(CONFIG_MODULE_DIRS[1])

from serverPKI_config import Pathes as Pathes
from serverPKI_config import X509atts as X509atts
from serverPKI_config import dbAccounts as dbAccounts

from serverPKI_config import SSH_CLIENT_USER_NAME as SSH_CLIENT_USER_NAME
from serverPKI_config import LE_SERVER as LE_SERVER

from serverPKI_config import SUBJECT_LOCAL_CA as SUBJECT_LOCAL_CA
from serverPKI_config import LOCAL_CA_BITS as LOCAL_CA_BITS
from serverPKI_config import LOCAL_CA_LIFETIME as LOCAL_CA_LIFETIME

from serverPKI_config import SUBJECT_LE_CA as SUBJECT_LE_CA
from serverPKI_config import PRE_PUBLISH_TIMEDELTA as PRE_PUBLISH_TIMEDELTA
from serverPKI_config import LOCAL_ISSUE_MAIL_TIMEDELTA as LOCAL_ISSUE_MAIL_TIMEDELTA

from serverPKI_config import MAIL_RELAY as MAIL_RELAY
from serverPKI_config import MAIL_SUBJECT as MAIL_SUBJECT
from serverPKI_config import MAIL_SENDER as MAIL_SENDER
from serverPKI_config import MAIL_RECIPIENT as MAIL_RECIPIENT

from serverPKI_config import SYSLOG_FACILITY as SYSLOG_FACILITY
