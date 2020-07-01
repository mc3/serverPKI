import sys, os, pty
from subprocess import Popen, PIPE

from postgresql import driver as db_conn

from .conftest import config_path_for_pytest

def test_if_db_setup(psql_handle):
    """
    Connect to DB and query a table. If no exception raised, all is ok
    :return:
    """
    (stdout, stderr, status) = psql_handle.run_psql(cmd='SELECT * FROM Services;')


def test_if_services_loaded(db_handle: db_conn):

    assert isinstance(db_handle, db_conn.pq3.Connection)

    result = db_handle.query.first("SELECT COUNT(*) FROM SERVICES")
    assert result == 5


def test_run_from_command_line(db_handle: db_conn, script_runner):
    test_if_services_loaded(db_handle)

    ret = script_runner.run('operate_serverPKI', '-f', config_path_for_pytest, '-v')
    print(ret.stdout)
    print(ret.stderr)
    assert ret.success
    assert '[1 certificates and CAs [] in DB]' in ret.stdout.strip()

