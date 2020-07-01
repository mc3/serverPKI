import sys, os, pty
import getpass

from postgresql import driver as db_conn

from serverPKI.utils import Misc, Pathes

from .conftest import get_hostname, run_command, setup_directories, config_path_for_pytest, TEMP_DIR
from .parameters import CLIENT_CERT_1, TEST_PLACE_1, CA_CERT_PASS_PHASE

def test_issue_CAcert_from_scratch(db_handle, monkeypatch, script_runner):
    """
    GIVEN a monkeypatched version of getpass.getpass()
    WHEN operate_serverPKI --issue-local-CAcert invoked via cli
    THEN check the return status
    """

    def mock_getpass(prompt: str):
        return CA_CERT_PASS_PHASE
    monkeypatch.setattr(getpass, 'getpass', mock_getpass)

    ret = script_runner.run('operate_serverPKI', '--issue-local-CAcert', '-f', config_path_for_pytest)
    assert ret.success
    print(ret.stdout)
    print(ret.stderr)

def test_if_CA_cert_issued_from_scratch(db_handle, monkeypatch, script_runner):

    rows = db_handle.query("""
    SELECT type, state, encryption_algo  FROM inst WHERE name = '{}'
    """.format(Misc.SUBJECT_LOCAL_CA))

    assert len(rows) == 1

    for row in rows:
        assert (row['type'] == 'local' and
                row['state'] == 'issued'
                and row['encryption_algo'] == 'rsa')

