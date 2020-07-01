import sys, os, pty
import getpass

from postgresql import driver as db_conn

from serverPKI.utils import Misc, Pathes

from .conftest import (get_hostname, run_command, setup_directories, config_path_for_pytest, TEMP_DIR,
                        insert_local_cert_meta, delete_and_cleanup_local_cert)
from .parameters import CLIENT_CERT_1, TEST_PLACE_1, CA_CERT_PASS_PHASE



def test_cert_meta_creation(db_handle):
    """
    Given:  A clean DB
    When:   Cert meta for local cert inserted into DB
    Then:   It should be queried
    :param db_handle:
    :return:
    """

    insert_local_cert_meta(db_handle)

    rows = db_handle.query("""
    SELECT "Subject", "Cert Name","Type","algo", "Dist Host", "Place" FROM certs""")

    assert len(rows) == 2

    for row in rows:
        assert row['Subject'] in ('CA', 'client')     # 'reserved' comes from initial setup
        if row['Subject'] == 'client':
            assert (row['Cert Name'] == CLIENT_CERT_1 and
                    row['Type'] == 'local' and
                    row['algo'] == 'rsa' and
                    row['Dist Host'] == get_hostname() and
                    row['Place'] == TEST_PLACE_1)


def test_issue_local_cert_from_ca_cert_in_db(db_handle, monkeypatch, script_runner):
    """
    Given:  A CA cert in DB
    And:    cert meta for local cert in DB
    Then:   operate_serverPKI --create-certs should create a local cert
    :param db_handle:
    :param monkeypatch:
    :param script_runner:
    :return:
    """

    def mock_getpass(prompt: str):
        return CA_CERT_PASS_PHASE

    monkeypatch.setattr(getpass, 'getpass', mock_getpass)

    # now issue local cert
    ret = script_runner.run('operate_serverPKI', '--create-certs', '-o', CLIENT_CERT_1, '-v', '-f', config_path_for_pytest)
    assert ret.success
    print(ret.stdout)
    print(ret.stderr)

    delete_and_cleanup_local_cert(False, db_handle)