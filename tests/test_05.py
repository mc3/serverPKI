import sys, os, pty
import getpass
from pathlib import Path
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

    for row in rows:
        assert row['Subject'] in ('CA', 'client')     # 'reserved' comes from initial setup
        if row['Subject'] == 'client':
            assert (row['Cert Name'] == CLIENT_CERT_1 and
                    row['Type'] == 'local' and
                    row['algo'] == 'rsa' and
                    row['Dist Host'] == get_hostname() and
                    row['Place'] == TEST_PLACE_1)

    assert len(rows) == 3



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
    ret = script_runner.run('operate_serverPKI', '--create-certs', '-o', CLIENT_CERT_1, '-d', '-f', config_path_for_pytest)
    assert ret.success


def test_distribute_local_cert(script_runner, setup_directories):
    """
    Given:  Issued local cert "CLIENT_CERT_1' in DB
    Then:   Distribute cert and key to
    :param script_runner:
    :param setup_directories:
    :return:
    """


    # now distribute local cert
    ret = script_runner.run('operate_serverPKI', '--distribute-certs', '-o', CLIENT_CERT_1, '-v', '-f', config_path_for_pytest)
    print(ret.stdout)
    print(ret.stderr)
    assert ret.success

    # obtain modulus of cert
    (rc, stdout) = run_command('openssl x509 -modulus -noout -in '
                                + str(TEMP_DIR) + '/client1_client_cert.pem | openssl md5', shell=True)
    assert rc==0
    print(stdout)
    cert_md5 = stdout.strip()

    # obtain modulus of key
    (rc, stdout) = run_command('openssl rsa -modulus -noout -in '
                                + str(TEMP_DIR) + '/client1_client_key.pem | openssl md5', shell=True)
    assert rc==0
    print(stdout)

    # does key belong to cert?
    assert cert_md5==stdout.strip()

    # check consistency of key
    (rc, stdout) = run_command('openssl rsa -check -noout -in '
                                + str(TEMP_DIR) + '/client1_client_key.pem', shell=True)
    assert rc==0
    print(stdout)
    assert stdout.strip()=='RSA key ok'
