import sys, os, pty
import getpass

from postgresql import driver as db_conn

from serverPKI.utils import Misc, Pathes

from .conftest import get_hostname, run_command, setup_directories, config_path_for_pytest, TEMP_DIR
from .parameters import CLIENT_CERT_1, TEST_PLACE_1, CA_CERT_PASS_PHASE

def insert_local_cert_meta(db_handle):

    result = db_handle.query.first("""
    INSERT INTO DISTHOSTS (fqdn) VALUES($1::TEXT)""", get_hostname())
    assert result == 1

    result = db_handle.query.first("""
    INSERT INTO PLACES(name, cert_path) VALUES($1::TEXT, $2::TEXT)""",
                                   TEST_PLACE_1, str(TEMP_DIR))
    assert result == 1

    result = db_handle.query.first("""
    SELECT * FROM add_cert($1::TEXT::citext, 'client'::TEXT::subject_type, 'local'::TEXT::cert_type, 'rsa'::TEXT::cert_encryption_algo, 'False', NULL, NULL, NULL, $2::TEXT::citext, NULL, $3::TEXT::citext)
    """, CLIENT_CERT_1, get_hostname(), TEST_PLACE_1)
    print(result)


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

def test_issue_local_cert_from_ca_cert_in_flatfile(db_handle, monkeypatch, script_runner, setup_directories):

    def mock_getpass(prompt: str):
        return CA_CERT_PASS_PHASE

    monkeypatch.setattr(getpass, 'getpass', mock_getpass)

    # export ca cert+key (row_id is 5) to work directory
    ret = script_runner.run('operate_serverPKI', '--export-cert-and-key', '5', '-f', config_path_for_pytest)
    assert ret.success
    print(ret.stdout)
    print(ret.stderr)

    # rename exported files to destination
    os.rename(Pathes.work + '/cert-5-rsa.pem', Pathes.ca_cert)
    os.rename(Pathes.work + '/key-5-rsa.pem', Pathes.ca_key)

    # delete ca cert in
    delete_and_cleanup_local_ca_cert(False, db_handle)

    # delete and re-insert local cert meta
    delete_and_cleanup_local_cert(True, db_handle)
    insert_local_cert_meta(db_handle)

    # now issue local cert
    ret = script_runner.run('operate_serverPKI', '--create-certs', '-o', CLIENT_CERT_1, '-v', '-f', config_path_for_pytest)
    assert ret.success
    print(ret.stdout)
    print(ret.stderr)
