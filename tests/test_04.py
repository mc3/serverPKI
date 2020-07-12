import sys, os, pty
import getpass

from postgresql import driver as db_conn

from serverPKI.utils import Misc, Pathes

from .conftest import (get_hostname, run_command, setup_directories, config_path_for_pytest, TEMP_DIR,
                delete_and_cleanup_local_ca_cert, delete_and_cleanup_local_cert, insert_local_cert_meta)
from .parameters import CLIENT_CERT_1, TEST_PLACE_1, CA_CERT_PASS_PHASE


def test_issue_local_cert_from_ca_cert_in_flatfile(db_handle, monkeypatch, script_runner, setup_directories):

    def mock_getpass(prompt: str):
        return CA_CERT_PASS_PHASE

    def mock_getpass(prompt: str):
        return CA_CERT_PASS_PHASE
    monkeypatch.setattr(getpass, 'getpass', mock_getpass)

    ret = script_runner.run('operate_serverPKI', '--issue-local-CAcert', '-f', config_path_for_pytest)
    assert ret.success

    # export ca cert+key (row_id is 3) to work directory
    ret = script_runner.run('operate_serverPKI', '--export-cert-and-key', '3', '-f', config_path_for_pytest)
    assert ret.success
    print(ret.stdout)
    print(ret.stderr)

    # rename exported files to destination
    os.rename(Pathes.work + '/cert-3-rsa.pem', Pathes.ca_cert)
    os.rename(Pathes.work + '/key-3-rsa.pem', Pathes.ca_key)

    # delete ca cert in db
    delete_and_cleanup_local_ca_cert(False, db_handle)

    # delete and re-insert local cert meta
    delete_and_cleanup_local_cert(True, db_handle)
    insert_local_cert_meta(db_handle)

    # now issue local cert
    ret = script_runner.run('operate_serverPKI', '--create-certs', '-o', CLIENT_CERT_1, '-v', '-f', config_path_for_pytest)
    assert ret.success
    print(ret.stdout)
    print(ret.stderr)

