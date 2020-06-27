import sys, os, pty
from subprocess import Popen, PIPE

from postgresql import driver as db_conn

from serverPKI.utils import Misc

from .conftest import get_config_path, get_hostname, run_command, setup_directories, TEMP_DIR
from .parameters import CLIENT_CERT_1, TEST_PLACE_1, CA_CERT_PASS_PHASE

config_file = get_config_path()

def insert_local_cert_meta(db_handle):

    delete_and_cleanup_local_cert(True, db_handle)

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


def test_cert_meta_creation(db_handle):

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


def delete_and_cleanup_local_cert(allow_empty: bool, db_handle):

    result = db_handle.query.first("""
    DELETE FROM certificates WHERE  id in (SELECT id FROM subjects WHERE name = '{}')""".format(CLIENT_CERT_1))
    assert result == 1 or allow_empty

    result = db_handle.query.first("""
    DELETE FROM PLACES WHERE name = '{}'""".format(TEST_PLACE_1))
    assert result == 1 or allow_empty

    result = db_handle.query.first("""
    DELETE FROM DISTHOSTS WHERE fqdn = '{}'""".format(get_hostname()))
    assert result == 1 or allow_empty

def delete_and_cleanup_local_ca_cert(allow_empty: bool, db_handle) -> None:
    """
    Delete CA cert meta and instance. Also deletes any related local cert instances
    :param allow_empty: Ignore nonexistant CA cert
    :param db_handle:
    :return:
    """
    result = db_handle.query.first("""
    DELETE FROM certificates WHERE id in
        (SELECT id FROM subjects WHERE name = '{}')""".format(Misc.SUBJECT_LOCAL_CA))
    assert result == 1 or allow_empty

# CA cert tests

def test_issue_CAcert_from_scratch(db_handle):

    delete_and_cleanup_local_ca_cert(True, db_handle)

    master, slave = pty.openpty()
    p = Popen(('operate_serverPKI', '--issue-local-CAcert', '-f', config_file) ,
              stdin=slave, text=True, shell=True)
    os.write(master, str(CA_CERT_PASS_PHASE + '\n' + CA_CERT_PASS_PHASE + '\n').encode("UTF-8"))
    p.wait()
    os.close(master)
    os.close(slave)
    stdout, stderr = p.communicate()
    print(stdout)
    print(stderr)
    assert p.returncode == 0

def test_if_CA_cert_issued_from_scratch(db_handle):

    test_issue_CAcert_from_scratch(db_handle)

    rows = db_handle.query("""
    SELECT type, state, encryption_algo  FROM inst WHERE name = '{}'
    """.format(Misc.SUBJECT_LOCAL_CA))

    assert len(rows) == 1

    for row in rows:
        assert (row['type'] == 'local' and
                row['state'] == 'issued'
                and row['encryption_algo'] == 'rsa')

def test_issue_local_cert_from_ca_cert_in_flatfile(db_handle):

    test_issue_CAcert_from_scratch(db_handle)
    setup_directories()
    # export ca files (row_id is 1)
    status, stdout = run_command(('operate_serverPKI', '-f', config_file, '--export-cert-and-key', '1'))
    # delete ca cert in db
    delete_and_cleanup_local_ca_cert(True, db_handle)
    # delete and re-insert local cert meta
    delete_and_cleanup_local_cert(True, db_handle)
    insert_local_cert_meta(db_handle)

    # now issue local cert
    master, slave = pty.openpty()
    p = Popen(('operate_serverPKI', '--create-certs', '-o', CLIENT_CERT_1, '-v', '-f', config_file),
              stdin=slave, text=True, shell=True)
    os.write(master, str(CA_CERT_PASS_PHASE + '\n').encode("UTF-8"))
    p.wait()
    os.close(master)
    os.close(slave)
    stdout, stderr = p.communicate()
    print(stdout)
    print(stderr)
    assert p.returncode == 0

def test_if_local_cert_and_ca_cert_from_flatfile_issued(db_handle):

    test_issue_local_cert_and_missing_ca_cert(db_handle)

    rows = db_handle.query("""
    SELECT id,name,type,state,encryption_algo FROM inst""")
    for row in rows:
        assert row['name'] in (Misc.SUBJECT_LOCAL_CA, CLIENT_CERT_1)
        assert row['type'] == 'local' and row['state'] == 'issued' and row['encryption_algo'] == 'rsq'

def test_issue_local_cert_and_missing_ca_cert(db_handle):

    delete_and_cleanup_local_ca_cert(True, db_handle)
    delete_and_cleanup_local_cert(True, db_handle)
    insert_local_cert_meta(db_handle)

    master, slave = pty.openpty()
    p = Popen(('operate_serverPKI', '--create-certs', '-o', CLIENT_CERT_1, '-v', '-f', config_file) ,
              stdin=slave, text=True, shell=True)
    os.write(master, str(CA_CERT_PASS_PHASE + '\n' + CA_CERT_PASS_PHASE + '\n').encode("UTF-8"))
    p.wait()
    os.close(master)
    os.close(slave)
    stdout, stderr = p.communicate()
    print(stdout)
    print(stderr)
    assert p.returncode == 0

def test_if_local_cert_and_missing_ca_cert_issued(db_handle):

    test_issue_local_cert_and_missing_ca_cert(db_handle)

    rows = db_handle.query("""
    SELECT id,name,type,state,encryption_algo FROM inst""")
    for row in rows:
        assert row['name'] in (Misc.SUBJECT_LOCAL_CA, CLIENT_CERT_1)
        assert row['type'] == 'local' and row['state'] == 'issued' and row['encryption_algo'] == 'rsq'

