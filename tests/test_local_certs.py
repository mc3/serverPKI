import sys
from subprocess import Popen, PIPE

from postgresql import driver as db_conn

from .conftest import CLIENT_CERT_1, TEST_PLACE_1, config_file, get_hostname
from .test_parameters import CLIENT_CERT_1, CA_CERT_PASS_PHASE

def test_1_db_setup(psql_handle):
    """
    Connect to DB and query a table. If no exception raised, all is ok
    :return:
    """
    (stdout, stderr, status) = psql_handle.run_psql(cmd='SELECT * FROM Services;')


def test_if_services_loaded(db_handle: db_conn):

    assert isinstance(db_handle, db_conn.pq3.Connection)

    result = db_handle.query.first("SELECT COUNT(*) FROM SERVICES")
    assert result == 5

def test_if_cert_meta_created(create_local_cert_meta, db_handle):

    rows = db_handle.query("""
    SELECT * FROM certs""")

    assert len(rows) == 2

    for row in rows:
        assert row['Subject'] in ('CA', 'client')     # 'reserved' comes from initial setup
        if row['Subject'] == 'client':
            for i in range(len(row)):
                assert row[i] == ('client', CLIENT_CERT_1, 'local', 'rsa', False, None, None, None, None, get_hostname(),
                                 None, 'place_1')[i]

def test_run_from_command_line_1(create_local_cert_meta):
    p = Popen(('operate_serverPKI', '-d', '-f', config_file) ,
              stdout=PIPE, stderr=PIPE, text=True)
    stdout, stderr = p.communicate()
    print(stderr)
    print(stdout)
    assert p.returncode == 0


def test_create_local_cert_without_cacert_1(create_local_cert_meta):
    p = Popen(('operate_serverPKI', '-C', '-o', CLIENT_CERT_1, '-v', '-f', config_file) ,
              stdout=PIPE, stderr=PIPE, text=True)
    ##p.communicate(input=CA_CERT_PASS_PHASE + '\n' + CA_CERT_PASS_PHASE + '\n')
    stdout, stderr = p.communicate()
    ##p.stdin.write(str(CA_CERT_PASS_PHASE + '\n' + CA_CERT_PASS_PHASE + '\n'))
    ##p.stdin.flush()
    ##stdout, stderr = p.communicate()
    print(stdout)
    print(stderr)
    assert p.returncode == 0
