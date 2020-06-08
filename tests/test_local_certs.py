import sys

from postgresql import driver as db_conn
import pytest

from .conftest import CLIENT_CERT_1, TEST_PLACE_1, get_hostname

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

    assert len(rows) == 1

    row = rows[0]
    print(row)
    for i in range(len(row)):
        assert row[i] == ('client', 'client1', 'local', 'rsa', False, None, None, None, None, get_hostname(),
                         None, 'place_1')[i]

