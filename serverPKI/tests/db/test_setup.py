import sys

import pytest

from .psql import Psql

@pytest.fixture(scope="package")
def setup_database():

    psql = Psql()

    missing_role_msg = """
    CREATE ROLE "{}" WITH
      LOGIN
      NOSUPERUSER
      INHERIT
      CREATEDB
      NOCREATEROLE
      NOREPLICATION;
    ALTER ROLE "{}" SET search_path TO pki, dd, public;
    """.format(psql.db_user, psql.db_user)
    
    # just test, if we can connect to server
    (stdout, stderr, status) = psql.run_psql(cmd='SELECT NOW();', alt_db=True)
    if status:
        print('? missing role {} ?? - create it first:'.format(
            psql.db_user))
        print(missing_role_msg)
        assert False
        
    (stdout, stderr, status) = psql.run_psql(
        cmd='DROP DATABASE IF EXISTS "{}";'.format(
            psql.db_database),
        alt_db=True)
    if status:
        assert False

    (stdout, stderr, status) = psql.run_psql(
        cmd='CREATE DATABASE "{}"'.format(
            psql.db_database),
        alt_db=True)
    if status:
        assert False

    print('Creating schemd dd')
    sql_file = str(psql.fresh_install_dir / 'create_schema_dd.sql')
    (stdout, stderr, status) = psql.run_psql(sql_file=sql_file)
    if status:
        assert False

    print('Creating extension citext')
    sql_file = str(psql.fresh_install_dir / 'create_extension_citext.sql')
    (stdout, stderr, status) = psql.run_psql(sql_file=sql_file, run_as_dba=True)
    if status:
        assert False

    print('Creating schemd pki')
    sql_file = str(psql.fresh_install_dir / 'create_schema_pki.sql')
    (stdout, stderr, status) = psql.run_psql(sql_file=sql_file)
    if status:
        assert False

    print('Loading services')
    sql_file = str(psql.fresh_install_dir / 'load_services.sql')
    (stdout, stderr, status) = psql.run_psql(sql_file=sql_file)
    if status:
        assert False

    """
    print('Loading test data')
    with open(str(INSTALL_DIR / 'load_testdata.sql'), 'r') as sql_file:
        (stdout, stderr, status) = psql.run_psql(sql_file=fd)
        if status:
            assert False
    """
    yield psql
    psql = None

def test_db_setup(setup_database):
    """
    Connect to DB and query a table. If no exception raised, all is ok
    :return:
    """
    (stdout, stderr, status) = setup_database.run_psql(cmd='SELECT * FROM Services1;')
    print(stdout)
