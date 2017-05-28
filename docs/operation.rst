Operation
=========

Operation of the PKI is divided into

* Management of cert instances like issue, renewal, distribution, publishing
  and consolidation happens via the operate_serverPKI utility

* Management of configuration, which is done via psql (PostgreSQL command line
  utility) because configuration is stored in a database.

Management of cert instances
----------------------------

These are the command line options. Arguments are in capital letters::

  # operate_serverPKI --help
  Usage: operate_serverPKI [options]
  
  Certificate Authority operations
  
  Options:
    -h, --help            show this help message and exit
    -S, --schedule-actions
                          Scan configuration and schedule necessary actions of
                          selected certs/hosts. This may trigger issuence or
                          distribution of certs/TLSA-RRS. With this options 
                          "--create-certs" and "--distribute-certs" are ignored.
                          Any state transitions may happen
    -K, --consolidate-certs
                          Consolidate targets to be in sync with DB. This
                          affects certs in state "deployed".
    -T, --consolidate-TLSAs
                          Consolidate TLSA-RR to be in sync with DB. This
                          affects certs in state "deployed" or "prepublished".
    -R, --remove-TLSAs    Remove TLSA-RRs i.e. make them empty.
    -C, --create-certs    Scan configuration and create all certs, which are not
                          disbled or excluded. State will be "issued" of created
                          certs.
    -D, --distribute-certs
                          Scan configuration and distribute (to their target
                          host) all certs which are in state "issued" and
                          currently valid and not disabled or excluded. Changes
                          state to "deployed". Corresponding TLSA RR are also
                          installed, if not suppressed with --no-TLSA-records-
    -E, --extract-cert-and-key
                          Extract certificate and key to work directory. This
                          action may not be combined with other actions.
    -a, --all             All certs in configuration should be included in
                          operation, even if disabled.
    -i CERT_TO_BE_INCLUDED, --include=CERT_TO_BE_INCLUDED
                          Specify, which cert to be included, even if disabled,
                          in list of certs to be created or distributed. Is
                          cumulative if multiple times provided.
    -e CERT_TO_BE_EXCLUDED, --exclude=CERT_TO_BE_EXCLUDED
                          Specify, which cert to be excluded from list of certs
                          to be created or distributed. Is cumulative if
                          multiple times provided.
    -o ONLY_CERT, --only=ONLY_CERT
                          Specify from which cert(s) the list of certs to be
                          created or distributed. Is cumulative if multiple
                          times provided.
    -s SKIP_HOST, --skip-disthost=SKIP_HOST
                          Specify, which disthosts should not receive
                          distributions. Is cumulative if multiple times
                          provided.
    -l ONLY_HOST, --limit-to-disthost=ONLY_HOST
                          Specify, which disthosts should receive distributions
                          only (others are excluded). Is cumulative if multiple
                          times provided.
    -N, --no-TLSA-records
                          Do not distribute/change TLSA resource records.
    -n, --check-only      Do syntax check of configuration data.
    -d, --debug           Turn on debugging.
    -q, --quiet           Be quiet on command line. Do only logging. (for cron
                          jobs).
    -v, --verbose         Be more verbose.


Management of configuration
---------------------------

TBD

.. _States:

State table of cert instances
-----------------------------

.. image:: States.png
