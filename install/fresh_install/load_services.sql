----------------------------- serverPKI definition schema
SET search_path = pki, dd, public, pg_catalog;

START TRANSACTION; 


COPY services (id, name, port, tlsaprefix, created, updated, remarks) FROM stdin;
1	https	443	_443._tcp.{}. 3600 IN TLSA 3 0 1	2016-07-30 13:48:57.431786	2016-07-30 13:48:57.442189	\N
2	caldav	8443	_8443._tcp.{}. 3600 IN TLSA 3 0 1	2016-07-30 13:48:57.431786	2016-07-30 13:48:57.442189	\N
3	imap	143	_143._tcp.{}. 3600 IN TLSA 3 0 1	2016-07-30 13:48:57.431786	2016-07-30 13:48:57.442189	\N
4	imap	587	_587._tcp.{}. 3600 IN TLSA 3 0 1	2016-07-30 13:48:57.431786	2016-07-30 13:48:57.442189	\N
5	smtp	25	_25._tcp.{}. 3600 IN TLSA 3 0 1	2016-07-30 13:48:57.431786	2016-07-30 13:48:57.442189	\N
\.
SELECT setval('Services_id_seq', max(id)) FROM Services;


COMMIT;                 -- COPY services
