----------------------------- serverPKI definition schema
SET search_path = pki, dd, public, pg_catalog;
SET log_min_messages='error';

START TRANSACTION; 

COPY Certificates (id, type, disabled) FROM stdin;
1	LE	false
2	LE	false
3	local	false
4	local	false
5	local	false
6	LE	false
8	local	false
9	LE	false
10	LE	false
11	LE	false
12	LE	false
13	LE	false
14	LE	false
15	LE	false
16	LE	false
17	local	false
18	LE	false
19	LE	false
20	LE	false
21	LE	false
23	LE	false
24	LE	false
26	local	false
27	local	false
28	local	false
29	local	false
30	local	false
31	local	false
32	local	false
33	local	false
34	local	false
35	local	true
36	local	true
37	local	true
38	local	false
39	local	false
40	local	false
\.
SELECT setval('Certificates_id_seq', max(id)) FROM Certificates;

COPY Subjects (id, type, name, isAltname, certificate) FROM stdin;
1	server	build3.lrau.net	false	1
2	server	caldav.lrau.net	false	2
3	server	caldav3.lrau.net	true	2
4	server	caldav4.lrau.net	true	2
5	server	db1.in.chaos1.de	false	3
6	server	db.in.chaos1.de	true	3
7	server	loghost.in.chaos1.de	true	3
8	server	db4.lrau.net	false	4
9	server	fw.bu.lrau.net	false	5
10	server	git.chaos1.de	false	6
11	server	git.nussberg.de	true	6
12	server	git3.lrau.net	true	6
13	server	git4.lrau.net	true	6
14	server	gw.mu.lrau.net	false	8
15	server	imap.lrau.net	false	9
16	server	imap3.lrau.net	true	9
17	server	imap4.lrau.net	true	9
18	server	lists.framail.de	false	10
19	server	lists3.lrau.net	false	11
20	server	lists4.lrau.net	false	12
21	server	mailout3.lrau.net	false	13
22	server	mailout4.lrau.net	false	14
23	server	mx3.lrau.net	false	15
24	server	mx4.lrau.net	false	16
25	server	router.nussberg.de	false	17
26	server	tmx4.lrau.net	false	18
27	server	timap4.lrau.net	false	19
28	server	www.chaos1.de	false	20
29	server	chaos1.de	true	20
30	server	www.kreuzenderblick.de	false	21
31	server	kreuzenderblick.de	true	21
32	server	www.framail.de	false	23
33	server	framail.de	true	23
34	server	www.lechner-rau.de	false	24
35	server	lechner-rau.de	true	24
36	server	zeus.in.chaos1.de	false	26
37	server	axels-macpro.in.chaos1.de	false	27
38	server	waltrauds-imac.in.chaos1.de	false	28
39	server	wilhelms-imac.in.chaos1.de	false	29
40	client	ajr	false	30
41	client	aoxsuperd	false	31
42	client	aoxsuperO	false	32
43	client	hgu	false	33
44	client	erdb_op	false	34
45	client	caldavd	false	35
46	client	replicator	false	36
47	client	erdb_test	false	37
48	client	erdb_dev	false	38
49	client	syslog	false	39
50	client	bacula_dir	false	40
\.
SELECT setval('Subjects_id_seq', max(id)) FROM Subjects;


COPY Services (id, name, port, TLSAprefix) FROM stdin;
1	https	443	_443._tcp.{}. 3600 IN TLSA 3 0 1
2	caldav	8443	_8443._tcp.{}. 3600 IN TLSA 3 0 1
3	imap	143	_143._tcp.{}. 3600 IN TLSA 3 0 1
4	imap	587	_587._tcp.{}. 3600 IN TLSA 3 0 1
5	smtp	25	_25._tcp.{}. 3600 IN TLSA 3 0 1
\.
SELECT setval('Services_id_seq', max(id)) FROM Services;


COPY Certificates_Services (certificate, service) FROM stdin;
6	1
9	3
9	4
10	1
11	5
12	5
13	5
14	5
15	5
16	5
18	5
19	5
20	1
21	1
23	1
24	1
\.


-- 288(10) == 440(8):

COPY Places (id, name, cert_file_type, cert_path, key_path, uid, gid, mode, chownboth, pglink, reload_command) FROM stdin;
1	aox	combined	usr/local/etc/archiveopteryx/	\N	666	\N	\N	false	false	jexec {} service archiveopteryx onerestart
2	aox_test	combined	usr/local/archiveopteryx/lib/	\N	666	\N	\N	false	false	jexec {} /usr/local/archiveopteryx/bin/aox restart
3	bacula_dir	separate	var/db/bacula/.postgresql/	\N	910	\N	\N	false	true	\N
4	caldav	separate	usr/local/etc/caldavd/	\N	639	\N	\N	false	false	jexec {} service caldavd restart
5	caldav_db	separate	var/db/caldavd/.postgresql	\N	639	\N	\N	false	true	\N
6	db1_l	separate	usr/local/pgsql/	\N	70	\N	\N	false	false	\N
7	db1_l_data	separate	usr/local/pgsql/data-l/	\N	70	\N	\N	false	false	\N
23	db1_r	separate	/disk1/db/db-r/	\N	70	\N	\N	false	false	\N
8	db1_r_data	separate	/disk1/db/db-r/data/	\N	70	\N	\N	false	false	\N
9	db4	separate	/disk1/db/db-r	\N	70	\N	\N	false	false	\N
10	db4_data	separate	/disk1/db/db-r/data	\N	70	\N	\N	false	false	\N
11	erdb_bt	separate	var/spool/erdb_op/.postgresql	\N	1001	\N	\N	false	true	\N
12	erdb_bt_aox	separate	var/spool/erdb_op/.postgresql	\N	1001	\N	\N	false	true	\N
13	exim	separate	usr/local/etc/exim	\N	26	\N	\N	false	false	jexec {} service exim restart
14	exim_db	separate	var/spool/mqueue/.postgresql	\N	26	\N	\N	false	true	\N
21	isakmpd_cert	separate	/etc/isakmpd/certs	/etc/isakmpd/private	\N	\N	\N	false	false	\N
22	isakmpd_cert_only	cert only	/etc/isakmpd/certs	\N	\N	\N	\N	false	false	\N
15	mac_bacula	combined	usr/local/bacula/etc/	\N	\N	\N	\N	false	false	\N
16	mac_pgsql	separate	Users/{}/.postgresql	\N	\N	\N	\N	false	true	\N
17	nginx	separate	usr/local/etc/nginx/certs	\N	\N	\N	\N	false	false	jexec {} service nginx restart
18	nginx_cacert	combined cacert	usr/local/etc/nginx/certs	\N	\N	\N	\N	false	false	jexec {} service nginx restart
19	root	separate	root/.postgresql	\N	\N	\N	\N	false	true	\N
20	zeus	separate	/etc/certificates	\N	\N	29	288	false	false	\N
\.
SELECT setval('Places_id_seq', max(id)) FROM Places;


COPY DistHosts (id, FQDN, jailroot) FROM stdin;
1	atlas.in.chaos1.de	\N
2	axels-macpro.in.chaos1.de	\N
3	bh3.lrau.net	/usr/jails
4	bh4.lrau.net	/usr/jails
5	db1.in.chaos1.de	\N
6	fw1.bu.lrau.net	\N
7	fw2.bu.lrau.net	\N
8	gw1.in.chaos1.de	\N
9	gw2.in.chaos1.de	\N
15	hermes.in.chaos1.de	\N
10	ns2.lrau.net	\N
11	router.nussberg.de	\N
12	waltrauds-imac.in.chaos1.de	\N
13	wilhelms-imac.in.chaos1.de	\N
14	zeus.in.chaos1.de	\N
\.
SELECT setval('DistHosts_id_seq', max(id)) FROM DistHosts;


COPY Jails (id, name, disthost) FROM stdin;
1	build3	3
2	caldav3	3
3	caldav4	4
4	cp3	3
5	cp4	4
6	db4	4
7	git3	3
8	git4	4
9	imap3	3
10	imap4	4
11	lists3	3
12	lists4	4
13	log4	4
14	mailout3	3
15	mailout4	4
16	mx3	3
17	mx4	4
18	ns3	3
19	ns4	4
20	timap4	4
21	tmx4	4
22	www3	3
23	www4	4
\.
SELECT setval('Jails_id_seq', max(id)) FROM Jails;


COPY Targets (id, disthost, jail, place, certificate) FROM stdin;
1	3	1	17	1
2	3	2	4	2
3	4	3	4	2
4	5	\N	6	3
5	5	\N	7	3
6	5	\N	23	3
7	5	\N	8	3
8	4	6	9	4
9	4	6	10	4
10	6	\N	21	5
11	7	\N	21	5
12	8	\N	22	5
13	9	\N	22	5
14	11	\N	22	5
15	3	7	17	6
16	4	8	17	6
17	9	\N	21	8
18	8	\N	21	8
19	6	\N	22	8
20	7	\N	22	8
21	3	9	1	9
22	4	10	1	9
23	3	11	17	10
24	4	12	17	10
25	3	11	13	11
26	4	12	13	12
27	3	14	13	13
28	4	15	13	14
29	3	16	13	15
30	4	17	13	16
31	11	\N	21	17
32	6	\N	22	17
33	7	\N	22	17
34	4	21	13	18
35	4	20	1	19
36	4	20	2	19
37	4	20	13	19
38	3	22	17	20
39	4	23	17	20
40	3	4	17	21
41	4	5	17	21
42	3	4	17	23
43	4	5	17	23
44	3	22	17	24
45	4	23	17	24
46	14	\N	20	26
47	2	\N	15	27
48	12	\N	15	28
49	13	\N	15	29
50	2	\N	16	30
51	4	21	19	31
52	4	17	12	32
54	5	\N	11	34
55	3	14	14	34
56	3	16	14	34
57	4	15	14	34
58	4	17	14	34
59	4	17	11	34
63	4	21	19	38
65	15	\N	3	40
\.
SELECT setval('Targets_id_seq', max(id)) FROM Targets;


COMMIT;                 -- CREATE SCHEMA pki
