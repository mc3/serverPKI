----------------------------- serverPKI definition schema
SET search_path = pki, dd, public, pg_catalog;
SET log_min_messages='error';

START TRANSACTION; 

COPY Certificates (id, type, disabled, updated, created, remarks, authorized_until) FROM stdin;
1	LE	false	\N	\N	\N	\N
2	LE	false	\N	\N	\N	\N
3	local	false	\N	\N	\N	\N
4	local	false	\N	\N	\N	\N
5	local	false	\N	\N	\N	\N
6	LE	false	\N	\N	\N	\N
8	local	false	\N	\N	\N	\N
9	LE	false	\N	\N	\N	\N
10	LE	false	\N	\N	\N	\N
11	LE	false	\N	\N	\N	\N
12	LE	false	\N	\N	\N	\N
13	LE	false	\N	\N	\N	\N
14	LE	false	\N	\N	\N	\N
15	LE	false	\N	\N	\N	\N
16	LE	false	\N	\N	\N	\N
17	local	false	\N	\N	\N	\N
18	LE	false	\N	\N	\N	\N
19	LE	false	\N	\N	\N	\N
20	LE	false	\N	\N	\N	\N
21	LE	false	\N	\N	\N	\N
23	LE	false	\N	\N	\N	\N
24	LE	false	\N	\N	\N	\N
26	local	false	\N	\N	\N	\N
27	local	false	\N	\N	\N	\N
28	local	false	\N	\N	\N	\N
29	local	false	\N	\N	\N	\N
30	local	false	\N	\N	\N	\N
31	local	false	\N	\N	\N	\N
32	local	false	\N	\N	\N	\N
33	local	false	\N	\N	\N	\N
34	local	false	\N	\N	\N	\N
35	local	true	\N	\N	\N	\N
36	local	true	\N	\N	\N	\N
37	local	true	\N	\N	\N	\N
38	local	false	\N	\N	\N	\N
39	local	false	\N	\N	\N	\N
40	local	false	\N	\N	\N	\N
\.

SELECT setval('Certificates_id_seq', max(id)) FROM Certificates;

COPY Subjects (id, type, name, isAltname, certificate, updated, created, remarks) FROM stdin;
1	server	build1.example.com	false	1	\N	\N	\N
2	server	caldav.example.com	false	2	\N	\N	\N
3	server	caldav1.example.com	true	2	\N	\N	\N
4	server	caldav2.example.com	true	2	\N	\N	\N
5	server	db1.in.example.jp	false	3	\N	\N	\N
6	server	db.in.example.jp	true	3	\N	\N	\N
7	server	loghost.in.example.jp	true	3	\N	\N	\N
8	server	db2.example.com	false	4	\N	\N	\N
9	server	fw.x1.example.com	false	5	\N	\N	\N
10	server	git.example.jp	false	6	\N	\N	\N
11	server	git.example.au	true	6	\N	\N	\N
12	server	git1.example.com	true	6	\N	\N	\N
13	server	git2.example.com	true	6	\N	\N	\N
14	server	gw.f2.example.com	false	8	\N	\N	\N
15	server	imap.example.com	false	9	\N	\N	\N
16	server	imap1.example.com	true	9	\N	\N	\N
17	server	imap2.example.com	true	9	\N	\N	\N
18	server	lists.example.us	false	10	\N	\N	\N
19	server	lists1.example.com	false	11	\N	\N	\N
20	server	lists2.example.com	false	12	\N	\N	\N
21	server	mailout1.example.com	false	13	\N	\N	\N
22	server	mailout2.example.com	false	14	\N	\N	\N
23	server	mx1.example.com	false	15	\N	\N	\N
24	server	mx2.example.com	false	16	\N	\N	\N
25	server	router.example.au	false	17	\N	\N	\N
26	server	tmx2.example.com	false	18	\N	\N	\N
27	server	timap2.example.com	false	19	\N	\N	\N
28	server	www.example.jp	false	20	\N	\N	\N
29	server	example.jp	true	20	\N	\N	\N
30	server	www.example.no	false	21	\N	\N	\N
31	server	example.no	true	21	\N	\N	\N
32	server	www.example.us	false	23	\N	\N	\N
33	server	example.cn	true	23	\N	\N	\N
34	server	www.example.in	false	24	\N	\N	\N
35	server	example.in	true	24	\N	\N	\N
36	server	zeus.in.example.jp	false	26	\N	\N	\N
37	server	peters-macpro.in.example.jp	false	27	\N	\N	\N
38	server	hellens-imac.in.example.jp	false	28	\N	\N	\N
39	server	guys-imac.in.example.jp	false	29	\N	\N	\N
40	client	ferdinand	false	30	\N	\N	\N
41	client	aoxsuperd	false	31	\N	\N	\N
42	client	aoxsuperO	false	32	\N	\N	\N
43	client	sebastian	false	33	\N	\N	\N
44	client	erdb_op	false	34	\N	\N	\N
45	client	caldavd	false	35	\N	\N	\N
46	client	replicator	false	36	\N	\N	\N
47	client	erdb_test	false	37	\N	\N	\N
48	client	erdb_dev	false	38	\N	\N	\N
49	client	syslog	false	39	\N	\N	\N
50	client	bacula_dir	false	40	\N	\N	\N
\.

SELECT setval('Subjects_id_seq', max(id)) FROM Subjects;

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

COPY Places (id, name, cert_file_type, cert_path, key_path, uid, gid, mode, chownboth, pglink, reload_command, created, updated, remarks) FROM stdin;
1	aox	combine both	usr/local/etc/archiveopteryx/	\N	666	\N	\N	false	false	jexec {} service archiveopteryx onerestart	\N	\N	\N
2	aox_test	combine both	usr/local/archiveopteryx/lib/	\N	666	\N	\N	false	false	jexec {} /usr/local/archiveopteryx/bin/aox restart	\N	\N	\N
3	bacula_dir	separate	var/db/bacula/.postgresql/	\N	910	\N	\N	false	true	\N	\N	\N	\N
4	caldav	separate	usr/local/etc/caldavd/	\N	639	\N	\N	false	false	jexec {} service caldavd restart	\N	\N	\N
5	caldav_db	separate	var/db/caldavd/.postgresql	\N	639	\N	\N	false	true	\N	\N	\N	\N
6	db1_l	separate	usr/local/pgsql/	\N	70	\N	\N	false	false	\N	\N	\N	\N
7	db1_l_data	separate	usr/local/pgsql/data-l/	\N	70	\N	\N	false	false	\N	\N	\N	\N
23	db1_r	separate	/disk1/db/db-r/	\N	70	\N	\N	false	false	\N	\N	\N	\N
8	db1_r_data	separate	/disk1/db/db-r/data/	\N	70	\N	\N	false	false	\N	\N	\N	\N
9	db4	separate	/disk1/db/db-r	\N	70	\N	\N	false	false	\N	\N	\N	\N
10	db4_data	separate	/disk1/db/db-r/data	\N	70	\N	\N	false	false	\N	\N	\N	\N
11	erdb_bt	separate	var/spool/erdb_op/.postgresql	\N	1001	\N	\N	false	true	\N	\N	\N	\N
12	erdb_bt_aox	separate	var/spool/erdb_op/.postgresql	\N	1001	\N	\N	false	true	\N	\N	\N	\N
13	exim	separate	usr/local/etc/exim	\N	26	\N	\N	false	false	jexec {} service exim restart	\N	\N	\N
14	exim_db	separate	var/spool/mqueue/.postgresql	\N	26	\N	\N	false	true	\N	\N	\N	\N
21	isakmpd_cert	separate	/etc/isakmpd/certs	/etc/isakmpd/private	\N	\N	\N	false	false	\N	\N	\N	\N
22	isakmpd_cert_only	cert only	/etc/isakmpd/certs	\N	\N	\N	\N	false	false	\N	\N	\N	\N
15	mac_bacula	combine both	usr/local/bacula/etc/	\N	\N	\N	\N	false	false	\N	\N	\N	\N
16	mac_pgsql	separate	Users/{}/.postgresql	\N	\N	\N	\N	false	true	\N	\N	\N	\N
17	nginx	separate	usr/local/etc/nginx/certs	\N	\N	\N	\N	false	false	jexec {} service nginx restart	\N	\N	\N
18	nginx_cacert	combine cacert	usr/local/etc/nginx/certs	\N	\N	\N	\N	false	false	jexec {} service nginx restart	\N	\N	\N
19	x4	separate	root/.postgresql	\N	\N	\N	\N	false	true	\N	\N	\N	\N
20	zeus	separate	/etc/certificates	\N	\N	29	288	false	false	\N	\N	\N	\N
\.
SELECT setval('Places_id_seq', max(id)) FROM Places;


COPY DistHosts (id, FQDN, jailroot, updated, created, remarks) FROM stdin;
1	atlas.in.example.jp	\N	\N	\N	\N
2	peters-macpro.in.example.jp	\N	\N	\N	\N
3	x1.example.com	/usr/jails	\N	\N	\N
4	x2.example.com	/usr/jails	\N	\N	\N
5	db1.in.example.jp	\N	\N	\N	\N
6	fw1.x1.lrau.net	\N	\N	\N	\N
7	fw2.x1.lrau.net	\N	\N	\N	\N
8	gw1.f2.example.jp	\N	\N	\N	\N
9	gw2.f2.example.jp	\N	\N	\N	\N
15	hermes.in.example.jp	\N	\N	\N	\N
10	ns2.example.com	\N	\N	\N	\N
11	router.example.au	\N	\N	\N	\N
12	hellens-imac.in.example.jp	\N	\N	\N	\N
13	guys-imac.in.example.jp	\N	\N	\N	\N
14	zeus.in.example.jp	\N	\N	\N	\N
\.
SELECT setval('DistHosts_id_seq', max(id)) FROM DistHosts;


COPY Jails (id, name, disthost, updated, created, remarks) FROM stdin;
1	build1	3	\N	\N	\N
2	caldav1	3	\N	\N	\N
3	caldav2	4	\N	\N	\N
4	cp1	3	\N	\N	\N
5	cp2	4	\N	\N	\N
6	db2	4	\N	\N	\N
7	git1	3	\N	\N	\N
8	git2	4	\N	\N	\N
9	imap1	3	\N	\N	\N
10	imap2	4	\N	\N	\N
11	lists1	3	\N	\N	\N
12	lists2	4	\N	\N	\N
13	log2	4	\N	\N	\N
14	mailout1	3	\N	\N	\N
15	mailout2	4	\N	\N	\N
16	mx1	3	\N	\N	\N
17	mx2	4	\N	\N	\N
18	ns1	3	\N	\N	\N
19	ns2	4	\N	\N	\N
20	timap2	4	\N	\N	\N
21	tmx2	4	\N	\N	\N
22	www1	3	\N	\N	\N
23	www2	4	\N	\N	\N
\.
SELECT setval('Jails_id_seq', max(id)) FROM Jails;


COPY Targets (id, disthost, jail, place, certificate, updated, created, remarks) FROM stdin;
1	3	1	17	1	\N	\N	\N
2	3	2	4	2	\N	\N	\N
3	4	3	4	2	\N	\N	\N
4	5	\N	6	3	\N	\N	\N
5	5	\N	7	3	\N	\N	\N
6	5	\N	23	3	\N	\N	\N
7	5	\N	8	3	\N	\N	\N
8	4	6	9	4	\N	\N	\N
9	4	6	10	4	\N	\N	\N
10	6	\N	21	5	\N	\N	\N
11	7	\N	21	5	\N	\N	\N
12	8	\N	22	5	\N	\N	\N
13	9	\N	22	5	\N	\N	\N
14	11	\N	22	5	\N	\N	\N
15	3	7	17	6	\N	\N	\N
16	4	8	17	6	\N	\N	\N
17	9	\N	21	8	\N	\N	\N
18	8	\N	21	8	\N	\N	\N
19	6	\N	22	8	\N	\N	\N
20	7	\N	22	8	\N	\N	\N
21	3	9	1	9	\N	\N	\N
22	4	10	1	9	\N	\N	\N
23	3	11	17	10	\N	\N	\N
24	4	12	17	10	\N	\N	\N
25	3	11	13	11	\N	\N	\N
26	4	12	13	12	\N	\N	\N
27	3	14	13	13	\N	\N	\N
28	4	15	13	14	\N	\N	\N
29	3	16	13	15	\N	\N	\N
30	4	17	13	16	\N	\N	\N
31	11	\N	21	17	\N	\N	\N
32	6	\N	22	17	\N	\N	\N
33	7	\N	22	17	\N	\N	\N
34	4	21	13	18	\N	\N	\N
35	4	20	1	19	\N	\N	\N
36	4	20	2	19	\N	\N	\N
37	4	20	13	19	\N	\N	\N
38	3	22	17	20	\N	\N	\N
39	4	23	17	20	\N	\N	\N
40	3	4	17	21	\N	\N	\N
41	4	5	17	21	\N	\N	\N
42	3	4	17	23	\N	\N	\N
43	4	5	17	23	\N	\N	\N
44	3	22	17	24	\N	\N	\N
45	4	23	17	24	\N	\N	\N
46	14	\N	20	26	\N	\N	\N
47	2	\N	15	27	\N	\N	\N
48	12	\N	15	28	\N	\N	\N
49	13	\N	15	29	\N	\N	\N
50	2	\N	16	30	\N	\N	\N
51	4	21	19	31	\N	\N	\N
52	4	17	12	32	\N	\N	\N
54	5	\N	11	34	\N	\N	\N
55	3	14	14	34	\N	\N	\N
56	3	16	14	34	\N	\N	\N
57	4	15	14	34	\N	\N	\N
58	4	17	14	34	\N	\N	\N
59	4	17	11	34	\N	\N	\N
63	4	21	19	38	\N	\N	\N
65	15	\N	3	40	\N	\N	\N
\.
SELECT setval('Targets_id_seq', max(id)) FROM Targets;


COMMIT;					-- CREATE SCHEMA pki
