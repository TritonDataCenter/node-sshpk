// Copyright 2016 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var sinon = require('sinon');

var testDir = path.join(__dirname, 'assets');

var GEORGE_KEY, GEORGE_SSH, GEORGE_X509;
var BARRY_KEY;
var JIM_KEY, JIM_SSH, JIM_X509;
var EC_KEY, EC_KEY2;

test('setup', function (t) {
	var d = fs.readFileSync(path.join(testDir, 'id_dsa'));
	GEORGE_KEY = sshpk.parseKey(d);
	GEORGE_SSH = fs.readFileSync(path.join(testDir, 'george-openssh.pub'));
	GEORGE_X509 = fs.readFileSync(path.join(testDir, 'george-x509.pem'));

	d = fs.readFileSync(path.join(testDir, 'id_dsa2'));
	BARRY_KEY = sshpk.parsePrivateKey(d);

	d = fs.readFileSync(path.join(testDir, 'id_rsa'));
	JIM_KEY = sshpk.parsePrivateKey(d);

	JIM_SSH = fs.readFileSync(path.join(testDir, 'jim-openssh.pub'));
	JIM_X509 = fs.readFileSync(path.join(testDir, 'jim-x509.pem'));

	d = fs.readFileSync(path.join(testDir, 'id_ecdsa'));
	EC_KEY = sshpk.parsePrivateKey(d);
	d = fs.readFileSync(path.join(testDir, 'id_ecdsa2'));
	EC2_KEY = sshpk.parsePrivateKey(d);
	t.end();
});

test('dsa openssh cert self-signed', function (t) {
	var cert = sshpk.parseCertificate(GEORGE_SSH, 'openssh');
	t.ok(sshpk.Certificate.isCertificate(cert));

	t.ok(GEORGE_KEY.fingerprint().matches(cert.subjectKey));
	t.ok(cert.isSignedByKey(GEORGE_KEY));
	t.ok(!cert.isSignedByKey(BARRY_KEY));

	t.ok(!cert.isExpired(new Date('2016-07-22T00:00:00Z')));
	t.ok(cert.isExpired(new Date('2001-07-01T00:00:00Z')));
	t.ok(cert.isExpired(new Date('2017-07-23T00:00:00Z')));

	t.strictEqual(cert.subjects.length, 1);
	t.strictEqual(cert.subjects[0].toString(), 'UID=george');
	t.strictEqual(cert.subjects[0].type, 'user');
	t.strictEqual(cert.subjects[0].uid, 'george');

	t.throws(function () {
		cert.fingerprint();
	});
	t.end();
});

test('dsa x509 cert self-signed', function (t) {
	var cert = sshpk.parseCertificate(GEORGE_X509, 'pem');
	t.ok(sshpk.Certificate.isCertificate(cert));

	t.ok(GEORGE_KEY.fingerprint().matches(cert.subjectKey));
	t.ok(cert.isSignedByKey(GEORGE_KEY));
	t.ok(!cert.isSignedByKey(BARRY_KEY));

	t.ok(!cert.isExpired(new Date('2016-07-22T00:00:00Z')));
	t.ok(cert.isExpired(new Date('2001-07-01T00:00:00Z')));
	t.ok(cert.isExpired(new Date('2017-07-23T00:00:00Z')));

	t.strictEqual(cert.subjects.length, 1);
	t.strictEqual(cert.subjects[0].toString(), 'UID=george');
	t.strictEqual(cert.subjects[0].type, 'user');
	t.strictEqual(cert.subjects[0].uid, 'george');

	var fp = sshpk.parseFingerprint(
	    'SHA256:rPrIM16iuYN1UkWprtIkRaUzerKz0JkNd/FjKG7OJCU',
	    { type: 'certificate '});
	t.ok(fp.matches(cert));
	t.end();
});

test('rsa openssh cert self-signed', function (t) {
	var cert = sshpk.parseCertificate(JIM_SSH, 'openssh');
	t.ok(sshpk.Certificate.isCertificate(cert));

	t.ok(JIM_KEY.fingerprint().matches(cert.subjectKey));
	t.ok(cert.isSignedByKey(JIM_KEY));
	t.ok(!cert.isSignedByKey(BARRY_KEY));

	t.ok(!cert.isExpired(new Date('2016-07-23T00:00:00Z')));
	t.ok(cert.isExpired(new Date('2001-07-01T00:00:00Z')));
	t.ok(cert.isExpired(new Date('2017-07-23T00:00:00Z')));

	t.strictEqual(cert.subjects.length, 1);
	t.strictEqual(cert.subjects[0].toString(), 'CN=jim.com');
	t.strictEqual(cert.subjects[0].type, 'host');
	t.strictEqual(cert.subjects[0].hostname, 'jim.com');

	t.ok(cert.issuer.equals(cert.subjects[0]));

	t.end();
});

test('rsa x509 cert self-signed', function (t) {
	var cert = sshpk.parseCertificate(JIM_X509, 'pem');
	t.ok(sshpk.Certificate.isCertificate(cert));

	t.ok(JIM_KEY.fingerprint().matches(cert.subjectKey));
	t.ok(cert.isSignedByKey(JIM_KEY));
	t.ok(!cert.isSignedByKey(BARRY_KEY));

	t.ok(!cert.isExpired(new Date('2016-07-23T00:00:00Z')));
	t.ok(cert.isExpired(new Date('2001-07-01T00:00:00Z')));
	t.ok(cert.isExpired(new Date('2017-07-23T00:00:00Z')));

	t.strictEqual(cert.subjects.length, 1);
	t.strictEqual(cert.subjects[0].toString(), 'DC=jim, DC=com');
	t.strictEqual(cert.subjects[0].type, 'host');
	t.strictEqual(cert.subjects[0].hostname, 'jim.com');

	t.ok(cert.issuer.equals(cert.subjects[0]));
	t.ok(cert.isSignedBy(cert));

	t.end();
});

test('create rsa self-signed, loopback', function (t) {
	var id = sshpk.identityForHost('foobar.com');
	var cert = sshpk.createSelfSignedCertificate(id, JIM_KEY);

	var x509 = cert.toBuffer('pem');
	var cert2 = sshpk.parseCertificate(x509, 'pem');
	t.ok(JIM_KEY.fingerprint().matches(cert2.subjectKey));
	t.ok(cert2.subjects[0].equals(cert.subjects[0]));

	var ossh = cert.toBuffer('openssh');
	var cert3 = sshpk.parseCertificate(ossh, 'openssh');
	t.ok(JIM_KEY.fingerprint().matches(cert3.subjectKey));
	t.ok(cert3.subjects[0].equals(cert.subjects[0]));
	t.strictEqual(cert3.subjects[0].hostname, 'foobar.com');

	t.end();
});

test('create ecdsa signed, loopback', function (t) {
	var id = sshpk.identityForUser('jim');
	var ca = sshpk.identityForHost('foobar.com');
	var cacert = sshpk.createSelfSignedCertificate(ca, EC2_KEY);
	var cert = sshpk.createCertificate(id, EC_KEY, ca, EC2_KEY);

	var x509 = cert.toBuffer('pem');
	var cert2 = sshpk.parseCertificate(x509, 'pem');
	t.ok(EC_KEY.fingerprint().matches(cert2.subjectKey));
	t.ok(cert2.subjects[0].equals(cert.subjects[0]));
	t.ok(cert2.isSignedBy(cacert));

	var ossh = cert.toBuffer('openssh');
	var cert3 = sshpk.parseCertificate(ossh, 'openssh');
	t.ok(EC_KEY.fingerprint().matches(cert3.subjectKey));
	t.ok(cert3.subjects[0].equals(cert.subjects[0]));
	t.strictEqual(cert3.subjects[0].uid, 'jim');
	t.ok(cert3.isSignedBy(cacert));

	t.end();
});

test('subjectaltname', function (t) {
	var ids = [
		sshpk.identityForHost('foobar.com'),
		sshpk.identityForHost('www.foobar.com'),
		sshpk.identityForHost('mail.foobar.com')
	];
	var cert = sshpk.createSelfSignedCertificate(ids, JIM_KEY);

	var x509 = cert.toBuffer('pem');
	var cert2 = sshpk.parseCertificate(x509, 'pem');
	t.ok(JIM_KEY.fingerprint().matches(cert2.subjectKey));
	t.strictEqual(cert2.subjects.length, 3);
	t.ok(cert2.subjects[0].equals(cert.subjects[0]));
	t.ok(cert2.subjects[1].equals(cert.subjects[1]));
	t.strictEqual(cert2.subjects[0].hostname, 'foobar.com');
	t.strictEqual(cert2.subjects[1].hostname, 'www.foobar.com');

	var ossh = cert.toBuffer('openssh');
	var cert3 = sshpk.parseCertificate(ossh, 'openssh');
	t.ok(JIM_KEY.fingerprint().matches(cert3.subjectKey));
	t.ok(cert3.subjects[0].equals(cert.subjects[0]));
	t.strictEqual(cert3.subjects.length, 3);
	t.strictEqual(cert3.subjects[0].hostname, 'foobar.com');
	t.strictEqual(cert3.subjects[1].hostname, 'www.foobar.com');

	t.end();
});

test('napoleon cert (generalizedtime) (x509)', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'napoleon-cert.pem')), 'pem');
	t.strictEqual(cert.subjectKey.type, 'rsa');
	t.ok(cert.isExpired(new Date('1901-01-01T00:00Z')));
	console.log(cert.validFrom.getTime());
	console.log(cert.validUntil.getTime());
	t.ok(!cert.isExpired(new Date('1775-03-01T00:00Z')));
	t.end();
});

test('example cert: digicert (x509)', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'digicert.pem')), 'pem');
	t.strictEqual(cert.subjectKey.type, 'rsa');
	t.strictEqual(cert.subjects.length, 8);
	t.strictEqual(cert.subjects[0].hostname, 'www.digicert.com');
	t.strictEqual(cert.issuer.cn,
	    'DigiCert SHA2 Extended Validation Server CA');

	var cacert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'digicert-ca.crt')), 'x509');
	t.ok(cert.isSignedBy(cacert));
	t.end();
});

test('example cert: joyent (x509)', function (t) {
	var data = fs.readFileSync(path.join(testDir, 'joyent.pem'));
	var cert = sshpk.parseCertificate(data, 'pem');
	t.strictEqual(cert.subjectKey.type, 'rsa');
	t.strictEqual(cert.subjects[0].type, 'host');
	t.strictEqual(cert.subjects[0].hostname, '*.joyent.com');

	var fp = sshpk.parseFingerprint(
	    'SHA1:6UMWRUe9vr93cg8AGS7Nwl1XOAA',
	    { type: 'certificate' });
	t.ok(fp.matches(cert));
	t.end();
});

test('example cert: cloudflare (x509)', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'cloudflare.pem')), 'pem');
	t.strictEqual(cert.subjectKey.type, 'ecdsa');
	var id = sshpk.identityForHost('mail.imeyou.io');
	t.ok(cert.subjects.some(function (subj) {
		return (subj.equals(id));
	}));
	var fp = cert.fingerprint('sha1').toString('hex');
	t.strictEqual(fp.toUpperCase(),
	    'B7:11:BA:8E:83:43:E0:4D:A2:DC:6F:F7:87:2B:5D:78:2C:B1:31:2A');

	var cacert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'comodo.crt')), 'x509');
	t.ok(cert.isSignedBy(cacert));
	t.end();
});

test('example cert: letsencrypt (x509)', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'letsencrypt.pem')), 'pem');
	t.strictEqual(cert.subjectKey.type, 'rsa');
	t.strictEqual(cert.subjects[0].type, 'host');
	t.strictEqual(cert.subjects[0].hostname, 'cr.joyent.us');
	var fp = cert.fingerprint('sha1').toString('hex');
	t.strictEqual(fp.toUpperCase(),
	    '59:8B:FA:BF:F7:DD:D4:B5:7E:8F:53:61:B1:65:0D:DF:F5:4B:CC:72');
	t.end();
});

test('example cert: DSA example (x509 DER)', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, '1024b-dsa-example-cert.der')),
	    'x509');
	t.strictEqual(cert.subjectKey.type, 'dsa');
	t.strictEqual(cert.subjects[0].type, 'host');
	t.strictEqual(cert.subjects[0].hostname, 'www.example.com');

	var cacert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'frank4dd-cacert.der')), 'x509');
	t.ok(cert.isSignedBy(cacert));
	t.end();
});

test('example cert: lots of SAN (x509)', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'google_jp_458san.pem')),
	    'pem');
	t.strictEqual(cert.subjectKey.type, 'rsa');
	t.strictEqual(cert.subjects[0].type, 'host');
	t.strictEqual(cert.subjects[0].hostname, 'google.com');
	var id = sshpk.identityForHost('google.co.jp');
	t.ok(cert.subjects.some(function (subj) {
		return (subj.equals(id));
	}));
	t.end();
});
