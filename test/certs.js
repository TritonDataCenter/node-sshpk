// Copyright 2018 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var sinon = require('sinon');
var asn1 = require('asn1');
var SSHBuffer = require('../lib/ssh-buffer');

var testDir = path.join(__dirname, 'assets');

var GEORGE_KEY, GEORGE_SSH, GEORGE_X509;
var BARRY_KEY;
var JIM_KEY, JIM_SSH, JIM_X509, JIM_X509_TXT;
var EC_KEY, EC_KEY2;
var SUE_KEY;

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
	JIM_X509_TXT = fs.readFileSync(path.join(testDir, 'jim-x509-text.pem'));

	d = fs.readFileSync(path.join(testDir, 'id_ecdsa'));
	EC_KEY = sshpk.parsePrivateKey(d);
	d = fs.readFileSync(path.join(testDir, 'id_ecdsa2'));
	EC2_KEY = sshpk.parsePrivateKey(d);

	d = fs.readFileSync(path.join(testDir, 'id_ed25519'));
	SUE_KEY = sshpk.parsePrivateKey(d);

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

test('x509 pem cert with extra text', function (t) {
	var cert = sshpk.parseCertificate(JIM_X509_TXT, 'pem');
	t.ok(sshpk.Certificate.isCertificate(cert));
	t.ok(JIM_KEY.fingerprint().matches(cert.subjectKey));
	t.ok(cert.isSignedByKey(JIM_KEY));
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

test('create ed25519 self-signed, loopback', function (t) {
	var id = sshpk.identityForHost('foobar.com');
	var cert = sshpk.createSelfSignedCertificate(id, SUE_KEY);

	var x509 = cert.toBuffer('pem');
	var cert2 = sshpk.parseCertificate(x509, 'pem');
	t.ok(SUE_KEY.fingerprint().matches(cert2.subjectKey));
	t.ok(cert2.subjects[0].equals(cert.subjects[0]));
	t.ok(cert2.isSignedByKey(SUE_KEY));

	var ossh = cert.toBuffer('openssh');
	var cert3 = sshpk.parseCertificate(ossh, 'openssh');
	t.ok(SUE_KEY.fingerprint().matches(cert3.subjectKey));
	t.ok(cert3.subjects[0].equals(cert.subjects[0]));
	t.strictEqual(cert3.subjects[0].hostname, 'foobar.com');

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
	t.deepEqual(cert.subjects[0].toArray(), [
		{ name: 'c', value: 'FR' },
		{ name: 's', value: 'Île-de-France' },
		{ name: 'l', value: 'Paris' },
		{ name: 'o', value: 'Hereditary Monarchy' },
		{ name: 'ou', value: 'Head of State' },
		{ name: 'emailAddress', value: 'nappi@greatfrenchempire.fr' },
		{ name: 'cn', value: 'Emperor Napoleon I' },
		{ name: 'sn', value: 'Bonaparte' },
		{ name: 'gn', value: 'Napoleon' }
	]);
	t.end();
});

test('example cert: digicert ca (x509)', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'digicert-ca.crt')), 'x509');
	t.strictEqual(cert.subjectKey.type, 'rsa');
	t.strictEqual(cert.subjects.length, 1);
	t.deepEqual(cert.purposes.sort(),
	    ['ca', 'clientAuth', 'crl', 'serverAuth', 'signature']);
	var exts = cert.getExtensions();
	t.strictEqual(exts.length, 8);
	exts.forEach(function (ext) {
		t.strictEqual(ext.format, 'x509');
		t.strictEqual(typeof (ext.oid), 'string');
	});
	var basicExt = cert.getExtension('2.5.29.19');
	t.strictEqual(basicExt.oid, '2.5.29.19');
	t.strictEqual(basicExt.critical, true);
	t.strictEqual(basicExt.format, 'x509');
	t.strictEqual(basicExt.pathLen, 0);
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
	t.strictEqual(cert.issuer.get('c'), 'US');
	t.strictEqual(cert.issuer.get('o'), 'DigiCert Inc');

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
	t.deepEqual(cert.purposes.sort(),
	    ['clientAuth', 'keyEncryption', 'serverAuth', 'signature']);

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

test('example cert: openssh rsa with sha256 (7.0p1+)', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'openssh-rsa256.pub')),
	    'openssh');
	t.strictEqual(cert.subjectKey.type, 'rsa');
	t.ok(cert.isSignedByKey(cert.subjectKey));
	t.strictEqual(cert.signatures.openssh.signature.hashAlgorithm,
	    'sha256');
	t.end();
});

test('example cert: ed25519 cert from curdle-pkix-04', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'ed25519-pkix-cert.pem')),
	    'pem');
	t.strictEqual(cert.subjectKey.type, 'curve25519');
	t.strictEqual(cert.subjects[0].type, 'user');
	t.strictEqual(cert.subjects[0].cn, 'IETF Test Demo');

	var key = sshpk.parsePrivateKey(
	    fs.readFileSync(path.join(testDir, 'ed25519-pkix.pem')), 'pem');
	t.ok(cert.isSignedByKey(key));

	t.end();
});

test('cert with doubled-up DN attribute', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'double-title-cert.pem')),
	    'pem');

	var id = cert.subjects[0];
	t.throws(function () {
		id.get('title');
	});
	t.deepEqual(id.get('title', true), ['in-zone.key', 'in-zone.key']);

	t.strictEqual(id.get('ou'), 'delegated');
	t.strictEqual(id.get('cn'), '2dc79d36-ea01-c855-eab5-e2c7a24abbf4');

	t.end();
});

test('example cert: yubikey attestation cert', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'yubikey.pem')),
	    'pem');
	t.strictEqual(cert.subjectKey.type, 'ecdsa');
	t.strictEqual(cert.subjects[0].cn, 'YubiKey PIV Attestation 9e');

	var serialExt = cert.getExtension('1.3.6.1.4.1.41482.3.7');
	t.ok(serialExt);
	var der = new asn1.Ber.Reader(serialExt.data);
	t.strictEqual(der.readInt(), 5213681);

	var policyExt = cert.getExtension('1.3.6.1.4.1.41482.3.8');
	t.ok(policyExt);
	t.strictEqual(policyExt.data[0], 0x01); /* never require PIN */
	t.strictEqual(policyExt.data[1], 0x01); /* never require touch */

	t.end();
});

test('example cert: openssh extensions', function (t) {
	var cert = sshpk.parseCertificate(
	    fs.readFileSync(path.join(testDir, 'openssh-exts.pub')),
	    'openssh');
	t.strictEqual(cert.subjectKey.type, 'ecdsa');
	t.strictEqual(cert.subjects[0].uid, 'foo');

	var forceCmdExt = cert.getExtension('force-command');
	t.ok(forceCmdExt);
	t.strictEqual(forceCmdExt.name, 'force-command');
	t.strictEqual(forceCmdExt.critical, true);

	var cmdbuf = new SSHBuffer({ buffer: forceCmdExt.data });
	var cmd = cmdbuf.readString();
	t.strictEqual(cmd, 'foobarcmd');
	t.ok(cmdbuf.atEnd());

	t.ok(cert.getExtension('permit-port-forwarding'));
	t.notOk(cert.getExtension('source-address'));
	t.notOk(cert.getExtension('permit-pty'));

	t.end();
});
