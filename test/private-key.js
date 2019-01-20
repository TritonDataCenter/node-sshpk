// Copyright 2017 Joyent, Inc.  All rights reserved.

var test = require('tape').test;
var sshpk = require('../lib/index');
var path = require('path');
var fs = require('fs');

var testDir = path.join(__dirname, 'assets');

var ID_RSA_FP = sshpk.parseFingerprint(
    'SHA256:tT5wcGMJkBzNu+OoJYEgDCwIcDAIFCUahAmuTT4qC3s');
var ID_DSA_FP = sshpk.parseFingerprint(
    'SHA256:PCfwpK62grBWrAJceLetSNv9CTrX8yoD0miKf11DBG8');
var ID_ECDSA_FP = sshpk.parseFingerprint(
    'SHA256:e34c67Npv31uMtfVUEBJln5aOcJugzDaYGsj1Uph5DE');
var ID_ECDSA2_FP = sshpk.parseFingerprint(
    'SHA256:Kyu0EMqH8fzfp9RXKJ6kmsk9qKGBqVRtlOuk6bXfCEU');
var ID_ED25519_FP = sshpk.parseFingerprint(
    'SHA256:2UeFLCUKw2lvd8O1zfINNVzE0kUcu2HJHXQr/TGHt60');
var ID_RSA_O_FP = sshpk.parseFingerprint(
    'SHA256:sfZqx0wyXwuXhsza0Ld99+/YNEMFyubTD8fPJ1Jo7Xw');
var ID_ECDSA_ENC_FP = sshpk.parseFingerprint(
    'SHA256:n2/53LRiEy+DBbKltRHQC36vwRndRJve+912b8zDvow');

test('PrivateKey load RSA key', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir, 'id_rsa'));
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.strictEqual(key.type, 'rsa');
	t.strictEqual(key.size, 1024);
	t.ok(ID_RSA_FP.matches(key));
	t.end();
});

test('PrivateKey load DSA key', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir, 'id_dsa'));
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.strictEqual(key.type, 'dsa');
	t.strictEqual(key.size, 1024);
	t.ok(ID_DSA_FP.matches(key));
	t.end();
});

test('PrivateKey load ECDSA 384 key', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir, 'id_ecdsa'));
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.strictEqual(key.type, 'ecdsa');
	t.strictEqual(key.size, 384);
	t.ok(ID_ECDSA_FP.matches(key));
	t.end();
});

test('PrivateKey load ECDSA 256 key', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir, 'id_ecdsa2'));
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.strictEqual(key.type, 'ecdsa');
	t.strictEqual(key.size, 256);
	t.ok(ID_ECDSA2_FP.matches(key));
	t.end();
});

test('PrivateKey can\'t load a secp224r1 key', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir, 'secp224r1_key.pem'));
	t.throws(function() {
		sshpk.parsePrivateKey(keyPem, 'pem');
	});
	t.end();
});

test('PrivateKey load ECDSA 256 key explicit curve', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir, 'id_ecdsa_exp'));
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.strictEqual(key.type, 'ecdsa');
	t.strictEqual(key.size, 256);
	t.strictEqual(key.curve, 'nistp256');
	t.end();
});

test('PrivateKey load ED25519 256 key', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir, 'id_ed25519'));
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.strictEqual(key.type, 'ed25519');
	t.strictEqual(key.size, 256);
	t.ok(ID_ED25519_FP.matches(key));

	keyPem = key.toBuffer('openssh');
	var key2 = sshpk.parsePrivateKey(keyPem, 'openssh');
	t.ok(ID_ED25519_FP.matches(key2));

	keyPem = key.toBuffer('pkcs1');
	var realKeyPem = fs.readFileSync(path.join(testDir, 'id_ed25519.pem'));
	t.strictEqual(keyPem.toString('base64'), realKeyPem.toString('base64'));
	t.end();
});

test('PrivateKey load ed25519 pem key', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir, 'id_ed25519.pem'));
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.strictEqual(key.type, 'ed25519');
	t.strictEqual(key.size, 256);
	t.ok(ID_ED25519_FP.matches(key));
	t.end();
});

test('PrivateKey load ed25519 key (ex. from curdle-pkix-04)', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir, 'ed25519-pkix.pem'));
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.strictEqual(key.type, 'ed25519');
	t.strictEqual(key.size, 256);
	t.end();
});

test('PrivateKey load ed25519 key (no public curdle-pkix-05)', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir,
	    'curdle-pkix-privonly.pem'));
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.strictEqual(key.type, 'ed25519');
	t.strictEqual(key.size, 256);
	t.end();
});

test('PrivateKey load ed25519 key (w/ public curdle-pkix-05)', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir,
	    'curdle-pkix-withpub.pem'));
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.strictEqual(key.type, 'ed25519');
	t.strictEqual(key.size, 256);
	t.end();
});

test('PrivateKey invalid ed25519 key (not DER)', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir,
	    'ed25519-invalid-ber.pem'));
	t.throws(function () {
		sshpk.parsePrivateKey(keyPem, 'pem');
	});
	t.end();
});

test('PrivateKey invalid ed25519 key (invalid curve point)', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir,
	    'ed25519-invalid-mask.pem'));
	t.throws(function () {
		sshpk.parsePrivateKey(keyPem, 'pem');
	});
	t.end();
});

test('PrivateKey invalid ed25519 key (elided zero)', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir,
	    'ed25519-invalid-zero.pem'));
	/*
	 * We're actually more forgiving of this kind of invalid input than
	 * the RFC says we need to be. Since this is purely about the format of
	 * the data, and not about the validity of the point itself this should
	 * be safe.
	 */
	var key = sshpk.parsePrivateKey(keyPem, 'pem');
	t.end();
});

test('PrivateKey convert ssh-private rsa to pem', function (t) {
	var keySsh = fs.readFileSync(path.join(testDir, 'id_rsa_o'));
	var key = sshpk.parsePrivateKey(keySsh, 'ssh-private');
	t.strictEqual(key.type, 'rsa');
	t.strictEqual(key.size, 1044);
	t.ok(ID_RSA_O_FP.matches(key));

	var keyPem = key.toBuffer('pkcs8');
	var key2 = sshpk.parsePrivateKey(keyPem, 'pem');
	t.ok(ID_RSA_O_FP.matches(key2));

	var signer = key2.createSign('sha1');
	signer.update('foobar');
	var sig = signer.sign();
	/*
	 * Compare this to a known good signature from this key, generated by
	 * the openssh agent
	 */
	t.strictEqual(sig.toString(), 'CiMwFuHYzmiRY70E5XC5LqoSBItMUmpWkAUvf' +
	    'mx0T63WnX22ir+072EcMQkLDdrjWPwVHx0Cw52uA88FiC4BX74/PzB2Chi4pgTx' +
	    'p8RVRLKYY54ze+XT12iQPBU7oVRkr+ZoM3INZshZ3MhomvEQuVUQuAWlek6LLXp' +
	    'x+mVg8XlMS8g=');

	t.end();
});

test('parse pkcs8 unencrypted private keys', function (t) {
	var keyPkcs8 = fs.readFileSync(path.join(testDir, 'id_rsa8'));
	var key = sshpk.parsePrivateKey(keyPkcs8, 'pkcs8');
	t.strictEqual(key.type, 'rsa');
	t.ok(ID_RSA_FP.matches(key));

	var newPkcs8 = key.toBuffer('pkcs8');
	t.strictEqual(keyPkcs8.toString(), newPkcs8.toString());

	keyPkcs8 = fs.readFileSync(path.join(testDir, 'id_ecdsa8'));
	key = sshpk.parsePrivateKey(keyPkcs8, 'pkcs8');
	t.strictEqual(key.type, 'ecdsa');
	t.ok(ID_ECDSA_FP.matches(key));

	newPkcs8 = key.toBuffer('pkcs8');
	t.strictEqual(keyPkcs8.toString(), newPkcs8.toString());

	keyPkcs8 = fs.readFileSync(path.join(testDir, 'id_dsa8'));
	key = sshpk.parsePrivateKey(keyPkcs8, 'pkcs8');
	t.strictEqual(key.type, 'dsa');
	t.ok(ID_DSA_FP.matches(key));

	newPkcs8 = key.toBuffer('pkcs8');
	t.strictEqual(keyPkcs8.toString(), newPkcs8.toString());

	t.end();
});

test('parse and produce encrypted ssh-private ecdsa', function (t) {
	var keySsh = fs.readFileSync(path.join(testDir, 'id_ecdsa_enc'));
	t.throws(function () {
		sshpk.parsePrivateKey(keySsh, 'ssh-private');
	});
	t.throws(function () {
		sshpk.parsePrivateKey(keySsh, 'ssh-private',
		    { passphrase: 'incorrect' });
	});
	var key = sshpk.parsePrivateKey(keySsh, 'ssh-private',
	    { passphrase: 'foobar' });
	t.strictEqual(key.type, 'ecdsa');
	t.strictEqual(key.size, 256);
	t.ok(ID_ECDSA_ENC_FP.matches(key));

	var keySsh2 = key.toBuffer('ssh-private', { passphrase: 'foobar2' });
	t.throws(function () {
		sshpk.parsePrivateKey(keySsh2, 'ssh-private',
		    { passphrase: 'foobar' });
	});
	var key2 = sshpk.parsePrivateKey(keySsh2, 'ssh-private',
	    { passphrase: 'foobar2' });
	t.strictEqual(key.type, 'ecdsa');
	t.strictEqual(key.size, 256);
	t.ok(ID_ECDSA_ENC_FP.matches(key));

	t.end();
});

test('pem pkcs#5 encrypted with aes-256-cbc', function (t) {
	var keyPem = fs.readFileSync(path.join(testDir, 'p50key.pem'));
	t.throws(function () {
		sshpk.parsePrivateKey(keyPem, 'pem');
	});
	t.throws(function () {
		sshpk.parsePrivateKey(keyPem, 'pem',
		    { passphrase: 'incorrect' });
	});
	var key = sshpk.parsePrivateKey(keyPem, 'pem',
	    { passphrase: 'pass' });
	t.strictEqual(key.type, 'rsa');
	t.strictEqual(key.size, 2048);
	t.end();
});

var KEY_RSA, KEY_DSA, KEY_ECDSA, KEY_ECDSA2, KEY_ED25519;

test('setup keys', function (t) {
	KEY_RSA = sshpk.parsePrivateKey(fs.readFileSync(
	    path.join(testDir, 'id_rsa')), 'pem');
	KEY_DSA = sshpk.parsePrivateKey(fs.readFileSync(
	    path.join(testDir, 'id_dsa')), 'pem');
	KEY_ECDSA = sshpk.parsePrivateKey(fs.readFileSync(
	    path.join(testDir, 'id_ecdsa')), 'pem');
	KEY_ECDSA2 = sshpk.parsePrivateKey(fs.readFileSync(
	    path.join(testDir, 'id_ecdsa2')), 'pem');
	KEY_ED25519 = sshpk.parsePrivateKey(fs.readFileSync(
	    path.join(testDir, 'id_ed25519')), 'pem');
	t.end();
});

test('PrivateKey#toPublic on RSA key', function (t) {
	var pubKey = KEY_RSA.toPublic();
	t.strictEqual(KEY_RSA.type, pubKey.type);
	t.strictEqual(KEY_RSA.size, pubKey.size);
	t.strictEqual(KEY_RSA.hash('sha256').toString('base64'),
	    pubKey.hash('sha256').toString('base64'));
	t.notStrictEqual(KEY_RSA.toString('pem'), pubKey.toString('pem'));
	t.end();
});

test('PrivateKey#createSign on RSA key', function (t) {
	var s = KEY_RSA.createSign('sha256');
	s.update('foobar');
	var sig = s.sign();
	t.ok(sig);
	t.ok(sig instanceof sshpk.Signature);

	var v = KEY_RSA.createVerify('sha256');
	v.update('foobar');
	t.ok(v.verify(sig));

	t.end();
});

test('PrivateKey#createSign on DSA key', function (t) {
	var s = KEY_DSA.createSign('sha256');
	s.update('foobar');
	var sig = s.sign();
	t.ok(sig);
	t.ok(sig instanceof sshpk.Signature);

	var v = KEY_DSA.createVerify('sha256');
	v.update('foobar');
	t.ok(v.verify(sig));

	t.end();
});

test('PrivateKey#createSign on ECDSA 384 key', function (t) {
	var s = KEY_ECDSA.createSign('sha256');
	s.update('foobar');
	var sig = s.sign();
	t.ok(sig);
	t.ok(sig instanceof sshpk.Signature);

	var v = KEY_ECDSA.createVerify('sha256');
	v.update('foobar');
	t.ok(v.verify(sig));

	t.end();
});

test('PrivateKey#createSign on ECDSA 256 key', function (t) {
	var s = KEY_ECDSA2.createSign('sha256');
	s.update('foobar');
	var sig = s.sign();
	t.ok(sig);
	t.ok(sig instanceof sshpk.Signature);

	var v = KEY_ECDSA2.createVerify('sha256');
	v.update('foobar');
	t.ok(v.verify(sig));

	t.end();
});

test('PrivateKey.generate ecdsa default', function (t) {
	var key = sshpk.generatePrivateKey('ecdsa');
	t.ok(sshpk.PrivateKey.isPrivateKey(key));
	t.strictEqual(key.type, 'ecdsa');
	t.strictEqual(key.curve, 'nistp256');
	t.strictEqual(key.size, 256);

	var s = key.createSign('sha256');
	s.update('foobar');
	var sig = s.sign();
	t.ok(sig);
	t.ok(sig instanceof sshpk.Signature);

	var key2 = sshpk.parsePrivateKey(key.toBuffer('pem'));

	var v = key2.createVerify('sha256');
	v.update('foobar');
	t.ok(v.verify(sig));

	var key3 = sshpk.generatePrivateKey('ecdsa');
	t.ok(!key3.fingerprint().matches(key));

	t.end();
});

test('PrivateKey.generate ecdsa p-384', function (t) {
	var key = sshpk.generatePrivateKey('ecdsa', { curve: 'nistp384' });
	t.ok(sshpk.PrivateKey.isPrivateKey(key));
	t.strictEqual(key.type, 'ecdsa');
	t.strictEqual(key.curve, 'nistp384');
	t.strictEqual(key.size, 384);
	t.end();
});

test('pkcs8 PrivateKey without public part', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'pkcs8-nopub.pem'));
	var key = sshpk.parsePrivateKey(pem, 'pem');
	t.strictEqual(key.type, 'ecdsa');
	t.strictEqual(key.curve, 'nistp256');
	var fp = sshpk.parseFingerprint(
	    'SHA256:wU/JTqlHV21vv0tcaNOFUZD2FXciO2KwImEOW1+AH50');
	t.ok(fp.matches(key));
	t.end();
});

if (process.version.match(/^v0\.[0-9]\./))
	return;

test('PrivateKey.generate ed25519', function (t) {
	var key = sshpk.generatePrivateKey('ed25519');
	t.ok(sshpk.PrivateKey.isPrivateKey(key));
	t.strictEqual(key.type, 'ed25519');
	t.strictEqual(key.size, 256);

	var s = key.createSign('sha512');
	s.update('foobar');
	var sig = s.sign();
	t.ok(sig);
	t.ok(sig instanceof sshpk.Signature);

	var sshPub = key.toPublic().toBuffer('ssh');
	var key2 = sshpk.parseKey(sshPub);
	t.ok(key2.fingerprint().matches(key));

	var v = key2.createVerify('sha512');
	v.update('foobar');
	t.ok(v.verify(sig));

	t.end();
});

test('PrivateKey#createSign on ED25519 key', function (t) {
	var s = KEY_ED25519.createSign('sha512');
	s.write('foobar');
	var sig = s.sign();
	t.ok(sig);
	t.ok(sig instanceof sshpk.Signature);

	var v = KEY_ED25519.createVerify('sha512');
	v.write('foobar');
	t.ok(v.verify(sig));

	var v2 = KEY_ECDSA2.createVerify('sha512');
	v2.write('foobar');
	t.notOk(v2.verify(sig));

	/* ED25519 always uses SHA-512 */
	t.throws(function() {
		KEY_ED25519.createSign('sha1');
	});
	t.throws(function() {
		KEY_ED25519.createVerify('sha256');
	});

	t.end();
});
