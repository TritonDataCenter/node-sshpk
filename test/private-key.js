// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;
var sshpk = require('../lib/index');
var path = require('path');
var fs = require('fs');

var testDir = __dirname;

var ID_RSA_FP = sshpk.parseFingerprint(
    'SHA256:tT5wcGMJkBzNu+OoJYEgDCwIcDAIFCUahAmuTT4qC3s');
var ID_DSA_FP = sshpk.parseFingerprint(
    'SHA256:PCfwpK62grBWrAJceLetSNv9CTrX8yoD0miKf11DBG8');
var ID_ECDSA_FP = sshpk.parseFingerprint(
    'SHA256:e34c67Npv31uMtfVUEBJln5aOcJugzDaYGsj1Uph5DE');
var ID_ECDSA2_FP = sshpk.parseFingerprint(
    'SHA256:Kyu0EMqH8fzfp9RXKJ6kmsk9qKGBqVRtlOuk6bXfCEU');

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

var KEY_RSA, KEY_DSA, KEY_ECDSA, KEY_ECDSA2;

test('setup keys', function (t) {
	KEY_RSA = sshpk.parsePrivateKey(fs.readFileSync(
	    path.join(testDir, 'id_rsa')), 'pem');
	KEY_DSA = sshpk.parsePrivateKey(fs.readFileSync(
	    path.join(testDir, 'id_dsa')), 'pem');
	KEY_ECDSA = sshpk.parsePrivateKey(fs.readFileSync(
	    path.join(testDir, 'id_ecdsa')), 'pem');
	KEY_ECDSA2 = sshpk.parsePrivateKey(fs.readFileSync(
	    path.join(testDir, 'id_ecdsa2')), 'pem');
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
