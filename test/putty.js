// Copyright 2018 Joyent, Inc.	All rights reserved.

var test = require('tape').test;
var fs = require('fs');
var path = require('path');
var sshpk = require('../lib/index');

var testDir = path.join(__dirname, 'assets');

var PUTTY_DSA, PUTTY_DSA_PUB, PUTTY_RSA, PUTTY_RSA_SSH, PUTTY_DSA_SSH, PUTTY_DSA_LONG;

test('setup', function (t) {
	PUTTY_DSA = fs.readFileSync(path.join(testDir, 'dsa.ppk'));
	PUTTY_DSA_PUB = fs.readFileSync(path.join(testDir, 'dsa-pub.ppk'));
	PUTTY_RSA = fs.readFileSync(path.join(testDir, 'rsa.ppk'));
	PUTTY_RSA_SSH = fs.readFileSync(path.join(testDir, 'rsa-ppk'));
	PUTTY_DSA_SSH = fs.readFileSync(path.join(testDir, 'dsa-ppk'));
	PUTTY_DSA_LONG = fs.readFileSync(path.join(testDir, 'dsa-pub-err.ppk'));
	t.end();
});

test('parse DSA ppk file', function (t) {
	var k = sshpk.parsePrivateKey(PUTTY_DSA, 'putty', { passphrase: 'foobar' });
	t.strictEqual(k.type, 'dsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:l95D4D6waUPH49RvkOLHWzwGSNKqg3GZx5f28UdcmDo');
	t.strictEqual(k.comment, 'dsa-key-20210515');
	var priv = k.toString('pem').trim();
	t.strictEqual(priv, PUTTY_DSA_SSH.toString('ascii').trim());
	t.end();
});

test('parse DSA ppk file pub-only truncated', function (t) {
	var k = sshpk.parseKey(PUTTY_DSA_PUB, 'putty');
	t.strictEqual(k.type, 'dsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:l95D4D6waUPH49RvkOLHWzwGSNKqg3GZx5f28UdcmDo');
	t.strictEqual(k.comment, 'dsa-key-20210515');
	t.end();
});

test('parse RSA ppk file', function (t) {
	var k = sshpk.parsePrivateKey(PUTTY_RSA, 'putty', { passphrase: 'foobar' });
	t.strictEqual(k.type, 'rsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:DavVLu91hTy2jkSMKbb6maid8kpoCOP5YkB4Y3UX+dQ');
	t.strictEqual(k.comment, 'rsa-key-20210515');

	var priv = k.toString('pem').trim();
	t.strictEqual(priv, PUTTY_RSA_SSH.toString('ascii').trim());
	t.end();
});

test('parse garbage as putty', function (t) {
	t.throws(function () {
		sshpk.parseKey('asdflkasdjflasjf', 'putty');
	}, /first line/i);
	t.throws(function () {
		sshpk.parseKey(PUTTY_DSA_LONG, 'putty');
	}, /public-lines/i);
	t.throws(function () {
		var data = PUTTY_DSA.toString('ascii').
		    replace(/: ssh-dss/, ': ssh-rsa');
		sshpk.parseKey(data, 'putty');
	}, /algorithm mismatch/i);
	t.end();
});

test('parse RSA ppk file with auto', function (t) {
	var k = sshpk.parseKey(PUTTY_RSA, 'auto', { passphrase: 'foobar' });
	t.strictEqual(k.type, 'rsa');
	t.end();
});

test('generate dsa', function (t) {
	var k = sshpk.parseKey(PUTTY_DSA_SSH);
	k.comment = 'dsa-key-20210515'
	var ppk = k.toString('putty');
	t.strictEqual(ppk, PUTTY_DSA_PUB.toString('ascii'));
	t.end();
});
