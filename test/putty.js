// Copyright 2018 Joyent, Inc.	All rights reserved.

var test = require('tape').test;
var fs = require('fs');
var path = require('path');
var sshpk = require('../lib/index');

var testDir = path.join(__dirname, 'assets');

var PUTTY_DSA, PUTTY_DSA_PUB, PUTTY_RSA, PUTTY_DSA_SSH, PUTTY_DSA_LONG;

test('setup', function (t) {
	PUTTY_DSA = fs.readFileSync(path.join(testDir, 'dsa.ppk'));
	PUTTY_DSA_PUB = fs.readFileSync(path.join(testDir, 'dsa-pub.ppk'));
	PUTTY_RSA = fs.readFileSync(path.join(testDir, 'rsa.ppk'));
	PUTTY_DSA_SSH = fs.readFileSync(path.join(testDir, 'dsa-ppk.pub'));
	PUTTY_DSA_LONG = fs.readFileSync(path.join(testDir, 'dsa-pub-err.ppk'));
	t.end();
});

test('parse DSA ppk file', function (t) {
	var k = sshpk.parseKey(PUTTY_DSA, 'putty');
	t.strictEqual(k.type, 'dsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:wWAQNw7Px2Hymk7kimFL35jzdLqRt9V9hB5RH20YX8s');
	t.strictEqual(k.comment, 'dsa-key-20170331');
	var pub = k.toString('ssh');
	t.strictEqual(pub, PUTTY_DSA_SSH.toString('ascii').trim());
	t.end();
});

test('parse DSA ppk file pub-only truncated', function (t) {
	var k = sshpk.parseKey(PUTTY_DSA_PUB, 'putty');
	t.strictEqual(k.type, 'dsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:wWAQNw7Px2Hymk7kimFL35jzdLqRt9V9hB5RH20YX8s');
	t.strictEqual(k.comment, 'dsa-key-20170331');
	t.end();
});

test('parse RSA ppk file', function (t) {
	var k = sshpk.parseKey(PUTTY_RSA, 'putty');
	t.strictEqual(k.type, 'rsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:WqDr0IdKUPtbitHUtWGGsA/xV/JhxPbVJG+E0SLWEig');
	t.strictEqual(k.comment, 'rsa-key-20170331');
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
	var k = sshpk.parseKey(PUTTY_RSA, 'auto');
	t.strictEqual(k.type, 'rsa');
	t.end();
});

test('generate dsa', function (t) {
	var k = sshpk.parseKey(PUTTY_DSA_SSH);
	var ppk = k.toString('putty');
	t.strictEqual(ppk, PUTTY_DSA_PUB.toString('ascii'));
	t.end();
});
