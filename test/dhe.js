// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var ED_KEY, C_KEY;
var C_SSH;

test('setup', function (t) {
	var k = fs.readFileSync(path.join(__dirname, 'id_ed25519'));
	ED_KEY = sshpk.parsePrivateKey(k);
	t.end();
});

test('derive ed25519 -> curve25519', function (t) {
	C_KEY = ED_KEY.derive('curve25519');
	t.strictEqual(C_KEY.type, 'curve25519');
	t.strictEqual(C_KEY.size, 256);
	C_SSH = C_KEY.toBuffer('ssh');
	t.end();
});

test('derive curve25519 -> ed25519', function (t) {
	var k = sshpk.parsePrivateKey(C_SSH);
	t.strictEqual(k.type, 'curve25519');
	t.strictEqual(k.size, 256);
	var k2 = k.derive('ed25519');
	t.strictEqual(k2.type, 'ed25519');
	t.ok(k2.fingerprint().matches(ED_KEY));
	t.strictEqual(k2.part.r.toString('base64'),
	    ED_KEY.part.r.toString('base64'));
	t.end();
});
