// Copyright 2017 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');
var sshpk_dhe;
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var sinon = require('sinon');
var Buffer = require('safer-buffer').Buffer;

/* No need to do these on an older node */
if (crypto.createECDH === undefined)
	return;

var ED_KEY, ED2_KEY, EC_KEY, EC2_KEY, ECOUT_KEY, DS_KEY, DS2_KEY, DSOUT_KEY;
var C_KEY, C2_KEY;
var C_SSH;

var testDir = path.join(__dirname, 'assets');

var sandbox;

test('set up sandbox', function (t) {
	sandbox = sinon.sandbox.create();
	sandbox.stub(crypto, 'createECDH');
	t.ok(crypto.createECDH('prime256v1') === undefined);

	var name = require.resolve('../lib/dhe');
	delete (require.cache[name]);
	sshpk_dhe = require('../lib/dhe');

	t.end();
});

test('setup', function (t) {
	var k = fs.readFileSync(path.join(testDir, 'id_ed25519'));
	ED_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(testDir, 'id_ed255192'));
	ED2_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(testDir, 'id_ecdsa2'));
	EC_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(testDir, 'id_ecdsa3'));
	EC2_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(testDir, 'id_ecdsa'));
	ECOUT_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(testDir, 'id_dsa2'));
	DS_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(testDir, 'id_dsa3'));
	DS2_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(testDir, 'id_dsa'));
	DSOUT_KEY = sshpk.parsePrivateKey(k);
	t.end();
});

test('ecdhe shared secret', function (t) {
	var dh1 = new sshpk_dhe.DiffieHellman(EC_KEY);
	var secret1 = dh1.computeSecret(EC2_KEY.toPublic());
	t.ok(Buffer.isBuffer(secret1));
	t.deepEqual(secret1, Buffer.from(
	    'UoKiio/gnWj4BdV41YvoHu9yhjynGBmphZ1JFbpk30o=', 'base64'));

	var dh2 = new sshpk_dhe.DiffieHellman(EC2_KEY);
	var secret2 = dh2.computeSecret(EC_KEY.toPublic());
	t.deepEqual(secret1, secret2);
	t.end();
});

test('ecdhe generate ephemeral', function (t) {
	var dh = new sshpk_dhe.DiffieHellman(EC_KEY);
	var ek = dh.generateKey();
	t.ok(ek instanceof sshpk.PrivateKey);
	t.strictEqual(ek.type, 'ecdsa');
	t.strictEqual(ek.curve, 'nistp256');

	var secret1 = dh.computeSecret(EC_KEY);
	var secret2 = (new sshpk_dhe.DiffieHellman(EC_KEY)).computeSecret(ek);
	t.deepEqual(secret1, secret2);
	t.end();
});

test('ecdhe reject diff curves', function (t) {
	var dh = new sshpk_dhe.DiffieHellman(EC_KEY);
	t.throws(function () {
		dh.computeSecret(ECOUT_KEY.toPublic());
	});
	t.throws(function () {
		dh.setKey(ECOUT_KEY);
	});
	dh.setKey(EC2_KEY);
	t.strictEqual(dh.getKey().fingerprint().toString(),
	    EC2_KEY.fingerprint().toString());
	t.strictEqual(dh.getPublicKey().fingerprint().toString(),
	    EC2_KEY.fingerprint().toString());

	var dh2 = new sshpk_dhe.DiffieHellman(ECOUT_KEY);
	t.throws(function () {
		dh2.setKey(EC_KEY);
	});

	dh2 = new sshpk_dhe.DiffieHellman(EC_KEY);
	t.throws(function () {
		dh2.setKey(C_KEY);
	});
	t.end();
});

test('tear down sandbox', function (t) {
	sandbox.restore();
	t.end();
});
