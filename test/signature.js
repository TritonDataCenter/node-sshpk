// Copyright 2011 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var testDir = path.join(__dirname, 'assets');

var RSA_PEM = fs.readFileSync(path.join(testDir, 'id_rsa'));
var DSA_PEM = fs.readFileSync(path.join(testDir, 'id_dsa'));
var ECDSA_PEM = fs.readFileSync(path.join(testDir, 'id_ecdsa'));
var ED25519_PEM = fs.readFileSync(path.join(testDir, 'id_ed25519'));

var RSA_KEY, DSA_KEY, ECDSA_KEY, ED25519_KEY;

var DSA_SIG_ASN1 = 'MC0CFQCMhYhmerSHEK8h3Dd6DkWQggzY9QIUZ0sK0YNM9X3XfXo+jHiW' +
    'cp7D1zU=';
var ECDSA_SIG_ASN1 = 'MGUCMHkr2PgfR6vhLvXcY9bJOZN1AJAq9+YGmca95AC6iaNy3vqihq' +
    'fuYQMaH5xO7HRdUQIxAN9BGGg2TQ8VL1kIfBzHUXA4eEbhEWStxeHKwscfxr5oj5yh5dI5F' +
    'Fz5o4JnQzaqkQ=='
var RSA_SIG = 'XSnn5R/INegb91WFY29K/oI0LEqEBFMmr6JkeTgw19yD9KsBhnMW5v7XvizWk' +
    'oWYfnpO+LjJMMpYEMVayleexjuYH88EihViCF/VciqSCK0lHpfPQ9NHiKlK+KRdtzNezHta' +
    'YlqCAbk2OAJF/mr/y+0SSm5jrDeJcz/a21gRuf4=';
var DSA_SIG_HEX = '00000007' + '7373682d647373' + '00000028' +
    '8c8588667ab48710af21dc377a0e4590820cd8f5' +
    '674b0ad1834cf57dd77d7a3e8c7896729ec3d735';

var RSA_SIG_SSH = 'AAAAB3NzaC1yc2EAAACAXSnn5R/INegb91WFY29K/oI0LEqEBFMmr6Jke' +
    'Tgw19yD9KsBhnMW5v7XvizWkoWYfnpO+LjJMMpYEMVayleexjuYH88EihViCF/VciqSCK0l' +
    'HpfPQ9NHiKlK+KRdtzNezHtaYlqCAbk2OAJF/mr/y+0SSm5jrDeJcz/a21gRuf4=';

var DSA_SIG2_SSH = 'IcR83A4YPEn22Vnh09S9RHRhVD5fol0BoLbC1wcRpvoR46OZQguEzQ==';

var ECDSA_SIG2_SSH = 'AAAAMHs/mn99fHqPG3YsD5WOcZtLxmKwTvII1zzKKIZCgzmtgw9ttg' +
    '0i5W0yNCEJFc9eMQAAADEA1glXKGoiWzQKaVg0r2RQjnwtioaSV2a0WJFmRdxUi6UzNKbBQ' +
    'PanBc1MjwLVFnck';

var ECDSA2_SIG_SSH = 'AAAAIQCI1U+x3NzeTwPtISDGhGrPaqURX/NiCCbRzrtghOTaewAAAC' +
    'EAvL6M14xBYD1DHACgO+rkZqA+IbN5jcdCUx858CEoz9c=';

var ECDSA_SIG3_SSH = 'AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAABoAAAAMEfV+/DfXI5bYq' +
    'niW7H+KQSBQTqT4ChUtHfCd0AYH+QzwBf16R+H2JjAxuKzIhjjggAAADAlmHXEs07JDWzO+' +
    'cPy1k/gec3OQaKv7UOCcThjA5QQT840JgFbaoR7q71ZdU1Te0o=';

var ED25519_SIG_SSH = 'AAAAC3NzaC1lZDI1NTE5AAAAQI9k67LtavkMlKZgw/vvlY9NfkVGU' +
    '/Vln+nFWvs0Xc0Bkew6FTaR4IZo0q2C4bOsN9jlYSNu3CsMtlrjvQcR9w8=';

test('setup', function(t) {
	RSA_KEY = sshpk.parseKey(RSA_PEM, 'pem');
	DSA_KEY = sshpk.parseKey(DSA_PEM, 'pem');
	ECDSA_KEY = sshpk.parseKey(ECDSA_PEM, 'pem');
	ED25519_KEY = sshpk.parsePrivateKey(ED25519_PEM, 'pem');
	t.end();
});

test('convert RSA sig to SSH format', function(t) {
	var sig = sshpk.parseSignature(RSA_SIG, 'rsa', 'asn1');
	t.strictEqual(sig.toString('ssh'), RSA_SIG_SSH);
	t.end();
});

test('parse an invalid signature', function(t) {
	t.throws(function() {
		sshpk.parseSignature('AAAAA', 'dsa', 'asn1');
	}, sshpk.SignatureParseError);
	t.throws(function() {
		sshpk.parseSignature('AAAAA', 'ecdsa', 'ssh');
	}, sshpk.SignatureParseError);
	t.throws(function() {
		sshpk.parseSignature('', 'rsa', 'ssh');
	}, sshpk.SignatureParseError);
	t.end();
});

test('parse RSA sig in full wire SSH format and verify', function(t) {
	var sig = sshpk.parseSignature(RSA_SIG_SSH, 'rsa', 'ssh');
	var key = sshpk.parseKey(
	    fs.readFileSync(path.join(testDir, 'id_rsa')), 'pem');
	var s = key.createVerify('sha1');
	s.update('foobar');
	t.ok(s.verify(sig));
	t.end();
});

test('convert DSA sig to SSH format and back', function(t) {
	var sig = sshpk.parseSignature(DSA_SIG_ASN1, 'dsa', 'asn1');
	t.strictEqual(sig.toString('asn1'), DSA_SIG_ASN1);
	t.strictEqual(sig.toBuffer('ssh').toString('hex'), DSA_SIG_HEX);
	var sig2 = sshpk.parseSignature(sig.toString('ssh'), 'dsa', 'ssh');
	t.strictEqual(sig2.toString('asn1'), DSA_SIG_ASN1);
	t.end();
});

test('convert ECDSA sig to SSH format and back', function(t) {
	var sig = sshpk.parseSignature(ECDSA_SIG_ASN1, 'ecdsa', 'asn1');
	t.strictEqual(sig.toString('asn1'), ECDSA_SIG_ASN1);
	var sig2 = sshpk.parseSignature(sig.toString('ssh'), 'ecdsa', 'ssh');
	t.strictEqual(sig2.toString('asn1'), ECDSA_SIG_ASN1);
	t.end();
});

test('convert SSH DSA sig and verify', function(t) {
	var key = sshpk.parseKey(
	    fs.readFileSync(path.join(testDir, 'id_dsa')), 'pem');
	var sig = sshpk.parseSignature(DSA_SIG2_SSH, 'dsa', 'ssh');
	var s = key.createVerify();
	s.update('foobar');
	t.ok(s.verify(sig));
	t.end();
});

test('sign with DSA and loopback ssh', function(t) {
	var key = sshpk.parsePrivateKey(
	    fs.readFileSync(path.join(testDir, 'id_dsa')), 'pem');
	var signer = key.createSign();
	signer.update('foobar');
	var sig = signer.sign();

	var data = sig.toBuffer('ssh');
	sig = sshpk.parseSignature(data, 'dsa', 'ssh');

	var s = key.createVerify();
	s.update('foobar');
	t.ok(s.verify(sig));
	t.end();
});

test('sign with RSA and loopback ssh', function(t) {
	var key = sshpk.parsePrivateKey(
	    fs.readFileSync(path.join(testDir, 'id_rsa')), 'pem');
	var signer = key.createSign();
	signer.update('foobar');
	var sig = signer.sign();

	var data = sig.toBuffer('ssh');
	sig = sshpk.parseSignature(data, 'rsa', 'ssh');

	var s = key.createVerify();
	s.update('foobar');
	t.ok(s.verify(sig));
	t.end();
});

test('sign with ECDSA-256 and loopback ssh', function(t) {
	var key = sshpk.parsePrivateKey(
	    fs.readFileSync(path.join(testDir, 'id_ecdsa2')), 'pem');
	var signer = key.createSign();
	signer.update('foobar');
	var sig = signer.sign();

	var data = sig.toBuffer('ssh');
	sig = sshpk.parseSignature(data, 'ecdsa', 'ssh');

	var s = key.createVerify();
	s.update('foobar');
	t.ok(s.verify(sig));
	t.end();
});

test('convert SSH ECDSA-256 sig and verify', function(t) {
	var key = sshpk.parseKey(
	    fs.readFileSync(path.join(testDir, 'id_ecdsa2')), 'pem');
	var sig = sshpk.parseSignature(ECDSA2_SIG_SSH, 'ecdsa', 'ssh');
	var s = key.createVerify();
	s.update('foobar');
	t.ok(s.verify(sig));
	t.end();
});

test('signature of wrong type fails verification', function(t) {
	var key = sshpk.parseKey(
	    fs.readFileSync(path.join(testDir, 'id_ecdsa')), 'pem');
	var sig = sshpk.parseSignature(ECDSA_SIG_ASN1, 'rsa', 'asn1');
	var s = key.createVerify();
	s.update('foobar');
	t.notOk(s.verify(sig));
	t.end();
});

test('signature on wrong data fails verification', function(t) {
	var key = sshpk.parseKey(
	    fs.readFileSync(path.join(testDir, 'id_ecdsa2')), 'pem');
	var sig = sshpk.parseSignature(ECDSA2_SIG_SSH, 'ecdsa', 'ssh');
	var s = key.createVerify();
	s.update('foonotbar');
	t.ok(!s.verify(sig));
	t.end();
});

test('signature with wrong key fails verification', function(t) {
	var key = sshpk.parseKey(
	    fs.readFileSync(path.join(testDir, 'id_ecdsa')), 'pem');
	var sig = sshpk.parseSignature(ECDSA2_SIG_SSH, 'ecdsa', 'ssh');
	var s = key.createVerify();
	s.update('foobar');
	t.ok(!s.verify(sig));
	t.end();
});

test('convert SSH ECDSA-384 sig and verify', function(t) {
	var key = sshpk.parseKey(
	    fs.readFileSync(path.join(testDir, 'id_ecdsa')), 'pem');
	var sig = sshpk.parseSignature(ECDSA_SIG2_SSH, 'ecdsa', 'ssh');
	var s = key.createVerify();
	s.update('foobar');
	t.ok(s.verify(sig));
	t.end();
});

test('convert full wire SSH ECDSA-384 sig and verify', function(t) {
	var key = sshpk.parseKey(
	    fs.readFileSync(path.join(testDir, 'id_ecdsa')), 'pem');
	var sig = sshpk.parseSignature(ECDSA_SIG3_SSH, 'ecdsa', 'ssh');
	var s = key.createVerify();
	s.update('foobar');
	t.ok(s.verify(sig));
	t.end();
});

if (process.version.match(/^v0\.[0-9]\./))
	return;

test('parse ED25519 sig in full wire SSH format and verify', function(t) {
	var sig = sshpk.parseSignature(ED25519_SIG_SSH, 'ed25519', 'ssh');
	var s = ED25519_KEY.createVerify();
	s.update('foobar');
	t.ok(s.verify(sig));
	t.end();
});

test('sign with ED25519 key and convert to SSH format', function(t) {
	var s = ED25519_KEY.createSign();
	s.update('foobar');
	var sig = s.sign();
	t.strictEqual(sig.toString('ssh'), ED25519_SIG_SSH);
	t.end();
});
