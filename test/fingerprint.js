// Copyright 2011 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');

var SSH_1024 = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAvad19ePSDckmgmo6Unqmd8' +
	'n2G7o1794VN3FazVhV09yooXIuUhA+7OmT7ChiHueayxSubgL2MrO/HvvF/GGVUs/t3e0u4' +
	'5YwRC51EVhyDuqthVJWjKrYxgDMbHru8fc1oV51l0bKdmvmJWbA/VyeJvstoX+eiSGT3Jge' +
	'egSMVtc= mark@foo.local';

var SSH_2048 = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDrm0RN90tGM0/vcJgzJ4uW9' +
	'aT9iRzNQXYq4OQvsVgb2xRZ0mLwjmTOY4MJ2qWk8ENptY5yQBolpjjI0ziWaFfgo56fe' +
	'XC1iRN/FkBQw+JJSjOwzTWw8JWU5HF+mt9BPzj6hC2dVniCHt+9lRLDqqYd14bhDMHE0' +
	'XdRtX7Fv6bRkE+XxHdo8ITh1fZVShV3ukKC0KJbFBlNu8+Uu9bl8ZioyyFjwiw6bzQNY' +
	'3NXYFotzA9qDgHl+V0sldJLBCB+uilW1dns6pAfH2FxX3euZwnm+FGSKi9tI2wAW1EoV' +
	'SoBmUZAYAs+BqffNJHnIv1dexMmwdJdlZUeRK1Q1ES15gxx '+
	'mark@foo.local';

var SSH_MPNORM = 'ssh-rsa AAAAB3NzaC1yc2EAAAAEAAEAAQAAAQEAjb4zpS1Sl1m4szYzV/o' +
	'GgHmYM5zI/yvWESgltLZVpSY6i3UDljPEPJSRdCiDnPl8qgyWtU4YbRwctmZUqA9DvKA' +
	'GCcFSZ9OLkhBruPvKFi0Q+fgBEbR/tlLgXppi1EXEZwtUe97axsrp7DSrgbUYfNNRTtO' +
	'eVnAlosM+KkER8xIqNWJ4aQEPBE2MA0YcC4PYT/KdD1ap8Xdxucsy9YPVrqKT0Zql0Dy' +
	'SPt8hTmtJe78KjWsbAjaQvUbNg6lUxCGf6A/qym8smu9fGaYg2MUReVyhvxavBS64IV7' +
	'FrKCE76+lDQfM4UQqszW+ZtSv9EwbUPF7SyAHzKB4HRSgBLDViw== token-key';

var ED_SSH = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEi0pkfPe/+kbmnTSH0mfr0J4' +
	'Fq7M7bshFAKB6uCyLDm foo@bar';

var ED2_SSH = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPu+h5Zu8GHgh8seZ9GittT' +
	'WHfpbi0vkNksH77yaMKqD';

var ED2_PEM = '-----BEGIN PUBLIC KEY-----\n' +
	'MCowBQYDK2VwAyEA+76Hlm7wYeCHyx5n0aK21NYd+luLS+Q2SwfvvJowqoM=\n' +
	'-----END PUBLIC KEY-----\n';

test('fingerprint', function(t) {
	var k = sshpk.parseKey(SSH_1024, 'ssh');
	var fp = k.fingerprint('md5').toString();
	t.equal(fp, '59:a4:61:0e:38:18:9f:0f:28:58:2a:27:f7:65:c5:87');
	t.end();
});

test('fingerprint of key w/non-normalized mpint', function(t) {
	var k = sshpk.parseKey(SSH_MPNORM, 'ssh');
	var fp = k.fingerprint('sha256').toString();
	t.equal(fp, 'SHA256:uOCmXUwfjh90NlLAxI9/vGG9ewUqcHlM5dYYFLJlZyc');
	t.end();
});

test('sha1 fingerprint', function(t) {
	var k = sshpk.parseKey(SSH_1024, 'ssh');
	var fp = k.fingerprint('sha1').toString();
	t.equal(fp, 'SHA1:3JP2y/wCv8KnvAunLz7EjcEhKeE');
	t.end();
});

test('sha256 fingerprint', function(t) {
	var k = sshpk.parseKey(SSH_1024, 'ssh');
	var fp = k.fingerprint('sha256').toString();
	t.equal(fp, 'SHA256:n0akL6ACGYcTARqym7TL4DStmNFpxMkSlFwuCfqNP9M');
	t.end();
});

test('fingerprint with invalid algo', function(t) {
	var k = sshpk.parseKey(SSH_1024, 'ssh');
	t.throws(function() {
		k.fingerprint('foo1234');
	}, sshpk.InvalidAlgorithmError);
	t.end();
});

test('parse fingerprint with invalid algo', function(t) {
	t.throws(function () {
		sshpk.parseFingerprint('FOO1234:aaaaaaa');
	});
	t.end();
});

test('fingerprint matches', function(t) {
	var k1 = sshpk.parseKey(SSH_1024, 'ssh');
	var k2 = sshpk.parseKey(SSH_2048, 'ssh');
	var f = sshpk.parseFingerprint(
	    'SHA256:PYC9kPVC6J873CSIbfp0LwYeczP/W4ffObNCuDJ1u5w');
	t.ok(f.matches(k2));
	t.ok(!f.matches(k1));
	t.end();
});

test('fingerprint of ed25519 key', function(t) {
	var k = sshpk.parseKey(ED_SSH, 'ssh');
	var f = sshpk.parseFingerprint(
	    'SHA256:2UeFLCUKw2lvd8O1zfINNVzE0kUcu2HJHXQr/TGHt60');
	t.ok(f.matches(k));
	t.end();
});

test('fingerprint of non-normalized ed25519 key', function(t) {
	var k = sshpk.parseKey(ED2_SSH, 'ssh');
	var f = sshpk.parseFingerprint(
	    'SHA256:k1NS4bL2M1fG3JKd8WI9t6ETq+6VeRtvLAxt8DC0exE');
	t.ok(f.matches(k));
	k = sshpk.parseKey(ED2_PEM, 'pem');
	t.ok(f.matches(k));
	t.end();
});

test('invalid fingerprints', function(t) {
	t.throws(function () {
		var fp = sshpk.parseFingerprint(
		    'zzzzz!!!');
	}, sshpk.FingerprintFormatError);
	t.throws(function () {
		var fp = sshpk.parseFingerprint(
		    'SHA256:XXX%!@!#!@#!*');
	}, sshpk.FingerprintFormatError);
	t.throws(function () {
		var fp = sshpk.parseFingerprint(
		    '59:a4:61:0e:38:18:9f:0f:28:58:2a:27:f7:65:c5:8g');
	}, sshpk.FingerprintFormatError);
	t.end();
});
