// Copyright 2011 Joyent, Inc.  All rights reserved.

var test = require('tap').test;

var sshpubkey = require('../lib/index');

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

test('fingerprint', function(t) {
	var k = sshpubkey.parseKey(SSH_1024, 'ssh');
	var fp = k.fingerprint('md5').toString();
	t.equal(fp, '59:a4:61:0e:38:18:9f:0f:28:58:2a:27:f7:65:c5:87');
	t.end();
});

test('sha1 fingerprint', function(t) {
	var k = sshpubkey.parseKey(SSH_1024, 'ssh');
	var fp = k.fingerprint('sha1').toString();
	t.equal(fp, 'SHA1:3JP2y/wCv8KnvAunLz7EjcEhKeE');
	t.end();
});

test('sha256 fingerprint', function(t) {
	var k = sshpubkey.parseKey(SSH_1024, 'ssh');
	var fp = k.fingerprint('sha256').toString();
	t.equal(fp, 'SHA256:n0akL6ACGYcTARqym7TL4DStmNFpxMkSlFwuCfqNP9M');
	t.end();
});

test('fingerprint matches', function(t) {
	var k1 = sshpubkey.parseKey(SSH_1024, 'ssh');
	var k2 = sshpubkey.parseKey(SSH_2048, 'ssh');
	var f = sshpubkey.parseFingerprint(
	    'SHA256:PYC9kPVC6J873CSIbfp0LwYeczP/W4ffObNCuDJ1u5w');
	t.ok(f.matches(k2));
	t.ok(!f.matches(k1));
	t.end();
});
