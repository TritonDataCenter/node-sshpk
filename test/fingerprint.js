// Copyright 2011 Joyent, Inc.  All rights reserved.

var test = require('tap').test;

var Key = require('../lib/index').Key;
var Fingerprint = require('../lib/fingerprint').Fingerprint;

var SSH_1024 = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAvad19ePSDckmgmo6Unqmd8' +
	'n2G7o1794VN3FazVhV09yooXIuUhA+7OmT7ChiHueayxSubgL2MrO/HvvF/GGVUs/t3e0u4' +
	'5YwRC51EVhyDuqthVJWjKrYxgDMbHru8fc1oV51l0bKdmvmJWbA/VyeJvstoX+eiSGT3Jge' +
	'egSMVtc= mark@foo.local';

test('fingerprint', function(t) {
	var k = Key.parse(SSH_1024, 'ssh');
	var fp = k.fingerprint('md5').toString();
	t.equal(fp, '59:a4:61:0e:38:18:9f:0f:28:58:2a:27:f7:65:c5:87');
	t.end();
});

test('sha1 fingerprint', function(t) {
	var k = Key.parse(SSH_1024, 'ssh');
	var fp = k.fingerprint('sha1').toString();
	t.equal(fp, 'SHA1:3JP2y/wCv8KnvAunLz7EjcEhKeE');
	t.end();
});

test('sha256 fingerprint', function(t) {
	var k = Key.parse(SSH_1024, 'ssh');
	var fp = k.fingerprint('sha256').toString();
	t.equal(fp, 'SHA256:n0akL6ACGYcTARqym7TL4DStmNFpxMkSlFwuCfqNP9M');
	t.end();
});
