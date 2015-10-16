// Copyright 2011 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');

var SSH_1024 = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAvad19ePSDckmgmo6Unqmd8' +
	'n2G7o1794VN3FazVhV09yooXIuUhA+7OmT7ChiHueayxSubgL2MrO/HvvF/GGVUs/t3e0u4' +
	'5YwRC51EVhyDuqthVJWjKrYxgDMbHru8fc1oV51l0bKdmvmJWbA/VyeJvstoX+eiSGT3Jge' +
	'egSMVtc= mark@foo.local';

var SSH_1133 = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAjhShSqMBQvr+UtupcZj+l15' +
    'W9LKZ5NDKlUY5af6sGQTaaKCg1Ag5tsi3TrQeAqykdrz7Ugu3BPkLlgk2NvqziX6FdFKjw' +
    'hEEOsHPDFy5Z3ak4oYicHYZVg34pUYvps7dVbYE8D4Ba70txpMEgB3YIS+hUdqiHCIxZKW' +
    'V0PCXTAjjhDyN7I9KI7F4bSAGNf0=';

var PEM_2048 = '-----BEGIN PUBLIC KEY-----\n' +
	'MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAr+isTwMYqwCAcY0Yb2F0\n' +
	'pF+/F4/wxGzcrLR2PrgoBXwjj/TnEA3tJ7v08Rru3lAd/O59B6TbXOsYbQ+2Syd8\n' +
	'2Dm8L3SJRNlZJ6DZUOAwnTOoNgkfH2CsbGS84aTPTeXjmMsw52GvQ9yWFDUglHzM\n' +
	'IzK2iSHWNl1dAaBEiddifGmrpUTPJ5Tt7l8YS4jdaBf6klS+3CvL6xET/RjZhKGt\n' +
	'rrgsRRYUB2XVtgQhKDu7PtDdlpy4+VISdVhZSlXFnBhya/1KxLS5UFHSAdOjdxzW\n' +
	'1bh3cPzNtuPXZaiWUHvyIWpGVCzj5NyeDXcc7n0E20yx9ZDkAITuI8X49rnQzuCN\n' +
	'5QIBIw==\n' +
	'-----END PUBLIC KEY-----\n';

var ECDSA_256 = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIb' +
	'mlzdHAyNTYAAABBBDxYMQuEL51ja1vNXsH8gFXmOjJhVEI9Osv+rvt8vHjJK4FyIc' +
	'46H2406iAGE/rZcqeSjPbmcORXgCNNBlLJ0QQ= ' +
	'alex.wilson@awilson-mbp.local';

var DSA_1024 = 'ssh-dss AAAAB3NzaC1kc3MAAACBAKK5sckoM05sOPajUcTWG0zPTvyRmj6' +
	'YQ1g2IgezUUrXgY+2PPy07+JrQi8SN9qr/CBP+0q0Ec48qVFf9LlkUBwu9Jf5HTUVNiKNj3c' +
	'SRPFH8HqZn+nxhVsOLhnHWxgDQ8OOm48Ma61NcYVo2B0Ne8cUs8xSqLqba2EG9ze87FQZAAA' +
	'AFQCVP/xpiAofZRD8L4QFwxOW9krikQAAAIACNv0EmKr+nIA13fjhpiqbYYyVXYOiWM4cmOD' +
	'G/d1J8/vR4YhWHWPbAEw7LD0DEwDIHLlRZr/1jsHbFcwt4tzRs95fyHzpucpGhocmjWx43qt' +
	'xEhDeJrxPlkIXHakciAEhoo+5YeRSSgRse5PrZDosdr5fA+DADs8tnto5Glf5owAAAIBHcEF' +
	'5ytvCRiKbsWKOgeMZ7JT/XGX+hMhS7aaJ2IspKj7YsWada1yBwoM6yYHtlpnGsq/PoPaZU8K' +
	'40f47psV6OhSh+/O/jgqLS/Ur2c0mQQqIb7vvkc7he/SPOQAqyDmyYFBuazuSf2s9Uy2hfvj' +
	'Wgb6X+vN9W8SOb2668IL7Vg== mark@bluesnoop.local';

test('rsa1024 key metadata', function(t) {
	var k = sshpk.parseKey(SSH_1024, 'ssh');
	t.equal(k.type, 'rsa');
	t.equal(k.size, 1024);
	t.end();
});

test('rsa1133 key metadata', function(t) {
	var k = sshpk.parseKey(SSH_1133, 'ssh');
	t.equal(k.type, 'rsa');
	t.equal(k.size, 1133);
	t.end();
});

test('dsa1024 key metadata', function(t) {
	var k = sshpk.parseKey(DSA_1024, 'ssh');
	t.equal(k.type, 'dsa');
	t.equal(k.size, 1024);
	t.end();
});

test('rsa2048 pem key metadata', function(t) {
	var k = sshpk.parseKey(PEM_2048, 'pem');
	t.equal(k.type, 'rsa');
	t.equal(k.size, 2048);
	t.end();
});

test('ecdsa256 key metadata', function(t) {
	var k = sshpk.parseKey(ECDSA_256, 'ssh');
	t.equal(k.type, 'ecdsa');
	t.equal(k.curve, 'nistp256');
	t.equal(k.size, 256);
	t.end();
});
