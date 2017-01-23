// Copyright 2016 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var sinon = require('sinon');

var testDir = path.join(__dirname, 'assets');

test('setup', function (t) {
	// var d = fs.readFileSync(path.join(testDir, 'id_dsa'));
	t.end();
});

test('parse csr', function (t) {
	var cert = sshpk.parseCertificateRequest(
	    fs.readFileSync(path.join(testDir, 'test-csr.pem')), 'pem');
	t.strictEqual(cert.subjectKey.type, 'rsa');
	t.strictEqual(cert.subjects[0].type, 'host');
	t.strictEqual(cert.subjects[0].hostname, 'cr.joyent.us');
	var fp = cert.fingerprint('sha1').toString('hex');
	t.strictEqual(fp.toUpperCase(),
	    '59:8B:FA:BF:F7:DD:D4:B5:7E:8F:53:61:B1:65:0D:DF:F5:4B:CC:72');
	t.end();
});

test('create csr', function (t) {
})

