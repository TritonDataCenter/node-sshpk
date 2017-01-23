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

function simpleTest(t, csr) {
	csr = csr || sshpk.parseCertificateSigningRequest(
	    fs.readFileSync(path.join(testDir, 'simple-csr.pem')), 'pem');
	t.strictEqual(csr.version, 0);
	t.strictEqual(csr.type, 'certificate-signing-request');
	t.strictEqual(csr.subjectKey.type, 'rsa');
	t.strictEqual(csr.subjects[0].type, 'host');
	t.strictEqual(csr.subjects[0].hostname, 'de.doof.de');
	t.strictEqual(csr.signatures.x509.algo, 'rsa-sha256');

	t.strictEqual(false, !!csr.extentions);
	t.end();
}

test('simple parse csr', simpleTest);

// test('simple der equal parsed pem toBuffer', function(t) {
// 	var pem = sshpk.parseCertificateSigningRequest(
// 	    fs.readFileSync(path.join(testDir, 'simple-csr.pem')), 'pem');
// 	var pder = sshpk.parseCertificateSigningRequest(
// 	    fs.readFileSync(path.join(testDir, 'simple-csr.der')), 'der');
// 	var der = fs.readFileSync(path.join(testDir, 'simple-csr.der'));
// 	console.log(pder.toBuffer('pem').toString())
// 	t.ok(0==der.compare(pder.toBuffer('der')), "pem-der")
// 	t.ok(0==der.compare(pem.toBuffer('der')), "der-der")
//     t.end();
// })

function complexTest(t, csr) {
	csr = csr || sshpk.parseCertificateSigningRequest(
	    fs.readFileSync(path.join(testDir, 'test-csr.pem')), 'pem');
	t.strictEqual(csr.subjectKey.type, 'rsa');
	t.strictEqual(csr.subjects[0].type, 'host');
	t.strictEqual(csr.subjects[0].hostname, 'de.doof.de');
	t.strictEqual(csr.signatures.x509.algo, 'rsa-sha256');

	t.strictEqual(true, !!csr.extentions);
	t.strictEqual(csr.extentions[0].components[0].oid, '2.5.29.17')
	t.strictEqual(Buffer.from(csr.extentions[0].components[0].value).slice(4).toString(), 'www.doof.de')
	t.strictEqual(csr.extentions[0].components[1].oid, '2.5.29.18')
	t.strictEqual(Buffer.from(csr.extentions[0].components[1].value).slice(4).toString(), 'www.doox.de')
	t.end();
}

test('complex parse csr', complexTest);

// test('complex der equal parsed pem toBuffer', function(t) {
// 	var pem = sshpk.parseCertificateSigningRequest(
// 	    fs.readFileSync(path.join(testDir, 'test-csr.pem')), 'pem');
// 	var pder = sshpk.parseCertificateSigningRequest(
// 	    fs.readFileSync(path.join(testDir, 'test-csr.der')), 'der');
// 	var der = fs.readFileSync(path.join(testDir, 'test-csr.der'));
// 	t.ok(0==der.compare(pder.toBuffer('der')), "pem-der")
// 	t.ok(0==der.compare(pem.toBuffer('der')), "der-der")
//     t.end();
// })


test('simple parse write csr', function (t) {
	var csr = sshpk.parseCertificateSigningRequest(
	fs.readFileSync(path.join(testDir, 'simple-csr.pem')), 'pem');
	var buf = csr.toBuffer("pem")
	// console.log(buf.toString())
	csr = sshpk.parseCertificateSigningRequest(buf, 'pem')
	simpleTest(t, csr)
})

test('wr parse write csr', function (t) {
	var csr = sshpk.parseCertificateSigningRequest(
	fs.readFileSync(path.join(testDir, 'test-csr.pem')), 'pem');
	var buf = csr.toBuffer("pem")
	// console.log(buf.toString())
	csr = sshpk.parseCertificateSigningRequest(buf, 'pem')
	complexTest(t, csr)
})

