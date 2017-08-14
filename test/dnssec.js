// Copyright 2017 Joyent, Inc.	All rights reserved.

var test = require('tape').test;
var fs = require('fs');
var path = require('path');
var sshpk = require('../lib/index');
var testDir = path.join(__dirname, 'assets');

/*
 * Generated with:
 *     'dnssec-keygen -T KEY -a rsasha1 -b 1024 -n USER rsatest'
 *
 * which outputs two files named 'Krsatest.+005+57206.private' and
 * 'Krsatest.+005+57206.key'
 */
var DNSSEC_RSA, DNSSEC_RSA_PUB, PEM_RSA, PEM_RSA_PUB;

/*
 * Generated with:
 *     'dnssec-keygen -T KEY -a ECDSAP256SHA256 -n USER ecdsatest'
 *
 * which outputs two files named 'Kecdsatest.+013+43896.private' and
 * 'Kecdsatest.+013+43896.key'
 */
var DNSSEC_ECDSA, DNSSEC_ECDSA_PUB, PEM_ECDSA, PEM_ECDSA_PUB;

function readAsString(f) {
        var s = fs.readFileSync(path.join(testDir, f));
        return s.toString('utf8');
}

test('setup', function (t) {
        DNSSEC_RSA = readAsString('Krsatest.+005+57206.private');
        DNSSEC_RSA_PUB = readAsString('Krsatest.+005+57206.key');
        PEM_RSA = readAsString('Krsatest.+005+57206.pem');
        PEM_RSA_PUB = readAsString('Krsatest.+005+57206_pub.pem');

        DNSSEC_ECDSA = readAsString('Kecdsatest.+013+43896.private');
        DNSSEC_ECDSA_PUB = readAsString('Kecdsatest.+013+43896.key');
        PEM_ECDSA = readAsString('Kecdsatest.+013+43896.pem');
        PEM_ECDSA_PUB = readAsString('Kecdsatest.+013+43896_pub.pem');
	t.end();
});

// --- Tests
// read tests
test('1024b dnssec to pem private key', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_RSA, 'dnssec');
	t.strictEqual(k.toString('pem'), PEM_RSA);
	t.end();
});

test('1024b dnssec to pem public key', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_RSA, 'dnssec');
	t.strictEqual(k.toPublic().toString('pem'), PEM_RSA_PUB);
	t.end();
});

test('1024b dnssec public key to pem', function(t) {
	var k = sshpk.parseKey(DNSSEC_RSA_PUB, 'dnssec');
	t.strictEqual(k.toString('pem'), PEM_RSA_PUB);
	t.end();
});

test('1024b auto dnssec to pem private key', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_RSA, 'auto');
	t.strictEqual(k.toString('pem'), PEM_RSA);
	t.end();
});

test('1024b auto dnssec public key to pem', function(t) {
	var k = sshpk.parseKey(DNSSEC_RSA_PUB, 'auto');
	t.strictEqual(k.toString('pem'), PEM_RSA_PUB);
	t.end();
});

test('ecdsa dnssec to pem private key', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_ECDSA, 'dnssec');
	t.strictEqual(k.toString('pem'), PEM_ECDSA);
	t.end();
});

test('ecdsa dnssec to pem public key', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_ECDSA, 'dnssec');
	t.strictEqual(k.toPublic().toString('pem'), PEM_ECDSA_PUB);
	t.end();
});

// write tests
//--- Tests

function stripDNSSECTimestamp(m) {
	var out = []
	var lines = m.split('\n');
	lines.forEach(function(line) {
		if (line.match(/^Created.*/) || line.match(/^Publish.*/) ||
		    line.match(/^Activate.*/)) {
                        return;
		} else {
			if (line.length > 1)
				out.push(line);
		}
	});
	return (out.join('\n'));
}

// DNSSEC keys have timestamps -- for the comparison we'll strip them.
test('1024b pem private key to dnssec', function(t) {
	var k = sshpk.parsePrivateKey(PEM_RSA, 'pem');
	k = stripDNSSECTimestamp(k.toString('dnssec'));
	t.strictEqual(k, stripDNSSECTimestamp(DNSSEC_RSA));
	t.end();
});

test('1024b auto pem private key to dnssec', function(t) {
	var k = sshpk.parsePrivateKey(PEM_RSA, 'auto');
	k = stripDNSSECTimestamp(k.toString('dnssec'));
	t.strictEqual(k, stripDNSSECTimestamp(DNSSEC_RSA));
	t.end();
});

test('ecdsa pem private key to dnssec', function(t) {
	var k = sshpk.parsePrivateKey(PEM_RSA, 'pem');
	k = stripDNSSECTimestamp(k.toString('dnssec'));
	t.strictEqual(k, stripDNSSECTimestamp(DNSSEC_RSA));
	t.end();
});

test('ecdsa auto pem private key to dnssec', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_ECDSA, 'auto');
	k = stripDNSSECTimestamp(k.toString('dnssec'));
	t.strictEqual(k, stripDNSSECTimestamp(DNSSEC_ECDSA));
	t.end();
});
