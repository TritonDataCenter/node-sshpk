// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;
var sshpk = require('../lib/index');
var path = require('path');
var fs = require('fs');

var testDir = __dirname;

var spawn = require('child_process').spawn;

var FPS = {};
FPS.rsa = sshpk.parseFingerprint(
    'SHA256:tT5wcGMJkBzNu+OoJYEgDCwIcDAIFCUahAmuTT4qC3s');
FPS.dsa = sshpk.parseFingerprint(
    'SHA256:PCfwpK62grBWrAJceLetSNv9CTrX8yoD0miKf11DBG8');
FPS.ecdsa = sshpk.parseFingerprint(
    'SHA256:e34c67Npv31uMtfVUEBJln5aOcJugzDaYGsj1Uph5DE');
FPS.ecdsa2 = sshpk.parseFingerprint(
    'SHA256:Kyu0EMqH8fzfp9RXKJ6kmsk9qKGBqVRtlOuk6bXfCEU');

test('openssl version', function (t) {
	var kid = spawn('openssl', ['version']);
	var buf = '';
	var verLine;
	kid.stdout.on('data', function (data) {
		buf += data.toString();
		var parts = buf.split('\n');
		if (parts.length > 1) {
			verLine = parts[0];
			buf = parts[1];
		}
	});
	kid.on('close', function (rc) {
		if (rc !== 0 || verLine === undefined) {
			console.log('warning: failed to find openssl command');
			t.end();
			return;
		}

		var parts = verLine.split(' ');
		if (parts[0] === 'OpenSSL') {
			var ver = parts[1].split('.').map(function (p) {
				return (parseInt(p));
			});
			if (ver[0] > 1 || (ver[0] == 1 &&
			    (ver[1] > 0 || (ver[1] == 0 &&
			    ver[2] >= 2)))) {
				/* we're ok */
				genTests();
			}
		} else {
			genTests();
		}
		t.end();
	});
});

function genTests() {
['rsa', 'dsa', 'ecdsa'].forEach(function (algo) {
	test('pkcs8 '+algo+' public key parses', function (t) {
		var kid = spawn('openssl', [
			'pkey', '-in', path.join(testDir, 'id_' +algo),
			'-pubout']);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var pem = Buffer.concat(bufs);
			var key = sshpk.parseKey(pem, 'pkcs8');
			t.strictEqual(key.type, algo);
			if (algo === 'ecdsa')
				t.strictEqual(key.size, 384);
			else
				t.strictEqual(key.size, 1024);
			t.ok(FPS[algo].matches(key));
			t.end();
		});
	});

	test('pkcs8 '+algo+' private key parses', function (t) {
		var kid = spawn('openssl', [
			'pkey', '-in', path.join(testDir, 'id_' +algo)]);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var pem = Buffer.concat(bufs);
			var key = sshpk.parsePrivateKey(pem, 'pkcs8');
			t.strictEqual(key.type, algo);
			if (algo === 'ecdsa')
				t.strictEqual(key.size, 384);
			else
				t.strictEqual(key.size, 1024);
			t.ok(FPS[algo].matches(key));
			t.end();
		});
	});

	test('pkcs8 '+algo+' public key output', function (t) {
		var pem = fs.readFileSync(path.join(testDir, 'id_' + algo));
		var key = sshpk.parsePrivateKey(pem, 'pkcs1');
		var pkcs8 = key.toPublic().toBuffer('pkcs8');
		t.ok(pkcs8, 'output produced');

		var kid = spawn('openssl', ['pkey',
		    '-in', path.join(testDir, 'id_' + algo),
		    '-pubout']);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var output = Buffer.concat(bufs);
			t.strictEqual(pkcs8.toString('base64'),
			    output.toString('base64'));
			t.end();
		});
	});

	test('pkcs8 '+algo+' private key output', function (t) {
		var pem = fs.readFileSync(path.join(testDir, 'id_' + algo));
		var key = sshpk.parsePrivateKey(pem, 'pkcs1');
		var pkcs8 = key.toBuffer('pkcs8');
		t.ok(pkcs8, 'output produced');

		var kid = spawn('openssl', ['pkey',
		    '-in', path.join(testDir, 'id_' + algo)]);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var output = Buffer.concat(bufs);
			t.strictEqual(pkcs8.toString('base64'),
			    output.toString('base64'));
			t.end();
		});
	});
});
}

