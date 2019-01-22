// Copyright 2018 Joyent, Inc.  All rights reserved.

var test = require('tape').test;
var sshpk = require('../lib/index');
var path = require('path');
var fs = require('fs');
var temp = require('temp');

var testDir = path.join(__dirname, 'assets');

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

var ASN1PARSE_LINE =
    /^\s*([0-9]*):d=([0-9]+)\s+hl=([0-9]+)\s+l=\s*([0-9]+)\s*([a-z]+):\s*([^:\[]+)\s*(\[[^\]]+\])?\s*(:.+)?$/;
function asn1parse_line2obj(line) {
	var m = line.match(ASN1PARSE_LINE);
	if (!m)
		throw (new Error('Not a valid asn1parse output line'));
	var obj = {
	    offset: parseInt(m[1], 10),
	    depth: parseInt(m[2], 10),
	    headerLength: parseInt(m[3], 10),
	    length: parseInt(m[4], 10),
	    type: m[5],
	    tag: m[6].trim()
	};
	if (m[7])
		obj.valueType = m[7].slice(1, m[7].length - 1);
	if (m[8])
		obj.value = m[8].slice(1);
	return (obj);
}

temp.track();

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
			    ver[2] >= 1)))) {
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
	var tmp;

	test('make temp dir', function (t) {
		temp.mkdir('sshpk.test.openssl-cmd.' + algo,
		    function (err, tmpDir) {
			t.error(err);
			tmp = tmpDir;
			t.end();
		});
	});

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

	test('sign with sshpk, openssl dgst verify', function (t) {
		var pem = fs.readFileSync(path.join(testDir, 'id_' + algo));
		var key = sshpk.parsePrivateKey(pem, 'pkcs1');
		var pkcs8 = key.toPublic().toBuffer('pkcs8');

		var data = 'foobartest';
		var sig = key.createSign('sha256').update(data).sign().
		    toBuffer();

		fs.writeFileSync(path.join(tmp, 'signature'), sig);
		fs.writeFileSync(path.join(tmp, 'pubkey'), pkcs8);

		var kid = spawn('openssl', ['dgst',
		    '-binary', '-sha256',
		    '-verify', path.join(tmp, 'pubkey'),
		    '-signature', path.join(tmp, 'signature')]);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.stderr.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var output = Buffer.concat(bufs).toString('ascii');
			t.strictEqual(output, 'Verified OK\n');
			t.end();
		});
		kid.stdin.write(data);
		kid.stdin.end();
	});

	test('sign with openssl, verify with sshpk', function (t) {
		var pem = fs.readFileSync(path.join(testDir, 'id_' + algo));
		var key = sshpk.parsePrivateKey(pem, 'pkcs1');

		var data = 'foobartest';

		var kid = spawn('openssl', ['dgst',
		    '-binary', '-sha256',
		    '-sign', path.join(testDir, 'id_' + algo)]);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0, 'openssl exited 0');
			if (bufs.length === 0) {
				t.fail('"openssl dgst" wrote no output');
				t.end();
				return;
			}
			var output = Buffer.concat(bufs);
			var sig = sshpk.parseSignature(output, algo, 'asn1');
			t.ok(sig);
			t.ok(key.createVerify('sha256').update(data).
			    verify(sig));
			t.end();
		});
		kid.stdin.write(data);
		kid.stdin.end();
	});

	test('make a self-signed cert, parse with openssh', function (t) {
		var pem = fs.readFileSync(path.join(testDir, 'id_' + algo));
		var key = sshpk.parsePrivateKey(pem, 'pkcs1');

		var ids = [
			sshpk.identityFromDN('cn=' + algo + ', c=US'),
			sshpk.identityFromDN('cn=' + algo + '.test, c=AU')
		];
		var cert = sshpk.createSelfSignedCertificate(ids, key);
		var certPem = cert.toBuffer('pem');

		var kid = spawn('openssl', ['x509', '-text']);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var output = Buffer.concat(bufs).toString();

			var m = output.match(/Issuer: (.*)$/m);
			t.strictEqual(m[1].replace(/ = /g, '='),
			    'CN=' + algo + ', C=US');

			m = output.match(/Subject: (.*)$/m);
			t.strictEqual(m[1].replace(/ = /g, '='),
			    'CN=' + algo + ', C=US');

			var re = /DNS:([^, \n]+)([, ]+|$)/gm;
			m = re.exec(output);
			t.strictEqual(m[1], algo);

			m = re.exec(output);
			t.strictEqual(m[1], algo + '.test');
			t.end();
		});
		kid.stdin.write(certPem);
		kid.stdin.end();
	});

	test('make a self-signed cert, verify with openssh', function (t) {
		var pem = fs.readFileSync(path.join(testDir, 'id_' + algo));
		var key = sshpk.parsePrivateKey(pem, 'pkcs1');

		var id = sshpk.identityFromDN('cn=' + algo);
		var cert = sshpk.createSelfSignedCertificate(id, key,
		    { purposes: ['ca'] });
		var certPem = cert.toBuffer('pem');

		fs.writeFileSync(path.join(tmp, 'ca.pem'), certPem);

		var kid = spawn('openssl', ['verify',
		    '-CAfile', path.join(tmp, 'ca.pem')]);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var output = Buffer.concat(bufs).toString();
			t.strictEqual(output.trim(), 'stdin: OK');
			t.end();
		});
		kid.stdin.write(certPem);
		kid.stdin.end();
	});

	test('make a self-signed cert with utf8 chars', function (t) {
		var pem = fs.readFileSync(path.join(testDir, 'id_' + algo));
		var key = sshpk.parsePrivateKey(pem, 'pkcs1');

		var id = sshpk.identityFromDN('cn=おはよう');
		var cert = sshpk.createSelfSignedCertificate(id, key);
		var certPem = cert.toBuffer('pem');

		fs.writeFileSync(path.join(tmp, 'ca.pem'), certPem);

		var kid = spawn('openssl', ['verify',
		    '-CAfile', path.join(tmp, 'ca.pem')]);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var output = Buffer.concat(bufs).toString();
			t.strictEqual(output.trim(), 'stdin: OK');
			t.end();
		});
		kid.stdin.write(certPem);
		kid.stdin.end();
	});

	test('verify a self-signed cert with utf8 chars', function (t) {
		var pem = fs.readFileSync(path.join(testDir, 'id_' + algo));
		var key = sshpk.parsePrivateKey(pem, 'pkcs1');

		var id = sshpk.identityFromDN('cn=おはよう');
		var cert = sshpk.createSelfSignedCertificate(id, key);
		var certPem = cert.toBuffer('pem');

		var kid = spawn('openssl', ['asn1parse']);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var output = Buffer.concat(bufs).toString('utf8');
			var lines = output.split('\n');
			var foundString = false;
			for (var i = 0; i < lines.length; ++i) {
				if (!lines[i])
					continue;
				var line = asn1parse_line2obj(lines[i]);
				if (line.tag === 'OBJECT' &&
				    line.value === 'commonName') {
					var nline = asn1parse_line2obj(
					    lines[i + 1]);
					t.strictEqual(nline.value,
					    'おはよう', 'CN should be set');
					t.strictEqual(nline.tag, 'UTF8STRING',
					    'CN should be a utf8string');
					foundString = true;
				}
			}
			t.ok(foundString);
			t.end();
		});
		kid.stdin.write(certPem);
		kid.stdin.end();
	});

	test('make a self-signed cert with non-printable chars', function (t) {
		var pem = fs.readFileSync(path.join(testDir, 'id_' + algo));
		var key = sshpk.parsePrivateKey(pem, 'pkcs1');

		var id = sshpk.identityFromDN('cn=foo_bar@');
		var cert = sshpk.createSelfSignedCertificate(id, key);
		var certPem = cert.toBuffer('pem');

		var kid = spawn('openssl', ['asn1parse']);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var output = Buffer.concat(bufs).toString('utf8');
			var lines = output.split('\n');
			var foundString = false;
			for (var i = 0; i < lines.length; ++i) {
				if (!lines[i])
					continue;
				var line = asn1parse_line2obj(lines[i]);
				if (line.tag === 'OBJECT' &&
				    line.value === 'commonName') {
					var nline = asn1parse_line2obj(
					    lines[i + 1]);
					t.strictEqual(nline.value,
					    'foo_bar@', 'CN should be set');
					t.strictEqual(nline.tag, 'IA5STRING',
					    'CN should be a ia5string');
					foundString = true;
				}
			}
			t.ok(foundString);
			t.end();
		});
		kid.stdin.write(certPem);
		kid.stdin.end();
	});

	test('make a self-signed cert, openssl x509 -text parse', function (t) {
		var pem = fs.readFileSync(path.join(testDir, 'id_' + algo));
		var key = sshpk.parsePrivateKey(pem, 'pkcs1');

		var ids = [
			sshpk.identityFromDN('cn=' + algo + ', c=US'),
			sshpk.identityFromDN('cn=' + algo + '.test, c=AU')
		];
		var cert = sshpk.createSelfSignedCertificate(ids, key);
		var certPem = cert.toBuffer('pem');

		var kid = spawn('openssl', ['x509', '-text']);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var output = Buffer.concat(bufs).toString();

			var cert2 = sshpk.parseCertificate(output, 'pem');
			t.ok(cert2.fingerprint('sha512').matches(cert));
			t.end();
		});
		kid.stdin.write(certPem);
		kid.stdin.end();
	});

	test('make a self-signed cert with generated key', function (t) {
		if (algo !== 'ecdsa') {
			t.end();
			return;
		}

		var key = sshpk.generatePrivateKey(algo);

		var id = sshpk.identityFromDN('cn=' + algo);
		var cert = sshpk.createSelfSignedCertificate(id, key,
		    { purposes: ['ca'] });
		var certPem = cert.toBuffer('pem');

		fs.writeFileSync(path.join(tmp, 'ca.pem'), certPem);

		var kid = spawn('openssl', ['verify',
		    '-CAfile', path.join(tmp, 'ca.pem')]);
		var bufs = [];
		kid.stdout.on('data', bufs.push.bind(bufs));
		kid.on('close', function (rc) {
			t.equal(rc, 0);
			var output = Buffer.concat(bufs).toString();
			t.strictEqual(output.trim(), 'stdin: OK');
			t.end();
		});
		kid.stdin.write(certPem);
		kid.stdin.end();
	});
});

test('nulls in x509 rsa certs (#39)', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'id_rsa'));
	var key = sshpk.parsePrivateKey(pem, 'pkcs1');

	var id = sshpk.identityFromDN('cn=foobar');
	var cert = sshpk.createSelfSignedCertificate(id, key);
	var certPem = cert.toBuffer('pem');

	var kid = spawn('openssl', ['asn1parse']);
	var bufs = [];
	kid.stdout.on('data', bufs.push.bind(bufs));
	kid.on('close', function (rc) {
		t.equal(rc, 0, 'openssl command exit status 0');
		var output = Buffer.concat(bufs).toString('utf8');
		var lines = output.split('\n');
		var found = false;
		for (var i = 0; i < lines.length; ++i) {
			if (lines[i].length < 1)
				continue;
			var line = asn1parse_line2obj(lines[i]);
			if (line.type === 'prim' && line.tag === 'OBJECT' &&
			    line.value === 'sha256WithRSAEncryption') {
				var nline = asn1parse_line2obj(lines[i + 1]);
				t.strictEqual(nline.tag, 'NULL',
				    'null value must follow RSA OID');
				t.strictEqual(nline.type, 'prim',
				    'null should be primitive');
				t.strictEqual(nline.depth, line.depth,
				    'null should be at same depth as RSA OID');
				found = true;
			}
		}
		t.ok(found, 'should have an RSA OID');
		t.end();
	});
	kid.stdin.write(certPem);
	kid.stdin.end();
});

test('utf8string in issuer DN (#40)', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'id_rsa'));
	var ikey = sshpk.parsePrivateKey(pem, 'pkcs1');

	var certpem = fs.readFileSync(path.join(testDir, 'jim-x509-utf8.pem'));
	var issucert = sshpk.parseCertificate(certpem, 'pem');

	var issuid = issucert.subjects[0];
	var id = sshpk.identityFromDN('cn=foo_bar@');
	var key = sshpk.generatePrivateKey('ecdsa');

	var cert = sshpk.createCertificate(issuid, ikey, id, key);
	var certPem = cert.toBuffer('pem');

	var kid = spawn('openssl', ['asn1parse']);
	var bufs = [];
	kid.stdout.on('data', bufs.push.bind(bufs));
	kid.on('close', function (rc) {
		t.equal(rc, 0, 'openssl exited with 0 status');
		var output = Buffer.concat(bufs).toString('utf8');
		var lines = output.split('\n');
		var foundString = false;
		lines.forEach(function (line) {
			if (line.indexOf('foo_bar@') !== -1) {
				t.strictEqual(
				    line.indexOf('PRINTABLESTRING'),
				    -1, 'subject CN is printablestring');
				t.strictEqual(
				    line.indexOf('UTF8STRING'), -1,
				    'subject CN is not utf8string');
				t.notStrictEqual(
				    line.indexOf('IA5STRING'), -1,
				    'subject CN is not ia5string');
			}
			if (line.indexOf('a test string') !== -1) {
				t.notStrictEqual(
				    line.indexOf('UTF8STRING'),
				    -1, 'issuer CN is utf8string');
				t.strictEqual(
				    line.indexOf('PRINTABLESTRING'), -1,
				    'issuer CN is not printablestring');
				t.strictEqual(
				    line.indexOf('IA5STRING'), -1,
				    'issuer CN is not ia5string');
				foundString = true;
			}
		});
		t.ok(foundString, 'found the issuer CN');
		t.end();
	});
	kid.stdin.write(certPem);
	kid.stdin.end();
});

test('certs with <2050 dates should use UTCTime', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'id_rsa'));
	var key = sshpk.parsePrivateKey(pem, 'pkcs1');

	var id = sshpk.identityFromDN('cn=foobar');
	var opts = {};
	opts.validFrom = new Date('1990-01-02T03:04:05Z');
	opts.validUntil = new Date('2010-01-02T03:04:05Z');
	var cert = sshpk.createSelfSignedCertificate(id, key, opts);
	var certPem = cert.toBuffer('pem');

	var kid = spawn('openssl', ['asn1parse']);
	var bufs = [];
	kid.stdout.on('data', bufs.push.bind(bufs));
	kid.on('close', function (rc) {
		t.equal(rc, 0);
		var output = Buffer.concat(bufs).toString('utf8');
		var lines = output.split('\n');
		var found = 0;
		for (var i = 0; i < lines.length; ++i) {
			if (!lines[i])
				continue;
			var line = asn1parse_line2obj(lines[i]);
			if (line.tag === 'UTCTIME') {
				if (line.value === '900102030405Z' ||
				    line.value === '100102030405Z') {
					++found;
				} else {
					t.fail('unexpected utctime: ' +
					    line.value);
				}
			}
		}
		t.equal(found, 2);
		t.end();
	});
	kid.stdin.write(certPem);
	kid.stdin.end();
});

test('certs with >=2050 dates should use GeneralizedTime', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'id_rsa'));
	var key = sshpk.parsePrivateKey(pem, 'pkcs1');

	var id = sshpk.identityFromDN('cn=foobar');
	var opts = {};
	opts.validFrom = new Date('2050-01-02T03:04:05Z');
	opts.validUntil = new Date('2051-01-02T03:04:05Z');
	var cert = sshpk.createSelfSignedCertificate(id, key, opts);
	var certPem = cert.toBuffer('pem');

	var kid = spawn('openssl', ['asn1parse']);
	var bufs = [];
	kid.stdout.on('data', bufs.push.bind(bufs));
	kid.on('close', function (rc) {
		t.equal(rc, 0);
		var output = Buffer.concat(bufs).toString('utf8');
		var lines = output.split('\n');
		var found = 0;
		for (var i = 0; i < lines.length; ++i) {
			if (!lines[i])
				continue;
			var line = asn1parse_line2obj(lines[i]);
			if (line.tag === 'UTCTIME') {
				t.fail('unexpected utctime: ' + line.value);
			}
			if (line.tag === 'GENERALIZEDTIME') {
				if (line.value === '20500102030405Z') {
					++found;
				} else if (line.value === '20510102030405Z') {
					++found;
				} else {
					t.fail('bad gentime: ' + line.value);
				}
			}
		}
		t.equal(found, 2);
		t.end();
	});
	kid.stdin.write(certPem);
	kid.stdin.end();
});

test('certs with <1950 dates should use GeneralizedTime', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'id_rsa'));
	var key = sshpk.parsePrivateKey(pem, 'pkcs1');

	var id = sshpk.identityFromDN('cn=foobar');
	var opts = {};
	opts.validFrom = new Date('1949-01-02T03:04:05Z');
	opts.validUntil = new Date('1950-01-02T03:04:05Z');
	var cert = sshpk.createSelfSignedCertificate(id, key, opts);
	var certPem = cert.toBuffer('pem');

	var kid = spawn('openssl', ['asn1parse']);
	var bufs = [];
	kid.stdout.on('data', bufs.push.bind(bufs));
	kid.on('close', function (rc) {
		t.equal(rc, 0);
		var output = Buffer.concat(bufs).toString('utf8');
		var lines = output.split('\n');
		var found = 0;
		for (var i = 0; i < lines.length; ++i) {
			if (!lines[i])
				continue;
			var line = asn1parse_line2obj(lines[i]);
			if (line.tag === 'UTCTIME') {
				if (line.value === '500102030405Z') {
					++found;
				} else {
					t.fail('unexpected utctime: ' +
					    line.value);
				}
			}
			if (line.tag === 'GENERALIZEDTIME') {
				if (line.value === '19490102030405Z') {
					++found;
				} else {
					t.fail('unexpected gentime: ' +
					     line.value);
				}
			}
		}
		t.equal(found, 2);
		t.end();
	});
	kid.stdin.write(certPem);
	kid.stdin.end();
});

test('teardown', function (t) {
    temp.cleanup(function () {
        t.end();
    });
});
}

