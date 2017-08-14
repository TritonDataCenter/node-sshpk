// Copyright 2017 Joyent, Inc.	All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');

/*
 * Generated with:
 *     'dnssec-keygen -T KEY -a rsasha1 -b 1024 -n USER rsatest'
 *
 * which outputs two files named 'Krsatest.+005+57206.private' and
 * 'Krsatest.+005+57206.key'
 */
var DNSSEC_RSA =
    'Private-key-format: v1.3\n' +
    'Algorithm: 5 (RSASHA1)\n' +
    'Modulus: 1cNqdYrUKnXwdoUg7mgOCUYTvxv1n+tEy7JdsFiyrLcVqRxH4SyUeWKijcisNklDdl' +
    'ZDXkz3bn4jKfDHgKgsbPSYdn3sQbpjSzQVzzAJMv9Tgy9b801e1RAHJ1Bz4D0YaOi1dfxMLrJwY' +
    'jO490mw/6UMh9NmxLuWhUZdvib+Fz0=\n' +
    'PublicExponent: AQAB\n' +
    'PrivateExponent: YNB6vPW9leWInQU6nv99q/GTK/EL0/wIUoFcMWxasCLTqp3maDN6o2dq2/' +
    'BRHt0bstLq/CC7x81VO7+Te8+vHm3aHK8GQIuEExtJo/ydulUPFnMmmZa6kAFVrTvKs09+KAu93' +
    'K+bGch9zvPw51uKMiqAvOsYhvqHf/Pi2qxY5YE=\n' +
    'Prime1: 60nLFtb3pMo4xVJXCBTtkvB8JAiIyskccBvZfTR2urc8h1fciI3JjC8AfgMszPdHEGBR+jndXfbBLsQQl4hPkQ==\n' +
    'Prime2: 6JSPWFx7WdlSMT7PQ45NF7bHM6Vp8lfXQr1zLMpdXS1O3Oy3BbpqbmnjaToeNmcvRMPhtOeK9912nNiHxgqO7Q==\n' +
    'Exponent1: atUVxqgSx5seTdIGPGAsQwS4iS/q1JCePfUXOndg1YSvkhB9zO78LY+F3LGaXPKGLNRfRIuTjL+mlZJmqjc1UQ==\n' +
    'Exponent2: K4QQRfIXyjnVHQ2pbfRkDDnQj6M1bXht+DjGIe1DBroBdWh83f+BBmOdfwS2vmsT9wPHaTehUrsHBFWnIbC8CQ==\n' +
    'Coefficient: pMpjuudK7SoTi80t8JVr6x4kZdR73PVr9TVw60lZDCbsRjojEIpE08fuZ29/7aYCa5FHXF2xNEynjL5jepM6jA==\n' +
    'Created: 20170814221729\n' +
    'Publish: 20170814221729\n' +
    'Activate: 20170814221729\n';

var DNSSEC_RSA_PUB =
    'rsatest. IN KEY 0 3 5 AwEAAdXDanWK1Cp18HaFIO5oDglGE78b9Z/rRMuyXbBYsqy3FakcR+Es ' +
    'lHlioo3IrDZJQ3ZWQ15M925+Iynwx4CoLGz0mHZ97EG6Y0s0Fc8wCTL/ ' +
    'U4MvW/NNXtUQBydQc+A9GGjotXX8TC6ycGIzuPdJsP+lDIfTZsS7loVG Xb4m/hc9';

// same key as above, different format
var PEM_RSA =
    '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIICXAIBAAKBgQDVw2p1itQqdfB2hSDuaA4JRhO/G/Wf60TLsl2wWLKstxWpHEfh\n' +
    'LJR5YqKNyKw2SUN2VkNeTPdufiMp8MeAqCxs9Jh2fexBumNLNBXPMAky/1ODL1vz\n' +
    'TV7VEAcnUHPgPRho6LV1/EwusnBiM7j3SbD/pQyH02bEu5aFRl2+Jv4XPQIDAQAB\n' +
    'AoGAYNB6vPW9leWInQU6nv99q/GTK/EL0/wIUoFcMWxasCLTqp3maDN6o2dq2/BR\n' +
    'Ht0bstLq/CC7x81VO7+Te8+vHm3aHK8GQIuEExtJo/ydulUPFnMmmZa6kAFVrTvK\n' +
    's09+KAu93K+bGch9zvPw51uKMiqAvOsYhvqHf/Pi2qxY5YECQQDrScsW1vekyjjF\n' +
    'UlcIFO2S8HwkCIjKyRxwG9l9NHa6tzyHV9yIjcmMLwB+AyzM90cQYFH6Od1d9sEu\n' +
    'xBCXiE+RAkEA6JSPWFx7WdlSMT7PQ45NF7bHM6Vp8lfXQr1zLMpdXS1O3Oy3Bbpq\n' +
    'bmnjaToeNmcvRMPhtOeK9912nNiHxgqO7QJAatUVxqgSx5seTdIGPGAsQwS4iS/q\n' +
    '1JCePfUXOndg1YSvkhB9zO78LY+F3LGaXPKGLNRfRIuTjL+mlZJmqjc1UQJAK4QQ\n' +
    'RfIXyjnVHQ2pbfRkDDnQj6M1bXht+DjGIe1DBroBdWh83f+BBmOdfwS2vmsT9wPH\n' +
    'aTehUrsHBFWnIbC8CQJBAKTKY7rnSu0qE4vNLfCVa+seJGXUe9z1a/U1cOtJWQwm\n' +
    '7EY6IxCKRNPH7mdvf+2mAmuRR1xdsTRMp4y+Y3qTOow=\n' +
	'-----END RSA PRIVATE KEY-----\n';

var PEM_RSA_PUB =
    '-----BEGIN PUBLIC KEY-----\n' +
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVw2p1itQqdfB2hSDuaA4JRhO/\n' +
    'G/Wf60TLsl2wWLKstxWpHEfhLJR5YqKNyKw2SUN2VkNeTPdufiMp8MeAqCxs9Jh2\n' +
    'fexBumNLNBXPMAky/1ODL1vzTV7VEAcnUHPgPRho6LV1/EwusnBiM7j3SbD/pQyH\n' +
    '02bEu5aFRl2+Jv4XPQIDAQAB\n' +
    '-----END PUBLIC KEY-----\n';

/*
 * Generated with:
 *     'dnssec-keygen -T KEY -a ECDSAP256SHA256 -n USER ecdsatest'
 *
 * which outputs two files named 'Kecdsatest.+013+43896.private' and
 * 'Kecdsatest.+013+43896.key'
 */
var DNSSEC_ECDSA =
    'Private-key-format: v1.3\n' +
    'Algorithm: 13 (ECDSAP256SHA256)\n' +
    'PrivateKey: uLpudyhy2gElB3DeMkqX5xjfSV8AwYOO4uUj9hHuCt8=\n' +
    'Created: 20170814234326\n' +
    'Publish: 20170814234326\n' +
    'Activate: 20170814234326';
var DNSSEC_ECDSA_PUB =
    'ecdsatest. IN KEY 0 3 13 es1l0ZlSrePQHoKVPXcefo6ExgKfO+KkoT57saLvugu1GrnwHRpNmvk6 yOjQeu865o5vI+wtar62A5mgSf/fvQ==';
// Same key as above, as PEM
var PEM_ECDSA =
    '-----BEGIN EC PRIVATE KEY-----\n' +
    'MHcCAQEEILi6bncoctoBJQdw3jJKl+cY30lfAMGDjuLlI/YR7grfoAoGCCqGSM49\n' +
    'AwEHoUQDQgAEes1l0ZlSrePQHoKVPXcefo6ExgKfO+KkoT57saLvugu1GrnwHRpN\n' +
    'mvk6yOjQeu865o5vI+wtar62A5mgSf/fvQ==\n' +
    '-----END EC PRIVATE KEY-----\n'

var PEM_ECDSA_PUB =
    '-----BEGIN PUBLIC KEY-----\n' +
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEes1l0ZlSrePQHoKVPXcefo6ExgKf\n' +
    'O+KkoT57saLvugu1GrnwHRpNmvk6yOjQeu865o5vI+wtar62A5mgSf/fvQ==\n' +
    '-----END PUBLIC KEY-----\n'

///--- Tests
/// read tests
test('1024b dnssec to pem private key', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_RSA, 'dnssec');
	t.equal(k.toString('pem'), PEM_RSA);
	t.end();
});

test('1024b dnssec to pem public key', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_RSA, 'dnssec');
	t.equal(k.toPublic().toString('pem'), PEM_RSA_PUB);
	t.end();
});

test('1024b dnssec public key to pem', function(t) {
	var k = sshpk.parseKey(DNSSEC_RSA_PUB, 'dnssec');
	t.equal(k.toString('pem'), PEM_RSA_PUB);
	t.end();
});

test('1024b auto dnssec to pem private key', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_RSA, 'auto');
	t.equal(k.toString('pem'), PEM_RSA);
	t.end();
});

test('1024b auto dnssec public key to pem', function(t) {
	var k = sshpk.parseKey(DNSSEC_RSA_PUB, 'auto');
	t.equal(k.toString('pem'), PEM_RSA_PUB);
	t.end();
});

test('ecdsa dnssec to pem private key', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_ECDSA, 'dnssec');
	t.equal(k.toString('pem'), PEM_ECDSA);
	t.end();
});

test('ecdsa dnssec to pem public key', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_ECDSA, 'dnssec');
	t.equal(k.toPublic().toString('pem'), PEM_ECDSA_PUB);
	t.end();
});

// write tests
///--- Tests

function stripDNSSECTimestamp(m) {
	var out = []
	var lines = m.split('\n');
	lines.forEach(function(line) {
		if (line.match(/^Created.*/) || line.match(/^Publish.*/) ||
		    line.match(/^Activate.*/)) {
			// continue
		} else {
			if (line.length > 1)
				out.push(line);
		}
	});
	return (out.join('\n'));
}

/// DNSSEC keys have timestamps -- for the comparison we'll strip them.
test('1024b pem private key to dnssec', function(t) {
	var k = sshpk.parsePrivateKey(PEM_RSA, 'pem');
	k = stripDNSSECTimestamp(k.toString('dnssec'));
	console.log(k);
	t.equal(k, stripDNSSECTimestamp(DNSSEC_RSA));
	t.end();
});

test('1024b auto pem private key to dnssec', function(t) {
	var k = sshpk.parsePrivateKey(PEM_RSA, 'auto');
	k = stripDNSSECTimestamp(k.toString('dnssec'));
	t.equal(k, stripDNSSECTimestamp(DNSSEC_RSA));
	t.end();
});

test('ecdsa pem private key to dnssec', function(t) {
	var k = sshpk.parsePrivateKey(PEM_RSA, 'pem');
	k = stripDNSSECTimestamp(k.toString('dnssec'));
	t.equal(k, stripDNSSECTimestamp(DNSSEC_RSA));
	t.end();
});

test('ecdsa auto pem private key to dnssec', function(t) {
	var k = sshpk.parsePrivateKey(DNSSEC_ECDSA, 'auto');
	k = stripDNSSECTimestamp(k.toString('dnssec'));
	t.equal(k, stripDNSSECTimestamp(DNSSEC_ECDSA));
	t.end();
});
