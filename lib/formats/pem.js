// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var asn1 = require('asn1');
var algs = require('../algs');

/*
 * For reading we support both PKCS#1 and PKCS#8. If we find a private key,
 * we just take the public component of it and use that.
 */
function read(buf) {
	assert.buffer(buf, 'buf');
	buf = buf.toString();
	var lines = buf.split('\n');

	var m = lines[0].match(
	    /BEGIN ([A-Z]+ )?(PUBLIC|PRIVATE) KEY/);
	assert.ok(m);

	var m2 = lines[lines.length - 2].match(
	    /END ([A-Z]+ )?(PUBLIC|PRIVATE) KEY/);
	assert.ok(m2);

	/* Begin and end banners must match key type */
	assert.equal(m[2], m2[2]);
	var type = m[2].toLowerCase();

	var alg;
	if (m[1]) {
		/* They also must match algorithms, if given */
		assert.equal(m[1], m2[1]);
		alg = m[1].trim();
	}

	/* Chop off the first and last lines */
	lines = lines.slice(1, -2);
	buf = new Buffer(lines.join(''), 'base64');

	var der = new asn1.BerReader(buf);

	/*
	 * All of the PEM file types start with a sequence tag, so chop it
	 * off here
	 */
	der.readSequence();

	/* PKCS#1 type keys name an algorithm in the banner explicitly */
	if (alg)
		return (readPkcs1(alg, type, der));
	else
		return (readPkcs8(alg, type, der));
}

/* Helper to read in a single mpint */
function readMPInt(der, nm) {
	assert.strictEqual(der.peek(), asn1.Ber.Integer,
	    nm + ' is not an Integer');
	return (der.readString(asn1.Ber.Integer, true));
}

function readPkcs1(alg, type, der) {
	switch (alg) {
	case 'RSA':
		if (type === 'public')
			return (readPkcs1RSAPublic(der));
		else if (type === 'private')
			return (readPkcs1RSAPrivate(der));
		throw (new Error('Unknown key type: ' + type));
	case 'DSA':
		if (type === 'private')
			return (readPkcs1DSAPrivate(der));
		throw (new Error('DSA public keys cannot be PKCS#1'));
	case 'EC':
		if (type === 'private')
			return (readPkcs1ECDSAPrivate(der));
		throw (new Error('ECDSA public keys cannot be PKCS#1'));
	default:
		throw (new Error('Unknown key algo: ' + alg));
	}
}

function readPkcs1RSAPublic(der) {
	// modulus and exponent
	var n = readMPInt(der, 'modulus');
	var e = readMPInt(der, 'exponent');

	// now, make the key
	var key = {
		type: 'rsa',
		parts: [
			{ name: 'e', data: e },
			{ name: 'n', data: n }
		]
	};

	var Key = require('../key');
	return (new Key(key));
}

function readPkcs1RSAPrivate(der) {
	var version = readMPInt(der, 'version');
	assert.strictEqual(version.readUInt8(0), 0);

	// modulus then public exponent
	var n = readMPInt(der, 'modulus');
	var e = readMPInt(der, 'public exponent');

	// now, make the key
	var key = {
		type: 'rsa',
		parts: [
			{ name: 'e', data: e },
			{ name: 'n', data: n }
		]
	};

	var Key = require('../key');
	return (new Key(key));
}

function readPkcs1DSAPrivate(der) {
	var version = readMPInt(der, 'version');
	assert.strictEqual(version.readUInt8(0), 0);

	var p = readMPInt(der, 'p');
	var q = readMPInt(der, 'q');
	var g = readMPInt(der, 'g');
	var y = readMPInt(der, 'y');

	// now, make the key
	var key = {
		type: 'dsa',
		parts: [
			{ name: 'p', data: p },
			{ name: 'q', data: q },
			{ name: 'g', data: g },
			{ name: 'y', data: y }
		]
	};

	var Key = require('../key');
	return (new Key(key));
}

function readPkcs1ECDSAPrivate(der) {
	var version = readMPInt(der, 'version');
	assert.strictEqual(version.readUInt8(0), 1);

	// private key
	der.readString(asn1.Ber.OctetString, true);

	der.readSequence(0xa0);
	var curveOid = der.readOID();
	var curve;
	switch (curveOid) {
	case '1.2.840.10045.3.1.7':
		curve = 'nistp256';
		break;
	case '1.3.132.0.34':
		curve = 'nistp384';
		break;
	case '1.3.132.0.35':
		curve = 'nistp521';
		break;
	default:
		throw (new Error('Unknown ECDSA curve oid: ' + curveOid));
	}

	der.readSequence(0xa1);
	var Q = der.readString(asn1.Ber.BitString, true);
	if (Q[0] === 0x0)
		Q = Q.slice(1);

	var key = {
		type: 'ecdsa',
		parts: [
			{ name: 'curve', data: new Buffer(curve) },
			{ name: 'Q', data: Q }
		]
	};

	var Key = require('../key');
	return (new Key(key));
}

function readPkcs8(alg, type, der) {
	if (type !== 'public')
		throw (new Error('PKCS#8 only supports public keys'));
	der.readSequence();

	var oid = der.readOID();
	switch (oid) {
	case '1.2.840.113549.1.1.1':
		return (readPkcs8RSA(der));
	case '1.2.840.10040.4.1':
		return (readPkcs8DSA(der));
	case '1.2.840.10045.2.1':
		return (readPkcs8ECDSA(der));
	default:
		throw (new Error('Unknown key type OID ' + oid));
	}
}

function readPkcs8RSA(der) {
	// Null -- XXX this probably isn't good practice
	der.readByte();
	der.readByte();

	// bit string sequence
	der.readSequence(0x03);
	der.readByte();
	der.readSequence();

	// modulus
	var n = readMPInt(der, 'modulus');
	var e = readMPInt(der, 'exponent');

	// now, make the key
	var key = {
		type: 'rsa',
		parts: [
			{ name: 'e', data: e },
			{ name: 'n', data: n }
		]
	};

	var Key = require('../key');
	return (new Key(key));
}

function readPkcs8DSA(der) {
	der.readSequence();

	var p = readMPInt(der, 'p');
	var q = readMPInt(der, 'q');
	var g = readMPInt(der, 'g');

	// bit string sequence
	der.readSequence(0x03);
	der.readByte();

	var y = readMPInt(der, 'y');

	// now, make the key
	var key = {
		type: 'dsa',
		parts: [
			{ name: 'p', data: p },
			{ name: 'q', data: q },
			{ name: 'g', data: g },
			{ name: 'y', data: y }
		]
	};

	var Key = require('../key');
	return (new Key(key));
}

/* Count leading zero bits on a buffer */
function countZeros(buf) {
	var o = 0, obit = 8;
	while (o < buf.length) {
		var mask = (1 << obit);
		if ((buf[o] & mask) === mask)
			break;
		obit--;
		if (obit < 0) {
			o++;
			obit = 8;
		}
	}
	return (o*8 + (8 - obit) - 1);
}

function readPkcs8ECDSA(der) {
	// ECParameters sequence
	der.readSequence();
	var version = der.readString(asn1.Ber.Integer, true);
	assert.strictEqual(version.readUInt8(0), 1, 'version 1');

	var curve = {};
	// FieldID sequence
	der.readSequence();
	var fieldTypeOid = der.readOID();
	assert.strictEqual(fieldTypeOid, '1.2.840.10045.1.1', 'prime-field');
	var p = curve.p = der.readString(asn1.Ber.Integer, true);
	/*
	 * p always starts with a 1 bit, so count the zeros to get its
	 * real size.
	 */
	curve.size = p.length * 8 - countZeros(p);

	// Curve sequence
	der.readSequence();
	curve.a = der.readString(asn1.Ber.OctetString, true);
	curve.b = der.readString(asn1.Ber.OctetString, true);
	if (der.peek() === asn1.Ber.BitString)
		curve.s = der.readString(asn1.Ber.BitString, true);

	// Combined Gx and Gy
	curve.G = der.readString(asn1.Ber.OctetString, true);
	assert.strictEqual(curve.G[0], 0x4, 'uncompressed G is required');

	curve.n = der.readString(asn1.Ber.Integer, true);
	curve.h = der.readString(asn1.Ber.Integer, true);
	assert.strictEqual(curve.h[0], 0x1, 'a cofactor=1 curve is required');

	var curveName;
	var curveNames = Object.keys(algs.curves);
	for (var j = 0; j < curveNames.length; ++j) {
		var c = curveNames[j];
		var cd = algs.curves[c];
		var ks = Object.keys(cd);
		var equal = true;
		for (var i = 0; i < ks.length; ++i) {
			var k = ks[i];
			if (typeof (cd[k]) === 'object') {
				if (!cd[k].equals(curve[k])) {
					equal = false;
					break;
				}
			} else {
				if (cd[k] !== curve[k]) {
					equal = false;
					break;
				}
			}
		}
		if (equal) {
			curveName = c;
			break;
		}
	}
	assert.string(curveName, 'a known elliptic curve');

	var Q = der.readString(asn1.Ber.BitString, true);
	if (Q[0] === 0x0)
		Q = Q.slice(1);

	var key = {
		type: 'ecdsa',
		parts: [
			{ name: 'curve', data: new Buffer(curveName) },
			{ name: 'Q', data: Q }
		]
	};

	var Key = require('../key');
	return (new Key(key));
}

/* For writing, we only support PKCS#8 */
function write(key) {
	var Key = require('../key');
	assert.object(key);
	assert.ok(key instanceof Key);

	var der = new asn1.BerWriter();

	der.startSequence();

	der.startSequence();
	switch (key.type) {
	case 'rsa':
		der.writeOID('1.2.840.113549.1.1.1');
		der.writeNull();
		der.endSequence();
		writePkcs8RSA(key, der);
		break;
	case 'dsa':
		der.writeOID('1.2.840.10040.4.1');
		writePkcs8DSA(key, der);
		break;
	case 'ecdsa':
		der.writeOID('1.2.840.10045.2.1');
		writePkcs8ECDSA(key, der);
		break;
	default:
		throw (new Error('Unsupported key type: ' + key.type));
	}

	der.endSequence();

	var tmp = der.buffer.toString('base64');
	var body = '';
	for (var i = 0; i < tmp.length;) {
		var limit = i + 64;
		if (limit > tmp.length)
			limit = tmp.length;
		body += tmp.slice(i, limit);
		body += '\n';
		i = limit;
	}

	body = '-----BEGIN PUBLIC KEY-----\n' + body;
	body = body + '-----END PUBLIC KEY-----\n';

	return (new Buffer(body));
}

function writePkcs8RSA(key, der) {
	der.startSequence(asn1.Ber.BitString);
	der.writeByte(0x00);

	der.startSequence();
	der.writeBuffer(key.part.n.data, asn1.Ber.Integer);
	der.writeBuffer(key.part.e.data, asn1.Ber.Integer);
	der.endSequence();

	der.endSequence();
}

function writePkcs8DSA(key, der) {
	der.startSequence();
	der.writeBuffer(key.part.p.data, asn1.Ber.Integer);
	der.writeBuffer(key.part.q.data, asn1.Ber.Integer);
	der.writeBuffer(key.part.g.data, asn1.Ber.Integer);
	der.endSequence();
	der.endSequence();

	der.startSequence(asn1.Ber.BitString);
	der.writeByte(0x00);
	der.writeBuffer(key.part.y.data, asn1.Ber.Integer);
	der.endSequence();
}

function writePkcs8ECDSA(key, der) {
	// ECParameters sequence
	der.startSequence();

	var version = new Buffer(1);
	version.writeUInt8(1, 0);
	der.writeBuffer(version, asn1.Ber.Integer);

	var curve = algs.curves[key.curve];

	// FieldID sequence
	der.startSequence();
	der.writeOID('1.2.840.10045.1.1'); // prime-field
	der.writeBuffer(curve.p, asn1.Ber.Integer);
	der.endSequence();

	// Curve sequence
	der.startSequence();
	var a = curve.p;
	if (a[0] === 0x0)
		a = a.slice(1);
	der.writeBuffer(a, asn1.Ber.OctetString);
	der.writeBuffer(curve.b, asn1.Ber.OctetString);
	der.writeBuffer(curve.s, asn1.Ber.BitString);
	der.endSequence();

	der.writeBuffer(curve.G, asn1.Ber.OctetString);
	der.writeBuffer(curve.n, asn1.Ber.Integer);
	var h = curve.h;
	if (!h) {
		h = new Buffer(1);
		h.writeUInt8(1, 0);
	}
	der.writeBuffer(h, asn1.Ber.Integer);

	// ECParameters
	der.endSequence();
	der.endSequence();

	var Q = key.part.Q.data;
	if (Q[0] === 0x04)
		Q = Buffer.concat([new Buffer(1), Q]);
	der.writeBuffer(Q, asn1.Ber.BitString);
}

module.exports = {
	read: read,
	write: write
};
