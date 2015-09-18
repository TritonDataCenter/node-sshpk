// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var asn1 = require('asn1');

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

function readPkcs8ECDSA(der) {
	der.readSequence();
	var wat = der.readString(asn1.Ber.Integer, true);

	der.readSequence();
	console.log(der._offset);
	var curveOid = der.readOID();
	console.log(curveOid);
	console.log(der._offset);

	var wat = der.readString(asn1.Ber.Integer, true);
	console.log(wat);

	der.readSequence();
	var wat = der.readString(asn1.Ber.OctetString, true);
	console.log(wat);
	var wat = der.readString(asn1.Ber.OctetString, true);
	console.log(wat);
	var wat = der.readString(asn1.Ber.BitString, true);
	console.log(wat);
	var wat = der.readString(asn1.Ber.OctetString, true);
	console.log(wat);
	var wat = der.readString(asn1.Ber.Integer, true);
	console.log(wat);
	var wat = der.readString(asn1.Ber.Integer, true);
	console.log(wat);

	/*der.readSequence();
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
		//throw (new Error('Unknown ECDSA curve oid: ' + curveOid));
	}*/

	console.log(der._offset);
	var Q = der.readString(asn1.Ber.BitString, true);
	if (Q[0] === 0x0)
		Q = Q.slice(1);
	console.log("q = ");
	console.log(Q);

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

/* For writing, we only support PKCS#8 */
function write(key) {
	var Key = require('../key');
	assert.object(key);
	assert.ok(key instanceof Key);


}

module.exports = {
	read: read,
	write: write
};
