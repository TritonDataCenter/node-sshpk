// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var asn1 = require('asn1');

function read(buf) {
	assert.buffer(buf, 'buf');

	buf = buf.toString();

	var lines = buf.split('\n');
	var m = lines[0].match(/BEGIN ([A-Z]+ )?PUBLIC KEY/);
	assert.ok(m);
	var m2 = lines[lines.length - 2].
	    match(/END ([A-Z]+ )?PUBLIC KEY/);
	assert.ok(m2);
	var type;
	if (m[1]) {
		assert.equal(m[1], m2[1]);
		type = m[1].trim();
	}

	lines = lines.slice(1, -2);
	buf = new Buffer(lines.join(''), 'base64');

	var der = new asn1.BerReader(buf);

	der.readSequence();

	if (type) {
		switch (type) {
		case 'RSA':
			return (readRSA(der));
		default:
			throw (new Error('Unknown key type ' + m[1]));
		}
	}

	der.readSequence();

	var oid = der.readOID();
	switch (oid) {
	case '1.2.840.113549.1.1.1':
		return (readPkcsRSA(der));
	case '1.2.840.10040.4.1':
		return (readPkcsDSA(der));
	default:
		throw (new Error('Unknown key type OID ' + oid));
	}
}

function readInt(der, nm) {
	assert.equal(der.peek(), asn1.Ber.Integer, nm + ' not an integer');
	der._offset = der.readLength(der.offset + 1);
	var data = der._buf.slice(der.offset, der.offset + der.length);
	der._offset += der.length;
	return (data);
}

function readRSA(der) {
	// modulus
	var n = readInt(der, 'modulus');
	var e = readInt(der, 'exponent');

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

function readPkcsRSA(der) {
	// Null -- XXX this probably isn't good practice
	der.readByte();
	der.readByte();

	// bit string sequence
	der.readSequence(0x03);
	der.readByte();
	der.readSequence();

	// modulus
	var n = readInt(der, 'modulus');
	var e = readInt(der, 'exponent');

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

function readPkcsDSA(der) {
	der.readSequence();

	var p = readInt(der, 'p');
	var q = readInt(der, 'q');
	var g = readInt(der, 'g');

	// bit string sequence
	der.readSequence(0x03);
	der.readByte();

	var y = readInt(der, 'y');

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

function write(key) {
	var Key = require('../key');
	assert.object(key);
	assert.ok(key instanceof Key);
}

module.exports = {
	read: read,
	write: write
};
