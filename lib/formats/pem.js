// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var asn1 = require('asn1');
var Key = require('../key');

function read(buf) {
	assert.buffer(buf, 'buf');

	var endOfLine = buf.indexOf('\n');
	assert.ok(endOfLine !== -1);
	var firstLine = buf.slice(0, endOfLine).toString();
	assert.ok(firstLine.indexOf('BEGIN PUBLIC KEY') !== -1);

	buf = buf.slice(endOfLine + 1);
	var endTextStart = buf.indexOf('END PUBLIC KEY');
	assert.ok(endTextStart !== -1);
	while (buf[endTextStart] !== 10)
		endTextStart--;

	buf = buf.slice(0, endTextStart);
	buf = new Buffer(buf.toString(), 'base64');

	var der = new asn1.BerReader(buf);

	der.readSequence();
	der.readSequence();

	var oid = der.readOID();
	switch (oid) {
	case '1.2.840.113549.1.1.1':
		return (readRSA(der));
	case '1.2.840.10040.4.1':
		return (readDSA(der));
	default:
		throw (new Error('Unknown key type OID ' + oid));
	}
}

function readRSA(der) {
	// Null -- XXX this probably isn't good practice
	der.readByte();
	der.readByte();

	// bit string sequence
	der.readSequence(0x03);
	der.readByte();
	der.readSequence();

	// modulus
	assert.equal(der.peek(), asn1.Ber.Integer, 'modulus not an integer');
	der._offset = der.readLength(der.offset + 1);
	var modulus = der._buf.slice(der.offset, der.offset + der.length);
	der._offset += der.length;

	// exponent
	assert.equal(der.peek(), asn1.Ber.Integer, 'exponent not an integer');
	der._offset = der.readLength(der.offset + 1);
	var exponent = der._buf.slice(der.offset, der.offset + der.length);
	der._offset += der.length;

	// now, make the key
	var key = {
		type: 'rsa',
		parts: [
			{ name: 'e', data: exponent },
			{ name: 'n', data: modulus }
		]
	};

	return (new Key(key));
}

function readDSA(der) {
	der.readSequence();

	// p
	assert.equal(der.peek(), asn1.Ber.Integer, 'p not an integer');
	der._offset = der.readLength(der.offset + 1);
	var p = der._buf.slice(der.offset, der.offset + der.length);
	der._offset += der.length;

	// q
	assert.equal(der.peek(), asn1.Ber.Integer, 'q not an integer');
	der._offset = der.readLength(der.offset + 1);
	var q = der._buf.slice(der.offset, der.offset + der.length);
	der._offset += der.length;

	// g
	assert.equal(der.peek(), asn1.Ber.Integer, 'g not an integer');
	der._offset = der.readLength(der.offset + 1);
	var g = der._buf.slice(der.offset, der.offset + der.length);
	der._offset += der.length;

	// bit string sequence
	der.readSequence(0x03);
	der.readByte();
	der.readSequence();

	// y
	assert.equal(der.peek(), asn1.Ber.Integer, 'y not an integer');
	der._offset = der.readLength(der.offset + 1);
	var y = der._buf.slice(der.offset, der.offset + der.length);
	der._offset += der.length;

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

	return (new Key(key));
}

function write(key) {
	assert.object(key);
	assert.ok(key instanceof Key);
}

module.exports = {
	read: read,
	write: write
};
