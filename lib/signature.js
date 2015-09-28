// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var algs = require('./algs');
var crypto = require('crypto');
var errs = require('./errors');
var asn1 = require('asn1');

var InvalidAlgorithmError = errs.InvalidAlgorithmError;
var SignatureParseError = errs.SignatureParseError;

function Signature(opts) {
	assert.object(opts, 'options');
	assert.arrayOfObject(opts.parts, 'options.parts');
	assert.string(opts.type, 'options.type');

	var partLookup = {};
	for (var i = 0; i < opts.parts.length; ++i) {
		var part = opts.parts[i];
		partLookup[part.name] = part;
	}

	Object.defineProperties(this, {
		type: { value: opts.type },
		parts: { value: opts.parts },
		part: { value: partLookup }
	});
}

Signature.prototype.toBuffer = function (format) {
	if (format === undefined)
		format = 'asn1';
	assert.string(format, 'format');

	switch (this.type) {
	case 'rsa':
		return (this.part.sig.data);

	case 'dsa':
	case 'ecdsa':
		if (format === 'asn1') {
			var der = new asn1.BerWriter();
			der.startSequence();
			var zero = new Buffer(1);
			zero[0] = 0x0;
			var r = this.part.r.data;
			if ((r[0] & 0x80) === 0x80)
				r = Buffer.concat([zero, r]);
			var s = this.part.s.data;
			if ((s[0] & 0x80) === 0x80)
				s = Buffer.concat([zero, s]);
			der.writeBuffer(r, asn1.Ber.Integer);
			der.writeBuffer(s, asn1.Ber.Integer);
			der.endSequence();
			return (der.buffer);
		} else if (format === 'ssh' && this.type === 'dsa') {
			return (Buffer.concat([
			    this.part.r.data,
			    this.part.s.data]));
		} else if (format === 'ssh' && this.type === 'ecdsa') {
			var parts = [];
			parts.push(this.part.r.data);
			parts.push(this.part.s.data);

			var len = 0;
			for (var i = 0; i < parts.length; ++i)
				len += 4 + parts[i].length;

			var buf = new Buffer(len);
			var offset = 0;
			for (i = 0; i < parts.length; ++i) {
				buf.writeUInt32BE(parts[i].length, offset);
				offset += 4;
				offset += parts[i].copy(buf, offset);
			}
			assert.ok(offset === buf.length);

			return (buf);
		}
		throw (new Error('Invalid signature format'));
	default:
		throw (new Error('Invalid signature data'));
	}
};

Signature.prototype.toString = function (format) {
	assert.optionalString(format, 'format');
	return (this.toBuffer(format).toString('base64'));
};

Signature.parse = function (data, type, format) {
	if (typeof (data) === 'string')
		data = new Buffer(data, 'base64');
	assert.buffer(data, 'data');
	assert.string(format, 'format');
	assert.string(type, 'type');

	var opts = {};
	opts.type = type.toLowerCase();
	opts.parts = [];

	switch (opts.type) {
	case 'rsa':
		/* RSA in both formats is the same, just a blob */
		opts.parts.push({name: 'sig', data: data});
		return (new Signature(opts));

	case 'dsa':
	case 'ecdsa':
		if (format === 'asn1') {
			try {
				var der = new asn1.BerReader(data);
				der.readSequence();
				var r = der.readString(asn1.Ber.Integer, true);
				var s = der.readString(asn1.Ber.Integer, true);
			} catch (e) {
				throw (new SignatureParseError(type, format));
			}
			if (r[0] === 0x0)
				r = r.slice(1);
			if (s[0] === 0x0)
				s = s.slice(1);
			opts.parts.push({name: 'r', data: r});
			opts.parts.push({name: 's', data: s});

		} else if (format === 'ssh' && opts.type === 'dsa') {
			if (data.length != 40)
				throw (new SignatureParseError(type, format));
			opts.parts.push({name: 'r', data: data.slice(0, 20)});
			opts.parts.push({name: 's', data: data.slice(20, 40)});

		} else if (format === 'ssh' && opts.type === 'ecdsa') {
			var parts = opts.parts;
			var offset = 0;
			while (offset < data.length) {
				var len = data.readUInt32BE(offset);
				offset += 4;
				parts.push({
					data: data.slice(offset, offset + len)
				});
				offset += len;
			}
			if (parts.length !== 2)
				throw (new SignatureParseError(type, format));
			parts[0].name = 'r';
			parts[1].name = 's';

		} else {
			throw (new SignatureParseError(type, format));
		}
		return (new Signature(opts));

	default:
		throw (new InvalidAlgorithmError(type));
	}
};

module.exports = Signature;
