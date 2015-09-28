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
		type: { enumerable: true, value: opts.type },
		hashAlgorithm: { enumerable: true, writable: true,
		    value: opts.hashAlgo },
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
		if (this.type === 'ssh') {
			var parts = [];
			parts.push(new Buffer('ssh-rsa'));
			parts.push(this.part.sig.data);
			return (lengthPrefixJoin(parts));
		} else {
			return (this.part.sig.data);
		}

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
			var parts = [];
			parts.push(new Buffer('ssh-dss'));
			parts.push(Buffer.concat([
			    this.part.r.data,
			    this.part.s.data]));
			return (lengthPrefixJoin(parts));
		} else if (format === 'ssh' && this.type === 'ecdsa') {
			var parts = [];
			/* XXX: find a more proper way to do this? */
			var curve;
			var sz = this.part.r.data.length * 8;
			if (sz === 256)
				curve = 'nistp256';
			else if (sz === 384)
				curve = 'nistp384';
			else if (sz === 528)
				curve = 'nistp521';
			parts.push(new Buffer('ecdsa-sha2-' + curve))
			parts.push(this.part.r.data);
			parts.push(this.part.s.data);
			return (lengthPrefixJoin(parts));
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
		if (format === 'ssh') {
			try {
				var parts = lengthPrefixSplit(data);
				if (parts.length === 2 &&
				    parts[0].data.toString() === 'ssh-rsa') {
					parts[1].name = 'sig';
					opts.parts.push(parts[1]);
					return (new Signature(opts));
				}
			} catch (e) {
				/* fall through */
			}
		}
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
			if (data.length != 40) {
				var parts = lengthPrefixSplit(data);
				if (parts.length !== 2 ||
				    parts[1].data.length !== 40) {
					throw (new SignatureParseError(type,
					     format));
				}
				if (parts[0].data.toString() !== 'ssh-dss') {
					throw (new SignatureParseError(type,
					     format));
				}
				data = parts[1].data;
			}
			opts.parts.push({name: 'r', data: data.slice(0, 20)});
			opts.parts.push({name: 's', data: data.slice(20, 40)});

		} else if (format === 'ssh' && opts.type === 'ecdsa') {
			var parts = opts.parts = lengthPrefixSplit(data);
			if (parts.length === 3) {
				var part = parts.shift();
				var type = part.data.toString();
				console.log(type);
				if (!type.match(/^ecdsa-sha2-/)) {
					throw (new SignatureParseError(type,
					     format));
				}
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

function lengthPrefixSplit(data, offset) {
	var parts = [];
	if (offset === undefined)
		offset = 0;
	while (offset < data.length) {
		var len = data.readUInt32BE(offset);
		offset += 4;
		parts.push({
			data: data.slice(offset, offset + len)
		});
		offset += len;
	}
	return (parts);
}

function lengthPrefixJoin(buffers) {
	var size = 0;
	var i;
	for (i = 0; i < buffers.length; ++i)
		size += 4 + buffers[i].length;
	var buf = new Buffer(size);
	var offset = 0;
	for (i = 0; i < buffers.length; ++i) {
		buf.writeUInt32BE(buffers[i].length, offset);
		offset += 4;
		buffers[i].copy(buf, offset);
		offset += buffers[i].length;
	}
	assert.equal(offset, buf.length);
	return (buf);
}

module.exports = Signature;
