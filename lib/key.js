// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var algs = require('./algs');
var crypto = require('crypto');
var Fingerprint = require('./fingerprint');
var Signature = require('./signature');
var errs = require('./errors');

var InvalidAlgorithmError = errs.InvalidAlgorithmError;
var KeyParseError = errs.KeyParseError;

var formats = {};
formats['pem'] = require('./formats/pem');
formats['rfc4253'] = require('./formats/rfc4253');
formats['ssh'] = require('./formats/ssh');

function Key(opts) {
	assert.object(opts, 'options');
	assert.arrayOfObject(opts.parts, 'options.parts');
	assert.string(opts.type, 'options.type');
	assert.optionalString(opts.comment, 'options.comment');

	var algInfo = algs.info[opts.type];
	if (typeof (algInfo) !== 'object')
		throw (new InvalidAlgorithmError(opts.type));

	this.type = opts.type;
	this.parts = opts.parts;
	this.comment = opts.comment;

	/* To make things faster when all you want to do is get a fingerprint */
	this._rfc4253Cache = opts._rfc4253Cache;
	this._hashCache = {};

	this.part = {};
	for (var i = 0; i < opts.parts.length; ++i) {
		var part = opts.parts[i];
		this.part[part.name] = part;
	}

	if (this.type === 'ecdsa') {
		this.curve = this.part.curve.data.toString();
		this.size = algs.curves[this.curve].size;
	} else {
		var szPart = this.part[algInfo.sizePart];
		var sz = szPart.data.length;
		if (szPart.data[0] === 0x0)
			sz--;
		this.size = sz * 8;
	}
}

Key.prototype.toBuffer = function (format) {
	if (format === undefined)
		format = 'ssh';
	assert.string(format, 'format');
	assert.object(formats[format], 'formats[format]');

	return (formats[format].write(this));
};

Key.prototype.toString = function (format) {
	return (this.toBuffer(format).toString());
};

Key.prototype.hash = function (algo) {
	assert.string(algo, 'algorithm');
	algo = algo.toLowerCase();
	assert.ok(algs.hashAlgs[algo]);

	if (this._hashCache[algo])
		return (this._hashCache[algo]);

	if (this._rfc4253Cache === undefined)
		this._rfc4253Cache = formats['rfc4253'].write(this);

	var hash = crypto.createHash(algo).
	    update(this._rfc4253Cache).digest();
	/* Workaround for node 0.8 */
	if (typeof (hash) === 'string')
		hash = new Buffer(hash, 'binary');
	this._hashCache[algo] = hash;
	return (hash);
};

Key.prototype.fingerprint = function (algo) {
	if (algo === undefined)
		algo = 'sha256';
	assert.string(algo, 'algorithm');
	var opts = {
		hash: this.hash(algo),
		algorithm: algo
	};
	return (new Fingerprint(opts));
};

Key.prototype.createVerify = function (hashAlgo) {
	if (hashAlgo === undefined) {
		hashAlgo = 'sha1';
		if (this.type === 'rsa')
			hashAlgo = 'sha256';
		if (this.type === 'ecdsa') {
			if (this.size <= 256)
				hashAlgo = 'sha256';
			else if (this.size <= 384)
				hashAlgo = 'sha384';
			else
				hashAlgo = 'sha512';
		}
	}
	assert.string(hashAlgo, 'hash algorithm');
	var v, nm;
	try {
		nm = this.type.toUpperCase() + '-';
		if (this.type === 'ecdsa')
			nm += 'with-';
		nm += hashAlgo.toUpperCase();
		v = crypto.createVerify(nm);
	} catch (e) {
		if (e instanceof Error &&
		    e.message.match(/Unknown message digest/)) {
			nm = 'RSA-';
			nm += hashAlgo.toUpperCase();
			v = crypto.createVerify(nm);
		}
	}
	var oldVerify = v.verify.bind(v);
	var key = this.toBuffer('pem');
	v.verify = function (signature, fmt) {
		if (typeof (signature) === 'object' &&
		    signature instanceof Signature)
			return (oldVerify(key, signature.toBuffer('asn1')));
		return (oldVerify(key, signature, fmt));
	};
	return (v);
};

Key.parse = function (data, format, name) {
	if (typeof (data) !== 'string')
		assert.buffer(data, 'data');
	if (format === undefined)
		format = 'ssh';
	assert.string(format, 'format');
	if (name === undefined)
		name = '(unnamed)';

	assert.object(formats[format], 'formats[format]');

	try {
		var k = formats[format].read(data);
		return (k);
	} catch (e) {
		throw (new KeyParseError(name, format, e));
	}
};

module.exports = Key;
