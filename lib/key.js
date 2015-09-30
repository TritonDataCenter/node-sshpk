// Copyright 2015 Joyent, Inc.

module.exports = Key;

var assert = require('assert-plus');
var algs = require('./algs');
var crypto = require('crypto');
var Fingerprint = require('./fingerprint');
var Signature = require('./signature');
var errs = require('./errors');
var PrivateKey = require('./private-key');

var InvalidAlgorithmError = errs.InvalidAlgorithmError;
var KeyParseError = errs.KeyParseError;

var formats = {};
formats['pem'] = require('./formats/pem');
formats['pkcs1'] = require('./formats/pkcs1');
formats['pkcs8'] = require('./formats/pkcs8');
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

	var partLookup = {};
	for (var i = 0; i < opts.parts.length; ++i) {
		var part = opts.parts[i];
		partLookup[part.name] = part;
	}

	Object.defineProperties(this, {
		type: { enumerable: true, value: opts.type },
		parts: { value: opts.parts },
		part: { value: partLookup },
		comment: { enumerable: true, writable: true,
		    value: opts.comment },
		source: { value: opts.source },

		/* To make things faster when all you want is the fingerprint */
		_rfc4253Cache: { writable: true,
		    value: opts._rfc4253Cache },
		_hashCache: { writable: true, value: {} }
	});

	if (this.type === 'ecdsa') {
		var curve = this.part.curve.data.toString();
		Object.defineProperties(this, {
			curve: { enumerable: true, value: curve },
			size: { enumerable: true,
			    value: algs.curves[curve].size }
		});
	} else {
		var szPart = this.part[algInfo.sizePart];
		var sz = szPart.data.length;
		if (szPart.data[0] === 0x0)
			sz--;
		Object.defineProperties(this, {
			size: { enumerable: true, value: sz * 8 }
		});
	}
}

Key.prototype.toBuffer = function (format) {
	if (format === undefined)
		format = 'ssh';
	assert.string(format, 'format');
	assert.object(formats[format], 'formats[format]');

	if (format === 'rfc4253') {
		if (this._rfc4253Cache === undefined)
			this._rfc4253Cache = formats['rfc4253'].write(this);
		return (this._rfc4253Cache);
	}

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

	var hash = crypto.createHash(algo).
	    update(this.toBuffer('rfc4253')).digest();
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
	var v, nm, err;
	try {
		nm = this.type.toUpperCase() + '-';
		if (this.type === 'ecdsa')
			nm = 'ecdsa-with-';
		nm += hashAlgo.toUpperCase();
		v = crypto.createVerify(nm);
	} catch (e) {
		err = e;
	}
	if (v === undefined || (err instanceof Error &&
	    err.message.match(/Unknown message digest/))) {
		nm = 'RSA-';
		nm += hashAlgo.toUpperCase();
		v = crypto.createVerify(nm);
	}
	assert.ok(v, 'failed to create verifier');
	var oldVerify = v.verify.bind(v);
	var key = this.toBuffer('pkcs8');
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
		if (k instanceof PrivateKey)
			k = k.toPublic();
		return (k);
	} catch (e) {
		throw (new KeyParseError(name, format, e));
	}
};
