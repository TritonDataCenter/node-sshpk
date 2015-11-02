// Copyright 2015 Joyent, Inc.

module.exports = Fingerprint;

var assert = require('assert-plus');
var algs = require('./algs');
var crypto = require('crypto');
var errs = require('./errors');
var Key = require('./key');

var FingerprintFormatError = errs.FingerprintFormatError;
var InvalidAlgorithmError = errs.InvalidAlgorithmError;

function Fingerprint(opts) {
	assert.object(opts, 'options');
	assert.buffer(opts.hash, 'options.hash');
	assert.string(opts.algorithm, 'options.algorithm');

	this.algorithm = opts.algorithm.toLowerCase();
	if (algs.hashAlgs[this.algorithm] !== true)
		throw (new InvalidAlgorithmError(this.algorithm));

	this.hash = opts.hash;
}

Fingerprint.prototype.toString = function (format) {
	if (format === undefined) {
		if (this.algorithm === 'md5')
			format = 'hex';
		else
			format = 'base64';
	}
	assert.string(format);

	switch (format) {
	case 'hex':
		return (addColons(this.hash.toString('hex')));
	case 'base64':
		return (sshBase64Format(this.algorithm,
		    this.hash.toString('base64')));
	default:
		throw (new FingerprintFormatError(undefined, format));
	}
};

Fingerprint.prototype.matches = function (key) {
	assert.object(key, 'key');
	/* Defer until runtime due to circular deps */
	if (Key === undefined)
		Key = require('./key');
	assert.ok(key instanceof Key, 'key');

	var theirHash = key.hash(this.algorithm);
	var theirHash2 = crypto.createHash(this.algorithm).
	    update(theirHash).digest('base64');

	if (this.hash2 === undefined)
		this.hash2 = crypto.createHash(this.algorithm).
		    update(this.hash).digest('base64');

	return (this.hash2 === theirHash2);
};

Fingerprint.parse = function (fp, enAlgs) {
	assert.string(fp, 'fingerprint');

	var alg, hash;
	assert.optionalArrayOfString(enAlgs, 'algorithms');

	var parts = fp.split(':');
	if (parts.length == 2) {
		alg = parts[0].toLowerCase();
		/*JSSTYLED*/
		var base64RE = /^[A-Za-z0-9+\/=]+$/;
		if (!base64RE.test(parts[1]))
			throw (new FingerprintFormatError(fp));
		try {
			hash = new Buffer(parts[1], 'base64');
		} catch (e) {
			throw (new FingerprintFormatError(fp));
		}
	} else if (parts.length > 2) {
		alg = 'md5';
		if (parts[0].toLowerCase() === 'md5')
			parts = parts.slice(1);
		parts = parts.join('');
		/*JSSTYLED*/
		var md5RE = /^[a-fA-F0-9]+$/;
		if (!md5RE.test(parts))
			throw (new FingerprintFormatError(fp));
		try {
			hash = new Buffer(parts, 'hex');
		} catch (e) {
			throw (new FingerprintFormatError(fp));
		}
	}

	if (alg === undefined)
		throw (new FingerprintFormatError(fp));

	if (algs.hashAlgs[alg] === undefined)
		throw (new InvalidAlgorithmError(alg));

	if (enAlgs !== undefined) {
		enAlgs = enAlgs.map(function (a) { return a.toLowerCase(); });
		if (enAlgs.indexOf(alg) === -1)
			throw (new InvalidAlgorithmError(alg));
	}

	return (new Fingerprint({algorithm: alg, hash: hash}));
};

function addColons(s) {
	/*JSSTYLED*/
	return (s.replace(/(.{2})(?=.)/g, '$1:'));
}

function base64Strip(s) {
	/*JSSTYLED*/
	return (s.replace(/=*$/, ''));
}

function sshBase64Format(alg, h) {
	return (alg.toUpperCase() + ':' + base64Strip(h));
}
