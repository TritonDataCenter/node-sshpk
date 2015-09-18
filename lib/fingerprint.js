// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var algs = require('./algs');
var crypto = require('crypto');
var Key = require('./key');
var errs = require('./errors');

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
	this.hash2 = crypto.createHash(this.algorithm).
	    update(this.hash).digest('base64');
}

Fingerprint.prototype.toString = function (format) {
	if (format === undefined)
		if (this.algorithm === 'md5')
			format = 'hex';
		else
			format = 'base64';
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
}

Fingerprint.prototype.matches = function (key) {
	assert.object(key, 'key');
	assert.ok(key instanceof Key, 'key');

	var theirHash = key.hash(this.algorithm);
	var theirHash2 = crypto.createHash(this.algorithm).
	    update(theirHash).digest('base64');

	return (this.hash2 === theirHash2);
}

Fingerprint.parse = function (fp, algs) {
	assert.string(fp, 'fingerprint');

	var alg, hash;
	assert.optionalArrayOfString(algs, 'algorithms');

	var parts = fp.split(':');
	if (parts.length == 2) {
		alg = parts[0].toLowerCase();
		hash = new Buffer(parts[1], 'base64');
	} else if (parts.length > 2) {
		alg = 'md5';
		if (parts[0].toLowerCase() === 'md5')
			parts = parts.slice(1);
		parts = parts.join('');
		if (!/^[a-fA-F0-9]+$/.test(parts))
			throw (new FingerprintFormatError(fp));
		hash = new Buffer(parts, 'hex');
	}

	if (alg === undefined)
		throw (new FingerprintFormatError(fp));

	if (algs !== undefined) {
		algs = algs.map(function (a) { return a.toLowerCase(); });
		if (algs.indexOf(alg) === -1)
			throw (new InvalidAlgorithmError(alg));
	}

	return (new Fingerprint({algorithm: alg, hash: hash}));
}

function addColons(s) {
	return (s.replace(/(.{2})(?=.)/g, '$1:'));
}

function base64Strip(s) {
	return (s.replace(/=*$/, ''));
}

function sshBase64Format(alg, h) {
	return (alg.toUpperCase() + ':' + 
	    base64Strip(h.digest('base64')));
}

module.exports = Fingerprint;
