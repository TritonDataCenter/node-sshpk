// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var algs = require('./algs');
var crypto = require('crypto');
var Fingerprint = require('./fingerprint');
var errs = require('./errors');

var InvalidAlgorithmError = errs.InvalidAlgorithmError;

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

	var self = this;

	this.part = {};
	opts.parts.forEach(function (part) {
		self.part[part.name] = part;
	});

	var szPart = this.part[algInfo.sizePart].data;
	var sz = szPart.length;
	if (szPart.readUInt8(0) === 0)
		sz--;
	this.size = sz * 8 / 2;
}

Key.prototype.toString = function (format) {
	if (format === undefined)
		format = 'ssh';
	assert.string(format, 'format');
	assert.object(formats[format], 'formats[format]');

	return (formats[format].write(this).toString());
}

Key.prototype.hash = function (algo) {
	assert.string(algo, 'algorithm');
	algo = algo.toLowerCase();
	assert.ok(algs.hashAlgs[algo]);

	var buf = formats['rfc4253'].write(this);
	var hash = crypto.createHash(algo).update(buf).digest();
	return (hash);
}

Key.prototype.fingerprint = function (algo) {
	if (algo === undefined)
		algo = 'md5';
	assert.string(algo, 'algorithm');
	var opts = {
		hash: this.hash(algo),
		algorithm: algo
	};
	return (new Fingerprint(opts));
}

Key.parse = function (data, format) {
	if (typeof (data) === 'string')
		data = new Buffer(data);
	assert.buffer(data, 'data');
	if (format === 'undefined')
		format = 'ssh';
	assert.string(format, 'format');
	assert.object(formats[format], 'formats[format]');

	return (formats[format].read(data));
}

module.exports = Key;
