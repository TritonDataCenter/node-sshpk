// Copyright 2015 Joyent, Inc.

module.exports = {
	Verifier: Verifier,
	Signer: Signer
};

var ed;
var stream = require('stream');
var util = require('util');
var assert = require('assert-plus');
var Signature = require('./signature');

function Verifier(key, hashAlgo) {
	if (ed === undefined)
		ed = require('jodid25519');

	if (hashAlgo.toLowerCase() !== 'sha512')
		throw (new Error('ED25519 only supports the use of ' +
		    'SHA-512 hashes'));

	this.key = key;
	this.chunks = [];

	stream.Writable.call(this, {});
}
util.inherits(stream.Writable, Verifier);

Verifier.prototype._write = function (chunk, enc, cb) {
	this.chunks.push(chunk);
	cb();
};

Verifier.prototype.update = function (chunk) {
	if (typeof (chunk) === 'string')
		chunk = new Buffer(chunk, 'binary');
	this.chunks.push(chunk);
};

Verifier.prototype.verify = function (signature, fmt) {
	var sig;
	if (typeof (signature) === 'object' &&
	    signature instanceof Signature)
		sig = signature.toBuffer('raw');
	else if (typeof (signature) === 'string')
		sig = new Buffer(signature, 'base64');
	assert.buffer(sig);
	return (ed.eddsa.verify(sig.toString('binary'),
	    Buffer.concat(this.chunks).toString('binary'),
	    this.key.part.R.data.toString('binary')));
};

function Signer(key, hashAlgo) {
	if (ed === undefined)
		ed = require('jodid25519');

	if (hashAlgo.toLowerCase() !== 'sha512')
		throw (new Error('ED25519 only supports the use of ' +
		    'SHA-512 hashes'));

	this.key = key;
	this.chunks = [];

	stream.Writable.call(this, {});
}
util.inherits(stream.Writable, Signer);

Signer.prototype._write = function (chunk, enc, cb) {
	this.chunks.push(chunk);
	cb();
};

Signer.prototype.update = function (chunk) {
	if (typeof (chunk) === 'string')
		chunk = new Buffer(chunk, 'binary');
	this.chunks.push(chunk);
};

Signer.prototype.sign = function () {
	var sig = ed.eddsa.sign(Buffer.concat(this.chunks).toString('binary'),
	    this.key.part.r.data.slice(0, 32).toString('binary'),
	    this.key.part.R.data.toString('binary'));
	var sigBuf = new Buffer(sig, 'binary');
	var sigObj = Signature.parse(sigBuf, 'ed25519', 'raw');
	sigObj.hashAlgorithm = 'sha512';
	return (sigObj);
};
