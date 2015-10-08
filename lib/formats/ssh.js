// Copyright 2015 Joyent, Inc.

module.exports = {
	read: read,
	write: write
};

var assert = require('assert-plus');
var rfc4253 = require('./rfc4253');
var utils = require('../utils');
var Key = require('../key');
var PrivateKey = require('../private-key');

var sshpriv = require('./ssh-private');

function read(buf) {
	if (typeof (buf) !== 'string') {
		assert.buffer(buf, 'buf');
		buf = buf.toString('ascii');
	}

	var parts = buf.trim().replace(/\s+/g, ' ').split(' ');
	assert.ok(parts.length === 2 || parts.length === 3,
	    'invalid extra whitespace within key');

	var type = rfc4253.algToKeyType(parts[0]);

	var kbuf = new Buffer(parts[1], 'base64');
	var key = rfc4253.read(kbuf);

	assert.strictEqual(type, key.type);

	if (parts[2])
		key.comment = parts[2];

	return (key);
}

function write(key) {
	assert.object(key);
	if (key instanceof PrivateKey)
		throw (new Error('Private keys are not supported'));

	var parts = [];
	var alg = rfc4253.keyTypeToAlg(key);
	parts.push(alg);

	var buf = rfc4253.write(key);
	parts.push(buf.toString('base64'));

	if (key.comment)
		parts.push(key.comment);

	return (new Buffer(parts.join(' ')));
}
