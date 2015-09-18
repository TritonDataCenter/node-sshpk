// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var rfc4253 = require('./rfc4253');
var utils = require('../utils');

function read(buf) {
	assert.buffer(buf);

	var parts = buf.toString('ascii').split(' ');
	assert.ok(parts.length >= 2);

	var type = rfc4253.algToKeyType(parts[0]);

	var buf = new Buffer(parts[1], 'base64');
	var key = rfc4253.read(buf);

	assert.strictEqual(type, key.type);

	if (parts[2])
		key.comment = parts[2];

	return (key);
}

function write(key) {
	assert.object(key);

	var parts = [];
	var alg = rfc4253.keyTypeToAlg(key);
	parts.push(alg);

	var buf = rfc4253.write(key);
	parts.push(buf.toString('base64'));

	if (key.comment)
		parts.push(key.comment);

	return (new Buffer(parts.join(' ')));
}

module.exports = {
	read: read,
	write: write
};
