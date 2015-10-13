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

/*JSSTYLED*/
var SSHKEY_RE = /^([a-z0-9-]+)\s+([a-zA-Z0-9+\/]+[=]*)\s*(.*)$/;

function read(buf) {
	if (typeof (buf) !== 'string') {
		assert.buffer(buf, 'buf');
		buf = buf.toString('ascii');
	}

	var m = buf.trim().match(SSHKEY_RE);
	assert.ok(m, 'key must match regex');

	var type = rfc4253.algToKeyType(m[1]);

	var kbuf = new Buffer(m[2], 'base64');
	var key = rfc4253.read(kbuf);

	assert.strictEqual(type, key.type);

	if (m[3] && m[3].length > 0)
		key.comment = m[3];

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
