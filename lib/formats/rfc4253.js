// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var algInfos = require('../algs').info;
var Key = require('../key');

function algToKeyType(alg) {
	assert.string(alg);
	if (alg === 'ssh-dss')
		return ('dsa');
	else if (alg === 'ssh-rsa')
		return ('rsa');
	else if (alg.match(/^ecdsa-sha2-/))
		return ('ecdsa');
	else
		throw (new Error('Unknown algorithm ' + alg));
}

function keyTypeToAlg(key) {
	assert.object(key);
	if (key.type === 'dsa')
		return ('ssh-dss');
	else if (key.type === 'rsa')
		return ('ssh-rsa');
	else if (key.type === 'ecdsa')
		return ('ecdsa-sha2-' + key.curve);
	else
		throw (new Error('Unknown key type ' + key.type));
}

function read(buf) {
	assert.buffer(buf, 'buf');

	var parts = key.parts = [];
	while (buf.length > 0) {
		var len = buf.readUInt32BE(0);
		buf = buf.slice(4);
		parts.push({data: buf.slice(0, len)});
		buf = buf.slice(len);
	}

	assert.ok(parts.length > 1);
	assert.ok(parts[0].data.length > 0);

	var alg = parts[0].data.toString();
	key.type = algToKeyType(alg);

	/* Now chop off the algorithm identifier */
	parts = key.parts = parts.slice(1);

	var algInfo = algInfos[key.type];

	if (key.type === 'ecdsa') {
		var res = /^ecdsa-sha2-(.+)$/.exec(alg);
		assert.ok(res !== null);
		key.curve = res[1];
	}

	assert.strictEqual(algInfo.parts.length, parts.length);
	for (var i = 0; i < algInfo.parts.length; ++i)
		parts[i].name = algInfo.parts[i];

	return (new Key(key));
}

function write(key) {
	assert.object(key);
	assert.ok(key instanceof Key);

	var parts = [];

	var alg = keyTypeToAlg(key);
	parts.push(new Buffer(alg));

	for (var i = 0; i < key.parts.length; ++i)
		parts.push(key.parts[i].data);

	var buf = new Buffer(0);
	for (var i = 0; i < parts.length; ++i) {
		var b = new Buffer(4);
		b.writeUInt32BE(0, parts[i].length);
		buf = Buffer.concat([buf, b, parts[i]]);
	}

	return (buf);
}

module.exports = {
	read: read,
	write: write,

	/* shared with ssh format */
	keyTypeToAlg: keyTypeToAlg,
	algToKeyType: algToKeyType
};
