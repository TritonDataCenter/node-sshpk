// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var algInfos = require('../algs').info;
var Key;

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
		return ('ecdsa-sha2-' + key.part.curve.data.toString());
	else
		throw (new Error('Unknown key type ' + key.type));
}

function read(buf) {
	assert.buffer(buf, 'buf');

	/* Defer until runtime due to circular deps */
	if (Key === undefined)
		Key = require('../key');

	var key = {};
	key._rfc4253Cache = buf;

	var parts = key.parts = [];
	var offset = 0;
	while (offset < buf.length) {
		var len = buf.readUInt32BE(offset);
		offset += 4;
		parts.push({data: buf.slice(offset, offset + len)});
		offset += len;
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
		assert.strictEqual(res[1], parts[0].data.toString());
	}

	assert.strictEqual(algInfo.parts.length, parts.length);
	for (var i = 0; i < algInfo.parts.length; ++i)
		parts[i].name = algInfo.parts[i];

	return (new Key(key));
}

function write(key) {
	assert.object(key);

	var alg = keyTypeToAlg(key);
	var i;

	var size = 0;
	for (i = 0; i < key.parts.length; ++i)
		size += 4 + key.parts[i].data.length;
	size += alg.length + 4;

	var buf = new Buffer(size);
	var o = 0;

	o = buf.writeUInt32BE(alg.length, o);
	o += buf.write(alg, o);

	for (i = 0; i < key.parts.length; ++i) {
		o = buf.writeUInt32BE(key.parts[i].data.length, o);
		o += key.parts[i].data.copy(buf, o);
	}
	buf = buf.slice(0, o);

	return (buf);
}

module.exports = {
	read: read,
	write: write,

	/* shared with ssh format */
	keyTypeToAlg: keyTypeToAlg,
	algToKeyType: algToKeyType
};
