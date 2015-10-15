// Copyright 2015 Joyent, Inc.

module.exports = {
	bufferSplit: bufferSplit,
	addRSAMissing: addRSAMissing,
	calculateDSAPublic: calculateDSAPublic,
	mpNormalize: mpNormalize,
	ecNormalize: ecNormalize
};

var assert = require('assert-plus');
var PrivateKey = require('./private-key');

function bufferSplit(buf, chr) {
	assert.buffer(buf);
	assert.string(chr);

	var parts = [];
	var lastPart = 0;
	var matches = 0;
	for (var i = 0; i < buf.length; ++i) {
		if (buf[i] === chr.charCodeAt(matches))
			++matches;
		else if (buf[i] === chr.charCodeAt(0))
			matches = 1;
		else
			matches = 0;

		if (matches >= chr.length) {
			var newPart = i + 1;
			parts.push(buf.slice(lastPart, newPart - matches));
			lastPart = newPart;
			matches = 0;
		}
	}
	if (lastPart <= buf.length)
		parts.push(buf.slice(lastPart, buf.length));

	return (parts);
}

function ecNormalize(buf, addZero) {
	assert.buffer(buf);
	if (buf[0] === 0x00 && buf[1] === 0x04) {
		if (addZero)
			return (buf);
		return (buf.slice(1));
	} else if (buf[0] === 0x04) {
		if (!addZero)
			return (buf);
	} else {
		while (buf[0] === 0x00)
			buf = buf.slice(1);
		if (buf[0] === 0x02 || buf[0] === 0x03)
			throw (new Error('Compressed elliptic curve points ' +
			    'are not supported'));
		if (buf[0] !== 0x04)
			throw (new Error('Not a valid elliptic curve point'));
		if (!addZero)
			return (buf);
	}
	var b = new Buffer(buf.length + 1);
	b[0] = 0x0;
	buf.copy(b, 1);
	return (b);
}

function mpNormalize(buf) {
	assert.buffer(buf);
	while (buf.length > 1 && buf[0] === 0x00 && (buf[1] & 0x80) === 0x00)
		buf = buf.slice(1);
	if ((buf[0] & 0x80) === 0x80) {
		var b = new Buffer(buf.length + 1);
		b[0] = 0x00;
		buf.copy(b, 1);
		buf = b;
	}
	return (buf);
}

function calculateDSAPublic(g, p, x) {
	assert.buffer(g);
	assert.buffer(p);
	assert.buffer(x);
	try {
		var bigInt = require('big-integer');
	} catch (e) {
		throw (new Error('To load a PKCS#8 format DSA private key, ' +
		    'the node big-integer library is required.'));
	}
	g = bigInt(g.toString('hex'), 16);
	p = bigInt(p.toString('hex'), 16);
	x = bigInt(x.toString('hex'), 16);
	var y = modexp(g, x, p);
	y = new Buffer(y.toString(16), 'hex');
	if ((y[0] & 0x80) == 0x80) {
		var b = new Buffer(y.length + 1);
		b[0] = 0x00;
		y.copy(b, 1);
		y = b;
	}
	return (y);

	/* Bruce Schneier's modular exponentiation algorithm */
	function modexp(base, exp, mod) {
		var res = bigInt(1);
		base = base.mod(mod);
		while (exp.gt(0)) {
			if (exp.isOdd())
				res = res.times(base).mod(mod);
			exp = exp.shiftRight(1);
			base = base.square().mod(mod);
		}
		return (res);
	}
}

function addRSAMissing(key) {
	assert.object(key);
	assert.ok(key instanceof PrivateKey);
	try {
		var bigInt = require('big-integer');
	} catch (e) {
		throw (new Error('To write a PEM private key from ' +
		    'this source, the node big-integer lib is required.'));
	}

	var d = bigInt(key.part.d.data.toString('hex'), 16);
	var b;

	if (!key.part.dmodp) {
		var p = bigInt(key.part.p.data.toString('hex'), 16);
		var dmodp = d.mod(p.minus(1));
		dmodp = new Buffer(dmodp.toString(16), 'hex');
		if ((dmodp[0] & 0x80) == 0x80) {
			b = new Buffer(dmodp.length + 1);
			b[0] = 0x00;
			dmodp.copy(b, 1);
			dmodp = b;
		}
		key.part.dmodp = {name: 'dmodp', data: dmodp};
		key.parts.push(key.part.dmodp);
	}
	if (!key.part.dmodq) {
		var q = bigInt(key.part.q.data.toString('hex'), 16);
		var dmodq = d.mod(q.minus(1));
		dmodq = new Buffer(dmodq.toString(16), 'hex');
		if ((dmodq[0] & 0x80) == 0x80) {
			b = new Buffer(dmodq.length + 1);
			b[0] = 0x00;
			dmodq.copy(b, 1);
			dmodq = b;
		}
		key.part.dmodq = {name: 'dmodq', data: dmodq};
		key.parts.push(key.part.dmodq);
	}
}
