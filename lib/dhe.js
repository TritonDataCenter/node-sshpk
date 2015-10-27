// Copyright 2015 Joyent, Inc.

module.exports = DiffieHellman;

var assert = require('assert-plus');
var crypto = require('crypto');
var ed;

var Key = require('./key');
var PrivateKey = require('./private-key');

function DiffieHellman(key) {
	this._algo = key.type;
	this._curve = key.curve;
	this._key = key;
	if (key.type === 'dsa') {
		this._dh = crypto.createDiffieHellman(
		    key.part.p.data, undefined,
		    key.part.g.data, undefined);
		this._p = key.part.p;
		this._g = key.part.g;
		this._dh.setPrivateKey(key.part.x.data);
		this._dh.setPublicKey(key.part.y.data);
	} else if (key.type === 'ecdsa') {
		var curve = {
			'nistp256': 'prime256v1',
			'nistp384': 'secp384r1',
			'nistp521': 'secp521r1'
		}[key.curve];
		this._dh = crypto.createECDH(curve);
		this._dh.setPrivateKey(key.part.d.data);
		this._dh.setPublicKey(key.part.Q.data);
	} else if (key.type === 'curve25519') {
		if (ed === undefined)
			ed = require('jodid25519');
		this._priv = key.part.r.data;
		if (this._priv[0] === 0x00)
			this._priv = this._priv.slice(1);
		this._priv = this._priv.slice(0, 32);
	} else {
		throw (new Error('DH not supported for ' + key.type + ' keys'));
	}
}

DiffieHellman.prototype.getPublicKey = function () {
	return (this._key.toPublic());
};

DiffieHellman.prototype.getPrivateKey = function () {
	return (this._key);
};
DiffieHellman.prototype.getKey = DiffieHellman.prototype.getPrivateKey;

DiffieHellman.prototype._keyCheck = function (pk, isPub) {
	assert.object(pk, 'key');
	if (!isPub) {
		assert.ok(pk instanceof PrivateKey,
		    'key must be a sshpk.PrivateKey');
	}
	assert.ok(pk instanceof Key, 'key must be a sshpk.Key');

	if (pk.type !== this._algo) {
		throw (new Error('A ' + pk.type + ' key cannot be used in ' +
		    this._algo + ' Diffie-Hellman'));
	}

	if (pk.curve !== this._curve) {
		throw (new Error('A key from the ' + pk.curve + ' curve ' +
		    'cannot be used with a ' + this._curve +
		    ' Diffie-Hellman'));
	}

	if (pk.type === 'dsa') {
		assert.deepEqual(pk.part.p, this._p,
		    'DSA key prime does not match');
		assert.deepEqual(pk.part.g, this._g,
		    'DSA key generator does not match');
	}
};

DiffieHellman.prototype.setKey = function (pk) {
	this._keyCheck(pk);

	if (pk.type === 'dsa') {
		this._dh.setPrivateKey(pk.part.x.data);
		this._dh.setPublicKey(pk.part.y.data);

	} else if (pk.type === 'ecdsa') {
		this._dh.setPrivateKey(pk.part.d.data);
		this._dh.setPublicKey(pk.part.Q.data);

	} else if (pk.type === 'curve25519') {
		this._priv = pk.part.r.data;
		if (this._priv[0] === 0x00)
			this._priv = this._priv.slice(1);
		this._priv = this._priv.slice(0, 32);
	}
	this._key = pk;
};
DiffieHellman.prototype.setPrivateKey = DiffieHellman.prototype.setKey;

DiffieHellman.prototype.computeSecret = function (otherpk) {
	this._keyCheck(otherpk, true);

	if (this._algo === 'dsa') {
		return (this._dh.computeSecret(
		    otherpk.part.y.data));

	} else if (this._algo === 'ecdsa') {
		return (this._dh.computeSecret(
		    otherpk.part.Q.data));

	} else if (this._algo === 'curve25519') {
		var pub = otherpk.part.R.data;
		if (pub[0] === 0x00)
			pub = pub.slice(1);

		var secret = ed.dh.computeKey(
		    this._priv.toString('binary'),
		    pub.toString('binary'));

		return (new Buffer(secret, 'binary'));
	}

	throw (new Error('Invalid algorithm: ' + this._algo));
};

DiffieHellman.prototype.generateKey = function () {
	var parts = [];
	if (this._algo === 'dsa') {
		this._dh.generateKeys();

		parts.push({name: 'p', data: this._p.data});
		parts.push({name: 'q', data: this._key.part.q.data});
		parts.push({name: 'g', data: this._g.data});
		parts.push({name: 'y', data: this._dh.getPublicKey()});
		parts.push({name: 'x', data: this._dh.getPrivateKey()});
		this._key = new PrivateKey({
			type: 'dsa',
			parts: parts
		});
		return (this._key);

	} else if (this._algo === 'ecdsa') {
		this._dh.generateKeys();

		parts.push({name: 'curve', data: new Buffer(this._curve)});
		parts.push({name: 'Q', data: this._dh.getPublicKey()});
		parts.push({name: 'd', data: this._dh.getPrivateKey()});
		this._key = new PrivateKey({
			type: 'ecdsa',
			curve: this._curve,
			parts: parts
		});
		return (this._key);

	} else if (this._algo === 'curve25519') {
		var priv = ed.dh.generateKey();
		var pub = ed.dh.publicKey(priv);
		priv = new Buffer(priv, 'binary');
		pub = new Buffer(pub, 'binary');

		parts.push({name: 'R', data: pub});
		parts.push({name: 'r', data: Buffer.concat([priv, pub])});
		this._key = new PrivateKey({
			type: 'curve25519',
			parts: parts
		});
		return (this._key);
	}

	throw (new Error('Invalid algorithm: ' + this._algo));
};
DiffieHellman.prototype.generateKeys = DiffieHellman.prototype.generateKey;
