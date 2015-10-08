// Copyright 2015 Joyent, Inc.

module.exports = {
	read: read,
	write: write
};

var assert = require('assert-plus');
var utils = require('../utils');
var Key = require('../key');
var PrivateKey = require('../private-key');

var pem = require('./pem');
var ssh = require('./ssh');
var rfc4253 = require('./rfc4253');

function read(buf) {
	if (buf.slice(0, 4).toString('ascii') === '----')
		return (pem.read(buf));
	if (buf.slice(0, 4).toString('ascii') === 'ssh-')
		return (ssh.read(buf));
	if (buf.readUInt32BE(0) < buf.length)
		return (rfc4253.read(buf));
	throw (new Error('Failed to auto-detect format of key'));
}

function write(key) {
	throw (new Error('"auto" format cannot be used for writing'));
}
