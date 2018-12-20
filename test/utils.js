// Copyright 2011 Joyent, Inc.  All rights reserved.

var test = require('tape').test;
var Buffer = require('safer-buffer').Buffer;

var utils = require('../lib/utils');

test('bufferSplit single char', function(t) {
	var b = Buffer.from('abc 123 xyz ttt');
	var r = utils.bufferSplit(b, ' ');
	t.equal(r.length, 4);
	t.equal(r[0].toString(), 'abc');
	t.equal(r[1].toString(), '123');
	t.equal(r[2].toString(), 'xyz');
	t.end();
});

test('bufferSplit single char double sep', function(t) {
	var b = Buffer.from('abc 123 xyz   ttt');
	var r = utils.bufferSplit(b, ' ');
	t.equal(r.length, 6);
	t.equal(r[0].toString(), 'abc');
	t.equal(r[1].toString(), '123');
	t.equal(r[4].toString(), '');
	t.equal(r[5].toString(), 'ttt');
	t.end();
});

test('bufferSplit multi char', function(t) {
	var b = Buffer.from('abc 123 xyz ttt  ');
	var r = utils.bufferSplit(b, '123');
	t.equal(r.length, 2);
	t.equal(r[0].toString(), 'abc ');
	t.equal(r[1].toString(), ' xyz ttt  ');
	t.end();
});

/* These taken from RFC6070 */
test('pbkdf2 test vector 1', function (t) {
	var hashAlg = 'sha1';
	var salt = Buffer.from('salt');
	var iterations = 1;
	var size = 20;
	var passphrase = Buffer.from('password');

	var key = utils.pbkdf2(hashAlg, salt, iterations, size, passphrase);
	t.equal(key.toString('hex').toLowerCase(),
	    '0c60c80f961f0e71f3a9b524af6012062fe037a6');
	t.end();
});

test('pbkdf2 test vector 2', function (t) {
	var hashAlg = 'sha1';
	var salt = Buffer.from('salt');
	var iterations = 2;
	var size = 20;
	var passphrase = Buffer.from('password');

	var key = utils.pbkdf2(hashAlg, salt, iterations, size, passphrase);
	t.equal(key.toString('hex').toLowerCase(),
	    'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');
	t.end();
});

test('pbkdf2 test vector 5', function (t) {
	var hashAlg = 'sha1';
	var salt = Buffer.from('saltSALTsaltSALTsaltSALTsaltSALTsalt');
	var iterations = 4096;
	var size = 25;
	var passphrase = Buffer.from('passwordPASSWORDpassword');

	var key = utils.pbkdf2(hashAlg, salt, iterations, size, passphrase);
	t.equal(key.toString('hex').toLowerCase(),
	    '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038');
	t.end();
});

test('pbkdf2 wiki test', function (t) {
	var hashAlg = 'sha1';
	var salt = Buffer.from('A009C1A485912C6AE630D3E744240B04', 'hex');
	var iterations = 1000;
	var size = 16;
	var passphrase = Buffer.from(
	    'plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd');

	var key = utils.pbkdf2(hashAlg, salt, iterations, size, passphrase);
	t.equal(key.toString('hex').toUpperCase(),
	    '17EB4014C8C461C300E9B61518B9A18B');
	t.end();
});
