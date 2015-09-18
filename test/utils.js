// Copyright 2011 Joyent, Inc.  All rights reserved.

var test = require('tap').test;

var utils = require('../lib/utils');

test('bufferSplit single char', function(t) {
	var b = new Buffer('abc 123 xyz ttt');
	var r = utils.bufferSplit(b, ' ');
	t.equal(r.length, 4);
	t.equal(r[0].toString(), 'abc');
	t.equal(r[1].toString(), '123');
	t.equal(r[2].toString(), 'xyz');
	t.end();
});

test('bufferSplit single char double sep', function(t) {
	var b = new Buffer('abc 123 xyz   ttt');
	var r = utils.bufferSplit(b, ' ');
	t.equal(r.length, 6);
	t.equal(r[0].toString(), 'abc');
	t.equal(r[1].toString(), '123');
	t.equal(r[4].toString(), '');
	t.equal(r[5].toString(), 'ttt');
	t.end();
});

test('bufferSplit multi char', function(t) {
	var b = new Buffer('abc 123 xyz ttt  ');
	var r = utils.bufferSplit(b, '123');
	t.equal(r.length, 2);
	t.equal(r[0].toString(), 'abc ');
	t.equal(r[1].toString(), ' xyz ttt  ');
	t.end();
});
