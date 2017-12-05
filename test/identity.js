// Copyright 2016 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var sinon = require('sinon');

test('parsedn', function (t) {
	var id = sshpk.Identity.parseDN('cn=Blah Corp, s=CA, c=US');
	t.strictEqual(id.type, 'user');
	t.strictEqual(id.cn, 'Blah Corp');
	t.end();
});

test('parsedn escapes', function (t) {
	var id = sshpk.Identity.parseDN('cn=what\\,something,o=b==a,c=\\US');
	t.strictEqual(id.get('cn'), 'what,something');
	t.strictEqual(id.get('o'), 'b==a');
	t.strictEqual(id.get('c'), '\\US');
	id = sshpk.Identity.parseDN('cn\\=foo=bar');
	t.strictEqual(id.get('cn=foo'), 'bar');
	t.throws(function () {
		sshpk.Identity.parseDN('cn\\\\=foo');
	});
	t.end();
});

test('fromarray', function (t) {
	var arr = [
		{ name: 'ou', value: 'foo' },
		{ name: 'ou', value: 'bar' },
		{ name: 'cn', value: 'foobar,g=' }
	];
	var id = sshpk.identityFromArray(arr);
	t.throws(function () {
		id.get('ou');
	});
	t.deepEqual(id.get('ou', true), ['foo', 'bar']);
	t.strictEqual(id.get('cn'), 'foobar,g=');
	t.strictEqual(id.toString(), 'OU=foo, OU=bar, CN=foobar\\,g=');
	t.end();
});
