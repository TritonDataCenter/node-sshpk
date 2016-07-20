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
