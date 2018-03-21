// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;
var SSHBuffer = require('../lib/ssh-buffer');
var Buffer = require('safer-buffer').Buffer;

test('expands on write', function(t) {
	var buf = new SSHBuffer({buffer: Buffer.alloc(8)});
	buf.writeCString('abc123');
	buf.writeInt(42);
	buf.writeString('hi there what is up');

	var out = buf.toBuffer();
	t.ok(out.length > 8);

	var buf2 = new SSHBuffer({buffer: out});
	t.strictEqual(buf2.readChar(), 97);
	t.strictEqual(buf2.readCString(), 'bc123');
	t.strictEqual(buf2.readInt(), 42);
	t.strictEqual(buf2.readString(), 'hi there what is up');
	t.end();
});
