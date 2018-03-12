// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');

var KEY_LOST_WEQ = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAvad19ePSDckmgmo6Unqmd8' +
	'n2G7o1794VN3FazVhV09yooXIuUhA+7OmT7ChiHueayxSubgL2MrO/HvvF/GGVUs/t3e0u4' +
	'5YwRC51EVhyDuqthVJWjKrYxgDMbHru8fc1oV51l0bKdmvmJWbA/VyeJvstoX+eiSGT3Jge' +
	'egSMVtc=mark@foo.local';
test('lost whitespace before comment', function (t) {
	var k = sshpk.parseKey(KEY_LOST_WEQ, 'ssh');
	t.strictEqual(k.type, 'rsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:n0akL6ACGYcTARqym7TL4DStmNFpxMkSlFwuCfqNP9M');
	t.strictEqual(k.comment, 'mark@foo.local');
	t.end();
});

var KEY_LOST_EQ = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAvad19ePSDckmgmo6Unqmd8' +
	'n2G7o1794VN3FazVhV09yooXIuUhA+7OmT7ChiHueayxSubgL2MrO/HvvF/GGVUs/t3e0u4' +
	'5YwRC51EVhyDuqthVJWjKrYxgDMbHru8fc1oV51l0bKdmvmJWbA/VyeJvstoX+eiSGT3Jge' +
	'egSMVtcmark@foo.local';
test('lost whitespace and equals before comment', function (t) {
	var k = sshpk.parseKey(KEY_LOST_EQ, 'ssh');
	t.strictEqual(k.type, 'rsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:n0akL6ACGYcTARqym7TL4DStmNFpxMkSlFwuCfqNP9M');
	t.strictEqual(k.comment, 'mark@foo.local');
	t.end();
});

var KEY_LOST = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSNsN/sEEwzcDfKwi1aJwAb' +
    'f8lTkOSvC6JujRlWzmI7HjWmBephEGyFOY3FAYLRHNLNDDL/NSGcWTp08zLGbCeOey3hCGwm' +
    'msr5zH9sQIslD1ruGlXNWdV2hIF1VHfGPGlX5Sx1vz6ARKyp1jvMVWyhJNsH4lCEkl+5R8Y7' +
    'op+YwhjOyMqOmxhzQ8I6npXgo8JRsSZs0ikfUpORoMg+G2G62uDgYsRFYNZhHo5zv/1dV4rz' +
    'x9Tn6sgjgZ99sEymPLL1o8i53MjH31CMW8//SR4xgIVSABI831wsJIz0dj3khcSIrLbT3qOT' +
    'QtMcXDKBpk9+5AfNtHlCN5Ba68bU+W7alex@Alexs-MacBook-Pro-7.local';
test('lost whitespace, no equals', function (t) {
	var k = sshpk.parseKey(KEY_LOST, 'ssh');
	t.strictEqual(k.type, 'rsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:+lMZah1Mq1FnDRtPpiz6kxpx7nrqQe5okKakQOvLEZE');
	t.strictEqual(k.comment, 'alex@Alexs-MacBook-Pro-7.local');
	t.end();
});

var KEY_NEWLINE = 'ssh-ed25519  AAAAC3NzaC1lZDI1NTE5AAAAIEi0pkfPe/+kbmnTSH0mfr0J4' +
    'Fq7M7bshFAKB6uCyLDm\nfoo@bar';
test('newline before comment instead of space', function (t) {
	var k = sshpk.parseKey(KEY_NEWLINE, 'ssh');
	t.strictEqual(k.type, 'ed25519');
	t.strictEqual(k.comment, 'foo@bar');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:2UeFLCUKw2lvd8O1zfINNVzE0kUcu2HJHXQr/TGHt60');
	t.end();
});

var KEY_LINES = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSNsN/sEEwzcDfKwi1aJwAb\n' +
    'f8lTkOSvC6JujRlWzmI7HjWmBephEGyFOY3FAYLRHNLNDDL/NSGcWTp08zLGbCeOey3hCGwm\r\n' +
    'msr5zH9sQIslD1ruGlXNWdV2hIF1VHfGPGlX5Sx1vz6ARKyp1jvMVWyhJNsH4lCEkl+5R8Y7\n' +
    'op+YwhjOyMqOmxhzQ8I6npXgo8JRsSZs0ikfUpORoMg+G2G62uDgYsRFYNZhHo5zv/1dV4rz\r\n' +
    'x9Tn6sgjgZ99sEymPLL1o8i53MjH31CMW8//SR4xgIVSABI831wsJIz0dj3khcSIrLbT3qOT\n' +
    'QtMcXDKBpk9+5AfNtHlCN5Ba68bU+W7\r\nalex@Alexs-MacBook-Pro-7.local';
test('newlines everywhere', function (t) {
	var k = sshpk.parseKey(KEY_LINES, 'ssh');
	t.strictEqual(k.type, 'rsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:+lMZah1Mq1FnDRtPpiz6kxpx7nrqQe5okKakQOvLEZE');
	t.strictEqual(k.comment, 'alex@Alexs-MacBook-Pro-7.local');
	t.end();
});

var KEY_CONTINU = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSNsN/sEEwzcDfKwi1aJwAb\\\n' +
    'f8lTkOSvC6JujRlWzmI7HjWmBephEGyFOY3FAYLRHNLNDDL/NSGcWTp08zLGbCeOey3hCGwm \\\r\n' +
    'msr5zH9sQIslD1ruGlXNWdV2hIF1VHfGPGlX5Sx1vz6ARKyp1jvMVWyhJNsH4lCEkl+5R8Y7\\\n' +
    'op+YwhjOyMqOmxhzQ8I6npXgo8JRsSZs0ikfUpORoMg+G2G62uDgYsRFYNZhHo5zv/1dV4rz\\\r\n' +
    'x9Tn6sgjgZ99sEymPLL1o8i53MjH31CMW8//SR4xgIVSABI831wsJIz0dj3khcSIrLbT3qOT \\\n' +
    'QtMcXDKBpk9+5AfNtHlCN5Ba68bU+W7 \\\r\nalex@Alexs-MacBook-Pro-7.local';
test('line continuations, key from hell', function (t) {
	var k = sshpk.parseKey(KEY_CONTINU, 'ssh');
	t.strictEqual(k.type, 'rsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:+lMZah1Mq1FnDRtPpiz6kxpx7nrqQe5okKakQOvLEZE');
	t.strictEqual(k.comment, 'alex@Alexs-MacBook-Pro-7.local');
	t.end();
});

var KEY_NO_COMMENT = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAA' +
    'IbmlzdHAyNTYAAABBBK9+hFGVZ9RT61pg8t7EGgkvduhPr/CBYfx+5rQFEROj8EjkoGIH2xy' +
    'pHOHBz0WikK5hYcwTM5YMvnNxuU0h4+c=';
test('normal key, no comment', function (t) {
	var k = sshpk.parseKey(KEY_NO_COMMENT, 'ssh');
	t.strictEqual(k.type, 'ecdsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:Kyu0EMqH8fzfp9RXKJ6kmsk9qKGBqVRtlOuk6bXfCEU');
	t.strictEqual(k.comment, '(unnamed)');
	t.end();
});

var KEY_COMMENT_EQ = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAA' +
    'IbmlzdHAyNTYAAABBBK9+hFGVZ9RT61pg8t7EGgkvduhPr/CBYfx+5rQFEROj8EjkoGIH2xy' +
    'pHOHBz0WikK5hYcwTM5YMvnNxuU0h4+c= abc=def=a\n';
test('comment contains =, trailing newline', function (t) {
	var k = sshpk.parseKey(KEY_COMMENT_EQ, 'ssh');
	t.strictEqual(k.type, 'ecdsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:Kyu0EMqH8fzfp9RXKJ6kmsk9qKGBqVRtlOuk6bXfCEU');
	t.strictEqual(k.comment, 'abc=def=a');
	t.end();
});

var KEY_BREAK = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzd' +
    'HAyNTYAAABBBK9+hFGVZ9RT61pg8t7\nEGgkvduhPr/CBYfx+5rQFEROj8EjkoGIH2xypHOH' +
    'Bz0WikK5hYcwTM5YMvnNxuU0h4+c=';
test('line broken in the middle, no comment', function (t) {
	var k = sshpk.parseKey(KEY_BREAK, 'ssh');
	t.strictEqual(k.type, 'ecdsa');
	t.strictEqual(k.fingerprint('sha256').toString(),
	    'SHA256:Kyu0EMqH8fzfp9RXKJ6kmsk9qKGBqVRtlOuk6bXfCEU');
	t.strictEqual(k.comment, '(unnamed)');
	t.end();
});

var KEY_WOOPS = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoTItbmlzdHAyNTYAAAAIbmlzd' +
    'HAyNTYAAABBBK9+hFGVZ9RT61pg8t7\nEGgkvduhPr/CBYfx+5rQFEROj8EjkoGIH2xypHOH' +
    'Bz0WikK5hYcwTM5YMvnNxuU0h4+c=';
test('missing character in middle', function (t) {
	t.throws(function () {
		sshpk.parseKey(KEY_WOOPS, 'ssh');
	});
	t.end();
});
