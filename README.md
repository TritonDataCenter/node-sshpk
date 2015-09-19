sshpk
=========

Parse, convert, fingerprint and use SSH public keys in pure node -- no
`ssh-keygen` or other external dependencies.

Supports RSA, DSA and ECDSA (nistp-*) key types. Can also parse SSH private
keys in PEM format and output their public half.

This library has been extracted from
[`node-http-signature`](https://github.com/joyent/node-http-signature)
(work by [Mark Cavage](https://github.com/mcavage) and
[Dave Eddy](https://github.com/bahamas10)) and
[`node-ssh-fingerprint`](https://github.com/bahamas10/node-ssh-fingerprint)
(work by Dave Eddy), with some additions (including ECDSA support) by
[Alex Wilson](https://github.com/arekinath).

Install
-------

```
npm install sshpk
```

Examples
--------

```js
var sshpk = require('sshpk');

var fs = require('fs');

/* Read in an OpenSSH-format public key */
var keyPub = fs.readFileSync('id_rsa.pub');
var key = sshpk.parseKey(keyPub, 'ssh');

/* Get metadata about the key */
console.log('type => %s', key.type);
console.log('size => %d bits', key.size);
console.log('comment => %s', key.comment);

/* Compute key fingerprints, in new OpenSSH (>6.7) format, and old MD5 */
console.log('fingerprint => %s', key.fingerprint().toString());
console.log('old-style fingerprint => %s', key.fingerprint('md5').toString());
```

Example output:

```
type => rsa
size => 2048 bits
comment => foo@foo.com
fingerprint => SHA256:PYC9kPVC6J873CSIbfp0LwYeczP/W4ffObNCuDJ1u5w
old-style fingerprint => a0:c8:ad:6c:32:9a:32:fa:59:cc:a9:8c:0a:0d:6e:bd
```

More examples: converting between formats:

```js
/* Read in a PEM public key (PKCS#8) */
var keyPem = fs.readFileSync('id_rsa.pem');
var key = sshpk.parseKey(keyPem, 'pem');


/* Read in an OpenSSH/PEM *private* key, will load just the public half */
var keyPriv = fs.readFileSync('id_ecdsa');
var key = sshpk.parseKey(keyPriv, 'pem');


/* Convert to PEM PKCS#8 public key format */
var pemBuf = key.toBuffer('pem');

/* Convert to SSH public key format (and return as a string) */
var sshKey = key.toString('ssh');


/* Make a crypto.Verifier with this key */
var v = key.createVerify('sha1');
v.update('some data here');
var valid = v.verify(signature);
```

Matching fingerprints with keys:

```js
var fp = sshpk.parseFingerprint('SHA256:PYC9kPVC6J873CSIbfp0LwYeczP/W4ffObNCuDJ1u5w');

var keys = [sshpk.parseKey(...), sshpk.parseKey(...), ...];

keys.forEach(function (key) {
	if (fp.matches(key))
		console.log('found it!')''
});
```

Usage
-----

### `parseKey(data[, format = 'ssh'[, name]])`

Parses a key from a given data format and returns a new `Key` object.

Parameters

- `data` -- Either a Buffer or String, containing the key
- `format` -- String name of format to use, valid options are `pem` (supports
              both PKCS#1 and PKCS#8), `rfc4253` (raw OpenSSH wire format, as
              returned by `ssh-agent`, for example), `ssh` (OpenSSH format)
- `name` -- Optional name for the key being parsed (eg. the filename that
            was opened). Used to generate Error messages

### `Key#type`

String, the type of key. Valid options are `rsa`, `dsa`, `ecdsa`.

### `Key#size`

Integer, "size" of the key in bits. For RSA/DSA this is the size of the modulus;
for ECDSA this is the bit size of the curve in use.

### `Key#comment`

Optional string, a key comment used by some formats (eg the `ssh` format).

### `Key#curve`

Only present if `this.type === 'ecdsa'`, string containing the name of the
named curve used with this key. Possible values include `nistp256`, `nistp384`
and `nistp521`.

### `Key#toBuffer([format = 'ssh'])`

Convert the key into a given data format and return the serialized key as
a Buffer.

Parameters

- `format` -- String name of format to use, valid options are `pem`, `rfc4253`,
              `ssh`

### `Key#toString([format = 'ssh])`

Same as `this.toBuffer(format).toString()`.

### `Key#fingerprint([algorithm = 'sha256'])`

Creates a new `Fingerprint` object representing this Key's fingerprint.

Parameters

- `algorithm` -- String name of hash algorithm to use, valid options are `md5`,
                 `sha1`, `sha256`, `sha384`, `sha512`

### `Key#createVerify(hashAlgorithm)`

Creates a `crypto.Verifier` specialized to use this Key (and the correct public
key algorithm to match it). The returned Verifier has the same API as a regular
one, except that the `verify()` function takes only the target signature as an
argument.

Parameters

- `hashAlgorithm` -- String name of hash algorithm to use, any supported by
                     OpenSSL are valid, usually including `sha1`, `sha256`

### `parseFingerprint(fingerprint[, algorithms])`

Pre-parses a fingerprint, creating a `Fingerprint` object that can be used to
quickly locate a key by using the `Fingerprint#matches` function.

Parameters

- `fingerprint` -- String, the fingerprint value, in any supported format
- `algorithms` -- Optional list of strings, names of hash algorithms to limit
                  support to. If `fingerprint` uses a hash algorithm not on
                  this list, throws `InvalidAlgorithmError`.

### `Fingerprint#toString([format])`

Returns a fingerprint as a string, in the given format.

Parameters

- `format` -- Optional String, format to use, valid options are `hex` and
              `base64`. If this `Fingerprint` uses the `md5` algorithm, the
              default format is `hex`. Otherwise, the default is `base64`.

### `Fingerprint#matches(key)`

Verifies whether or not this `Fingerprint` matches a given `Key`. This function
uses double-hashing to avoid leaking timing information. Returns a boolean.

Parameters

- `key` -- a `Key` object, the key to match this fingerprint against

Errors
------

### `InvalidAlgorithmError`

The specified algorithm is not valid, either because it is not supported, or
because it was not included on a list of allowed algorithms.

Thrown by `Fingerprint.parse`, `Key#fingerprint`.

Properties

- `algorithm` -- the algorithm that could not be validated

### `FingerprintFormatError`

The fingerprint string given could not be parsed as a supported fingerprint
format, or the specified fingerprint format is invalid.

Thrown by `Fingerprint.parse`, `Fingerprint#toString`.

Properties

- `fingerprint` -- if caused by a fingerprint, the string value given
- `format` -- if caused by an invalid format specification, the string value given

### `KeyParseError`

The key data given could not be parsed as a valid key.

Properties

- `keyName` -- `name` that was given to `Key#parse`
- `format` -- the `format` that was trying to parse the key
- `innerErr` -- the inner Error thrown by the format parser
