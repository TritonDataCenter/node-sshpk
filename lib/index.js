// Copyright 2015 Joyent, Inc.

var Key = require('./key');
var Fingerprint = require('./fingerprint');
var errs = require('./errors');

module.exports = {
	/* top-level classes */
	Key: Key,
	Fingerprint: Fingerprint,

	/* errors */
	FingerprintFormatError: errs.FingerprintFormatError,
	InvalidAlgorithmError: errs.InvalidAlgorithmError,
	KeyParseError: errs.KeyParseError
};
