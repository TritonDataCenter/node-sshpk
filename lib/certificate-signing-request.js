// Copyright 2016 Joyent, Inc.

module.exports = CertificateSigningRequest;

var assert = require('assert-plus');
var algs = require('./algs');
var crypto = require('crypto');
var Fingerprint = require('./fingerprint');
var Signature = require('./signature');
var errs = require('./errors');
var util = require('util');
var utils = require('./utils');
var Key = require('./key');
var PrivateKey = require('./private-key');
var Identity = require('./identity');

var formats = {};
formats['der'] = require('./formats/csr');
formats['pem'] = require('./formats/csr-pem');

var CertificateParseError = errs.CertificateParseError;
var InvalidAlgorithmError = errs.InvalidAlgorithmError;

function CertificateSigningRequest(opts) {
	// console.log(opts)
	assert.object(opts, 'options');
	assert.arrayOfObject(opts.subjects, 'options.subjects');
	utils.assertCompatible(opts.subjects[0], Identity, [1, 0],
	    'options.subjects');
	utils.assertCompatible(opts.subjectKey, Key, [1, 0],
	    'options.subjectKey');

	assert.object(opts.signatures, 'options.signatures');

	if (opts.extentions) {
		utils.assertCompatible(opts.extentions[0], Identity, [1, 0],
	    'options.extentions');
	}

	this._hashCache = {};

	this.type = "certificate-signing-request"

	this.version = opts.version || 0;

	this.subjects = opts.subjects;
	this.subjectKey = opts.subjectKey;
	this.signatures = opts.signatures;
	this.extentions = opts.extentions;
}

CertificateSigningRequest.formats = formats;

CertificateSigningRequest.prototype.toBuffer = function (format, options) {
	if (format === undefined)
		format = 'pem';
	assert.string(format, 'format');
	assert.object(formats[format], 'formats[format]');
	assert.optionalObject(options, 'options');

	return (formats[format].write(this, options));
};

CertificateSigningRequest.prototype.toString = function (format, options) {
	if (format === undefined)
		format = 'pem';
	return (this.toBuffer(format, options).toString());
};

CertificateSigningRequest.prototype.fingerprint = function (algo) {
	if (algo === undefined)
		algo = 'sha256';
	assert.string(algo, 'algorithm');
	var opts = {
		type: 'certificate-signing-request',
		hash: this.hash(algo),
		algorithm: algo
	};
	return (new Fingerprint(opts));
};

CertificateSigningRequest.prototype.hash = function (algo) {
	assert.string(algo, 'algorithm');
	algo = algo.toLowerCase();
	if (algs.hashAlgs[algo] === undefined)
		throw (new InvalidAlgorithmError(algo));

	if (this._hashCache[algo])
		return (this._hashCache[algo]);

	var hash = crypto.createHash(algo).
	    update(this.toBuffer('der')).digest();
	this._hashCache[algo] = hash;
	return (hash);
};

CertificateSigningRequest.create = function (subjectOrSubjects, key, options) {
	var subjects;
	if (Array.isArray(subjectOrSubjects))
		subjects = subjectOrSubjects;
	else
		subjects = [subjectOrSubjects];

	assert.arrayOfObject(subjects);
	subjects.forEach(function (subject) {
		utils.assertCompatible(subject, Identity, [1, 0], 'subject');
	});

	utils.assertCompatible(key, Key, [1, 0], 'key');
	if (PrivateKey.isPrivateKey(key))
		key = key.toPublic();
	utils.assertCompatible(issuer, Identity, [1, 0], 'issuer');
	utils.assertCompatible(issuerKey, PrivateKey, [1, 2], 'issuer key');

	assert.optionalObject(options, 'options');
	if (options === undefined)
		options = {};
	assert.optionalObject(options.validFrom, 'options.validFrom');
	assert.optionalObject(options.validUntil, 'options.validUntil');
	var validFrom = options.validFrom;
	var validUntil = options.validUntil;
	if (validFrom === undefined)
		validFrom = new Date();
	if (validUntil === undefined) {
		assert.optionalNumber(options.lifetime, 'options.lifetime');
		var lifetime = options.lifetime;
		if (lifetime === undefined)
			lifetime = 10*365*24*3600;
		validUntil = new Date();
		validUntil.setTime(validUntil.getTime() + lifetime*1000);
	}
	assert.optionalBuffer(options.serial, 'options.serial');
	var serial = options.serial;
	if (serial === undefined)
		serial = new Buffer('0000000000000001', 'hex');

	var cert = new Certificate({
		subjects: subjects,
		issuer: issuer,
		subjectKey: key,
		issuerKey: issuerKey.toPublic(),
		signatures: {},
		serial: serial,
		validFrom: validFrom,
		validUntil: validUntil
	});
	cert.signWith(issuerKey);

	return (cert);
};

CertificateSigningRequest.parse = function (data, format, options) {
	if (typeof (data) !== 'string')
		assert.buffer(data, 'data');
	if (format === undefined)
		format = 'auto';
	assert.string(format, 'format');
	if (typeof (options) === 'string')
		options = { filename: options };
	assert.optionalObject(options, 'options');
	if (options === undefined)
		options = {};
	assert.optionalString(options.filename, 'options.filename');
	if (options.filename === undefined)
		options.filename = '(unnamed)';

	assert.object(formats[format], 'formats[format]');

	try {
		var k = formats[format].read(data, options);
		return (k);
	} catch (e) {
		console.log(e)
		throw (new CertificateParseError(options.filename, format, e));
	}
};

/*
 * API versions for CertificateSigningRequest:
 * [1,0] -- initial ver
 */
CertificateSigningRequest.prototype._sshpkApiVersion = [1, 0];

CertificateSigningRequest._oldVersionDetect = function (obj) {
	return ([1, 0]);
};
