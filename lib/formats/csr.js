// Copyright 2016 Joyent, Inc.

module.exports = {
	read: read,
	write: write
};

var assert = require('assert-plus');
var asn1 = require('asn1');
var algs = require('../algs');
var utils = require('../utils');
var Key = require('../key');
var PrivateKey = require('../private-key');
var pem = require('./pem');
var Identity = require('../identity');
var Signature = require('../signature');
var x509 = require('./x509');
var CertificateSigningRequest = require('../certificate-signing-request');
var pkcs8 = require('./pkcs8');

/* Helper to read in a single mpint */

function readSeq(der, ofs) {
	if (ofs) {
		der._offset = ofs;
	}
	der.readSequence();
	var lst = der._buf.slice(der._offset, der._offset + der._len);
	if (lst && lst.length > 0) {
		return new asn1.BerReader(lst);
	} 
	return null;
}

function headerSize(size)  {
	if (size >= 0x100) {
		return 4;
	}
	if (size >= 0x80) {
		return 3;
	}
	return 2;
}

function sizeWithHeader(size) {
	return headerSize(size) + size
}

function read(buf, options) {
	if (typeof (buf) === 'string') {
		buf = new Buffer(buf, 'binary');
	}
	assert.buffer(buf, 'buf');

	var obj = {}
	var der = new asn1.BerReader(buf);
	var outter = readSeq(der)
	var common = readSeq(outter)
	obj.version = common.readInt();

	var tmp = common._offset;
	obj.subjects = [ Identity.parseAsn1(common) ]
	var entries = readSeq(common, tmp) //, common._offset)

	encr = readSeq(common, 2 + 1 + sizeWithHeader(entries._size))
	// type = readSeq(encr)
	// obj.encrType = type.readOID()
	// encr._offset = type._size + 2 /* size of seq */
	obj.subjectKey = pkcs8.readPkcs8(undefined, 'public', encr);
	//encr.readString(asn1.Ber.BitString, true)
	var extOfs = 2 + 1 + sizeWithHeader(encr._size)
										 + sizeWithHeader(entries._size)
	var cont = readSeq(common, extOfs)
  // console.log(">>>>>>>>>", extOfs, cont, outter)
	if (cont) {
		var trailer = readSeq(common)
		// tailer.readSequence(0x30, true)
		// console.log(cont, trailer)
		let extentionOid = trailer.readOID();
		assert.strictEqual(extentionOid, '1.2.840.113549.1.9.14',
		    'Only Extention Request is supported')
		// console.log(obj)
		obj.extentions = [ Identity.parseExtention(trailer) ];
	}
	var ofs = sizeWithHeader(common._size);
	// obj.sigOid = pkType.readOID()
	// obj.signature = outter.readString(asn1.Ber.BitString, true)

	var sigSeq = readSeq(outter, ofs)
	var sigAlgOid = sigSeq.readOID();
	// console.log(x509)
	var sigAlg = x509.SIGN_ALGS[sigAlgOid];
	if (sigAlg === undefined)
		throw (new Error('unknown signature algorithm ' + sigAlgOid+":"+x509.SIGN_ALGS));

	outter._offset = ofs + sizeWithHeader(sigSeq._size)
	var sigData = outter.readString(asn1.Ber.BitString, true);
	if (sigData[0] === 0)
		sigData = sigData.slice(1);
	var algParts = sigAlg.split('-');

	obj.signatures = {};
	var sig = (obj.signatures.x509 = {});
	sig.signature = Signature.parse(sigData, algParts[0], 'asn1');
	sig.signature.hashAlgorithm = algParts[1];
	sig.algo = sigAlg;
	sig.cache = buf.slice(0, ofs);

	return (new CertificateSigningRequest(obj))
}

function write(csr, options) {
	var sig = csr.signatures.x509;
	assert.object(sig, 'x509 signature');

	var der = new asn1.BerWriter();
	der.startSequence();
	der.startSequence();
	der.writeInt(csr.version);

	var subject = csr.subjects[0];
	subject.toAsn1(der);

	pkcs8.writePkcs8(der, csr.subjectKey);

	if (csr.extentions) {
		der.startSequence();
		der.startSequence();
		der.writeOID('1.2.840.113549.1.9.14');
		der.startSequence();
		var extentions = csr.extentions[0];
		extentions.toExtentionAsn1(der);
		der.endSequence();
		der.endSequence();
		der.endSequence();
	}
	der.endSequence();

	der.startSequence();
	der.writeOID(x509.SIGN_ALGS[sig.algo]);
	if (sig.algo.match(/^rsa-/))
		der.writeNull();
	der.endSequence();

	var sigData = sig.signature.toBuffer('asn1');
	var data = new Buffer(sigData.length + 1);
	data[0] = 0;
	sigData.copy(data, 1);
	der.writeBuffer(data, asn1.Ber.BitString);
	der.endSequence();
	return (der.buffer);
}

function writeTBSCert(cert, der) {
	// var sig = cert.signatures.x509;
	// assert.object(sig, 'x509 signature');

	der.startSequence();

	der.startSequence(Local(0));
	der.writeInt(2);
	der.endSequence();

	der.writeBuffer(utils.mpNormalize(cert.serial), asn1.Ber.Integer);

	der.startSequence();
	der.writeOID(SIGN_ALGS[sig.algo]);
	der.endSequence();

	cert.issuer.toAsn1(der);

	der.startSequence();
	der.writeString(dateToUTCTime(cert.validFrom), asn1.Ber.UTCTime);
	der.writeString(dateToUTCTime(cert.validUntil), asn1.Ber.UTCTime);
	der.endSequence();

	var subject = cert.subjects[0];
	var altNames = cert.subjects.slice(1);
	subject.toAsn1(der);

	pkcs8.writePkcs8(der, cert.subjectKey);

	if (sig.extras && sig.extras.issuerUniqueID) {
		der.writeBuffer(sig.extras.issuerUniqueID, Local(1));
	}

	if (sig.extras && sig.extras.subjectUniqueID) {
		der.writeBuffer(sig.extras.subjectUniqueID, Local(2));
	}

	if (altNames.length > 0 || subject.type === 'host' ||
	    (sig.extras && sig.extras.exts)) {
		der.startSequence(Local(3));
		der.startSequence();

		var exts = [
			{ oid: EXTS.altName }
		];
		if (sig.extras && sig.extras.exts)
			exts = sig.extras.exts;

		for (var i = 0; i < exts.length; ++i) {
			der.startSequence();
			der.writeOID(exts[i].oid);

			if (exts[i].critical !== undefined)
				der.writeBoolean(exts[i].critical);

			if (exts[i].oid === EXTS.altName) {
				der.startSequence(asn1.Ber.OctetString);
				der.startSequence();
				if (subject.type === 'host') {
					der.writeString(subject.hostname,
					    Context(2));
				}
				for (var j = 0; j < altNames.length; ++j) {
					if (altNames[j].type === 'host') {
						der.writeString(
						    altNames[j].hostname,
						    ALTNAME.DNSName);
					} else if (altNames[j].type ===
					    'email') {
						der.writeString(
						    altNames[j].email,
						    ALTNAME.RFC822Name);
					} else {
						/*
						 * Encode anything else as a
						 * DN style name for now.
						 */
						der.startSequence(
						    ALTNAME.DirectoryName);
						altNames[j].toAsn1(der);
						der.endSequence();
					}
				}
				der.endSequence();
				der.endSequence();
			} else {
				der.writeBuffer(exts[i].data,
				    asn1.Ber.OctetString);
			}

			der.endSequence();
		}

		der.endSequence();
		der.endSequence();
	}

	der.endSequence();
}
