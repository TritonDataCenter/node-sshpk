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
var Certificate = require('../certificate');
var pkcs8 = require('./pkcs8');

/* Helper to read in a single mpint */
function readMPInt(der, nm) {
	assert.strictEqual(der.peek(), asn1.Ber.Integer,
	    nm + ' is not an Integer');
	return (utils.mpNormalize(der.readString(asn1.Ber.Integer, true)));
}

function Local(i) {
	return (asn1.Ber.Context | asn1.Ber.Constructor | i);
}

function Context(i) {
	return (asn1.Ber.Context | i);
}

function readSeq(der, ofs) {
	if (ofs) {
		der._offset = ofs;
	}
	der.readSequence();
	var lst = der._buf.slice(der._offset, der._offset + der._len);
	if (lst && lst.length > 0) {
		// console.log("readSeq", der, lst.length)
		return new asn1.BerReader(lst);
	} 
	return null;
}

function skipCont(der, ofs) {
	var skip = 0;
	var saveOfs = der._offset;
	der._offset = ofs;
	if (der.readByte(false) === 0xa0) {
		skip = 2;
	}
	der._offset = saveOfs;
	return skip + ofs;
}

function headerSize(size)  {
	return (size >= 0x80) ? 4 : 2 
}

function sizeWithHeader(size) {
	return headerSize(size) + size
}

function read(buf, options) {
	if (typeof (buf) === 'string') {
		buf = new Buffer(buf, 'binary');
	}
	assert.buffer(buf, 'buf');

	var der = new asn1.BerReader(buf);
	var outter = readSeq(der)
	console.log("outter", outter)

	var common = readSeq(outter)
	console.log("common", common, common._size)
	var version = common.readInt();
	console.log("version", version)



	var tmp = common._offset;
	var id = Identity.parseAsn1(common);
	var entries = readSeq(common, tmp) //, common._offset)
	console.log("XXXXXX", id)

  // console.log("entries", entries)

	// // entries.readSequence()
  // // console.log("entries-1", entries)
	// // entries.readSequence()
  // // console.log("entries-2", entries)
	// // var oid = entries.readOID()
  // // console.log("entries-3", entries, oid)
	// commons = {}
	// var ofs = entries._offset;
	// for (var i = readSeq(entries, ofs); i; i = readSeq(entries, ofs)) {
	// 	console.log("i===>", i, ofs)
	// 	var o = readSeq(i)
	// 	var id = Identity.parseAsn1(i);
	// 	console.log("o===>", o, id)
	// 	var oid = o.readOID()
	// 	console.log("oid=>", o, oid)
	// 	var commonName = o.readString(asn1.Ber.PrintableString, true).toString();
	// 	console.log("cn=>", o, commonName);
	// 	commons[oid] = commonName;
	// 	ofs += sizeWithHeader(i._size);
	// 	// break
	// }
	// console.log(commons)
	// console.log(common)
	// console.log(entries)

	encr = readSeq(common, 2 + 1 + sizeWithHeader(entries._size))
	console.log(encr)
	type = readSeq(encr)
	var encrType = type.readOID()
	encr._offset = type._size + 2 /* size of seq */
	console.log(encrType) //, encr, type)
	pubKey = encr.readString(asn1.Ber.BitString, true)
	console.log(pubKey.length, pubKey)

	var cont = readSeq(common, 2 + 1 + sizeWithHeader(encr._size) 
																	 + sizeWithHeader(entries._size))
	console.log(">>>", cont)
	var trailer = readSeq(common)
	console.log("===", trailer)

	// tailer.readSequence(0x30, true)
	var oid = trailer.readOID()
	console.log("tailer:oid:", oid, trailer)

	var extensions = Identity.parseExtention(trailer);
	console.log("ZZZZZZ", extensions)
  
	// var pk0 = readSeq(trailer)
	// console.log("pk0:", pk0)
	// var pk1 = readSeq(trailer)
	// console.log("pk1:", pk1)

	// extentions = {}
	// var ofs = 0;
	// for (var i = readSeq(pk1, ofs); i; i = readSeq(pk1, ofs)) {
	// 	console.log("pk2:", i)
	// 	var oid = i.readOID()
	// 	var commonName = i.readString(asn1.Ber.OctetString, true).toString()
	// 	// console.log("cn=>", o, commonName)
	// 	extentions[oid] = commonName
	// 	ofs += sizeWithHeader(i._size)
	// 	console.log("ofs:", ofs)
	// 	// break
	// }
	// console.log(extentions)
	// console.log(sizeWithHeader(encr._size))
	// console.log(sizeWithHeader(entries._size))
	// console.log(sizeWithHeader(cont._size))
	// console.log(sizeWithHeader(pk0._size))
	var ofs = sizeWithHeader(common._size);
	console.log(ofs, outter, outter._buf.length)
	var pkType = readSeq(outter, ofs)
	console.log(pkType)
	var pkOid = pkType.readOID()
	console.log(pkType, pkOid)
	outter._offset = ofs + sizeWithHeader(pkType._size)
	console.log(outter)
	var bitString = outter.readString(asn1.Ber.BitString, true)
	console.log(bitString.length, bitString)

  return (new CertificateRequest(obj))

	// var tbsStart = der.offset;
	// var s0 = der.readSequence();
  // console.log("--2", der.offset, s0, )
	// var sigOffset = der.offset + der.length;
	// var tbsEnd = sigOffset;

	// var version = der.readInt();
	// assert.ok(version == 0, 'only csr versions 0 supported');
	// console.log("--5", der.offset)
	// var s1 = der.readSequence();
  // console.log("-1", der.offset, s1, der)

	// var s2 = der.readSequence();
  // console.log("-2", der.offset, s2, der)
	// var s3 = der.readSequence();
  // console.log("-3", der.offset, s3, der)
	// var oid = der.readOID()
  // console.log("-4", der.offset, oid)
	// var commonName = der.readString(asn1.Ber.PrintableString, true).toString()
  // console.log("-5", der.offset, commonName)


	// der.readSequence();
  // console.log("-12", der.offset)
	// der.readSequence();
  // console.log("-13", der.offset)
	// var oid = der.readOID()
  // console.log("-14", der.offset, oid)
	// var serialNumber = der.readString(asn1.Ber.PrintableString, true).toString()
  // console.log("-15", der.offset, serialNumber)



	// var cert = {};
	// cert.signatures = {};
	// var sig = (cert.signatures.x509 = {});
	// sig.extras = {};

	// cert.serial = readMPInt(der, 'serial');

	// der.readSequence();
	// var after = der.offset + der.length;
	// var certAlgOid = der.readOID();
	// var certAlg = SIGN_ALGS[certAlgOid];
	// if (certAlg === undefined)
	// 	throw (new Error('unknown signature algorithm ' + certAlgOid));

	// der._offset = after;
	// cert.issuer = Identity.parseAsn1(der);

	// der.readSequence();
	// cert.validFrom = readDate(der);
	// cert.validUntil = readDate(der);

	// cert.subjects = [Identity.parseAsn1(der)];

	// der.readSequence();
	// after = der.offset + der.length;
	// cert.subjectKey = pkcs8.readPkcs8(undefined, 'public', der);
	// der._offset = after;

	// /* issuerUniqueID */
	// if (der.peek() === Local(1)) {
	// 	der.readSequence(Local(1));
	// 	sig.extras.issuerUniqueID =
	// 	    buf.slice(der.offset, der.offset + der.length);
	// 	der._offset += der.length;
	// }

	// /* subjectUniqueID */
	// if (der.peek() === Local(2)) {
	// 	der.readSequence(Local(2));
	// 	sig.extras.subjectUniqueID =
	// 	    buf.slice(der.offset, der.offset + der.length);
	// 	der._offset += der.length;
	// }

	// /* extensions */
	// if (der.peek() === Local(3)) {
	// 	der.readSequence(Local(3));
	// 	var extEnd = der.offset + der.length;
	// 	der.readSequence();

	// 	while (der.offset < extEnd)
	// 		readExtension(cert, buf, der);

	// 	assert.strictEqual(der.offset, extEnd);
	// }

	// assert.strictEqual(der.offset, sigOffset);

	// der.readSequence();
	// after = der.offset + der.length;
	// var sigAlgOid = der.readOID();
	// var sigAlg = SIGN_ALGS[sigAlgOid];
	// if (sigAlg === undefined)
	// 	throw (new Error('unknown signature algorithm ' + sigAlgOid));
	// der._offset = after;

	// var sigData = der.readString(asn1.Ber.BitString, true);
	// if (sigData[0] === 0)
	// 	sigData = sigData.slice(1);
	// var algParts = sigAlg.split('-');

	// sig.signature = Signature.parse(sigData, algParts[0], 'asn1');
	// sig.signature.hashAlgorithm = algParts[1];
	// sig.algo = sigAlg;
	// sig.cache = buf.slice(tbsStart, tbsEnd);

	// return (new Certificate(cert));
}

function readDate(der) {
	if (der.peek() === asn1.Ber.UTCTime) {
		return (utcTimeToDate(der.readString(asn1.Ber.UTCTime)));
	} else if (der.peek() === asn1.Ber.GeneralizedTime) {
		return (gTimeToDate(der.readString(asn1.Ber.GeneralizedTime)));
	} else {
		throw (new Error('Unsupported date format'));
	}
}

/* RFC5280, section 4.2.1.6 (GeneralName type) */
var ALTNAME = {
	OtherName: Local(0),
	RFC822Name: Context(1),
	DNSName: Context(2),
	X400Address: Local(3),
	DirectoryName: Local(4),
	EDIPartyName: Local(5),
	URI: Context(6),
	IPAddress: Context(7),
	OID: Context(8)
};

function readExtension(cert, buf, der) {
	der.readSequence();
	var after = der.offset + der.length;
	var extId = der.readOID();
	var id;
	var sig = cert.signatures.x509;
	sig.extras.exts = [];

	var critical;
	if (der.peek() === asn1.Ber.Boolean)
		critical = der.readBoolean();

	switch (extId) {
	case (EXTS.altName):
		der.readSequence(asn1.Ber.OctetString);
		der.readSequence();
		var aeEnd = der.offset + der.length;
		while (der.offset < aeEnd) {
			switch (der.peek()) {
			case ALTNAME.OtherName:
			case ALTNAME.EDIPartyName:
				der.readSequence();
				der._offset += der.length;
				break;
			case ALTNAME.OID:
				der.readOID(ALTNAME.OID);
				break;
			case ALTNAME.RFC822Name:
				/* RFC822 specifies email addresses */
				var email = der.readString(ALTNAME.RFC822Name);
				id = Identity.forEmail(email);
				if (!cert.subjects[0].equals(id))
					cert.subjects.push(id);
				break;
			case ALTNAME.DirectoryName:
				der.readSequence(ALTNAME.DirectoryName);
				id = Identity.parseAsn1(der);
				if (!cert.subjects[0].equals(id))
					cert.subjects.push(id);
				break;
			case ALTNAME.DNSName:
				var host = der.readString(
				    ALTNAME.DNSName);
				id = Identity.forHost(host);
				if (!cert.subjects[0].equals(id))
					cert.subjects.push(id);
				break;
			default:
				der.readString(der.peek());
				break;
			}
		}
		sig.extras.exts.push({ oid: extId, critical: critical });
		break;
	default:
		sig.extras.exts.push({
			oid: extId,
			critical: critical,
			data: der.readString(asn1.Ber.OctetString, true)
		});
		break;
	}

	der._offset = after;
}


function write(csr, options) {
	var sig = cert.signatures.x509;
	assert.object(sig, 'x509 signature');

	var der = new asn1.BerWriter();
	// outter
	der.startSequence();
	if (sig.cache) {
		der._ensure(sig.cache.length);
		sig.cache.copy(der._buf, der._offset);
		der._offset += sig.cache.length;
	} else {
		writeTBSCert(cert, der);
	}
  // common
	der.startSequence();
	der.writeString()
	der.startSequence();

	for (var k in csr.commons) {
		var v = csr.commons[k];
		der.startSequence();
		der.writeOID(k);
		der.writeString(v);
		der.endSequence();
	}
	der.endSequence()
	der.startSequence();
	der.startSequence();
	der.writeOID(SIGN_ALGS[sig.algo]);
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
	var sig = cert.signatures.x509;
	assert.object(sig, 'x509 signature');

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
