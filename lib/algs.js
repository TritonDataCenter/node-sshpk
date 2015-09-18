// Copyright 2015 Joyent, Inc.

var algInfo = {
	'dsa': {
		parts: ['p', 'q', 'g', 'y'],
		sizePart: 'p'
	},
	'rsa': {
		parts: ['e', 'n'],
		sizePart: 'n'
	},
	'ecdsa': {
		parts: ['curve', 'Q'],
		sizePart: 'Q'
	}
};

var hashAlgs = {
	'md5': true,
	'sha1': true,
	'sha256': true,
	'sha384': true,
	'sha512': true
}

module.exports = {
	info: algInfo,
	hashAlgs: hashAlgs
};
