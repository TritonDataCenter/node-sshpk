// Copyright 2011 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');

///--- Globals
var SSH_1024 = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAvad19ePSDckmgmo6Unqmd8' +
	'n2G7o1794VN3FazVhV09yooXIuUhA+7OmT7ChiHueayxSubgL2MrO/HvvF/GGVUs/t3e0u4' +
	'5YwRC51EVhyDuqthVJWjKrYxgDMbHru8fc1oV51l0bKdmvmJWbA/VyeJvstoX+eiSGT3Jge' +
	'egSMVtc= mark@foo.local';
var PEM_1024 = '-----BEGIN PUBLIC KEY-----\n' +
	'MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQC9p3X149INySaCajpSeqZ3yfYb\n' +
	'ujXv3hU3cVrNWFXT3Kihci5SED7s6ZPsKGIe55rLFK5uAvYys78e+8X8YZVSz+3d\n' +
	'7S7jljBELnURWHIO6q2FUlaMqtjGAMxseu7x9zWhXnWXRsp2a+YlZsD9XJ4m+y2h\n' +
	'f56JIZPcmB56BIxW1wIBIw==\n' +
	'-----END PUBLIC KEY-----\n';

var SSH_2048 = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAr+isTwMYqwCAcY0Yb2F0pF' +
	'+/F4/wxGzcrLR2PrgoBXwjj/TnEA3tJ7v08Rru3lAd/O59B6TbXOsYbQ+2Syd82Dm8L3SJR' +
	'NlZJ6DZUOAwnTOoNgkfH2CsbGS84aTPTeXjmMsw52GvQ9yWFDUglHzMIzK2iSHWNl1dAaBE' +
	'iddifGmrpUTPJ5Tt7l8YS4jdaBf6klS+3CvL6xET/RjZhKGtrrgsRRYUB2XVtgQhKDu7PtD' +
	'dlpy4+VISdVhZSlXFnBhya/1KxLS5UFHSAdOjdxzW1bh3cPzNtuPXZaiWUHvyIWpGVCzj5N' +
	'yeDXcc7n0E20yx9ZDkAITuI8X49rnQzuCN5Q== mark@bluesnoop.local';
var PEM_2048 = '-----BEGIN PUBLIC KEY-----\n' +
	'MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAr+isTwMYqwCAcY0Yb2F0\n' +
	'pF+/F4/wxGzcrLR2PrgoBXwjj/TnEA3tJ7v08Rru3lAd/O59B6TbXOsYbQ+2Syd8\n' +
	'2Dm8L3SJRNlZJ6DZUOAwnTOoNgkfH2CsbGS84aTPTeXjmMsw52GvQ9yWFDUglHzM\n' +
	'IzK2iSHWNl1dAaBEiddifGmrpUTPJ5Tt7l8YS4jdaBf6klS+3CvL6xET/RjZhKGt\n' +
	'rrgsRRYUB2XVtgQhKDu7PtDdlpy4+VISdVhZSlXFnBhya/1KxLS5UFHSAdOjdxzW\n' +
	'1bh3cPzNtuPXZaiWUHvyIWpGVCzj5NyeDXcc7n0E20yx9ZDkAITuI8X49rnQzuCN\n' +
	'5QIBIw==\n' +
	'-----END PUBLIC KEY-----\n';
var PEM_PRIVATE_2048 = '-----BEGIN RSA PRIVATE KEY-----\n' +
	'MIIEpAIBAAKCAQEAyGTB7EAD1/MCDFNmQa6WybEJkzWF1jswrIcZ1IN+T363Hv1+\n' +
	'qtFhjiY1JcIeJxOEEEhkSlRiiHnFs6Q25XZ80mXWiKeLEE1IF5nOVcNgxtSMRr61\n' +
	'qt0DD9/c1xWzHkQjnw6Q6SvLVzkkcLpDJnfLc1MsTGBzkSW1zdtfS8pf6rlZpa/l\n' +
	'0Tc0zI72ywN+9Lio2pDeXaJlNMfsiV78b47zDzt1AZhHba5pV8XQMAudhiIJI6jK\n' +
	'jN1HfUxV62wD5PrrU9xtDGUhVLSwhhOuBt9yvxcTyRvdWVwKN8d91shY+XCs4pVD\n' +
	'jG1IzoBviNvWPT5GwWx+rwb1vDFdd/SvDUdOzQIDAQABAoIBAA/LCRGCdgsV5spr\n' +
	'5Do29UFOB5AnfrXEknB2cU2zU0gWl34Ewm/Z8pNOZY/lPZUcz6Ks4eKNxfo1hqRC\n' +
	'w+TPssSuK/s3IRmWzaC2iXFu5XimFawZqZ2er3gXz4LP/f7bpecKMdd+kRb9tOaB\n' +
	'd3tXo5wiKPKYA2OkEjD4IgmKGIcaEq2rxQEg872OSHamd5JPtGmLPBIwiird6d3K\n' +
	'U15nWZVwTL8rPGBYN1I5pBERYCephBwXqzBE1BiK9FZbevEIoSOI057WTAuAy/DB\n' +
	'8/svhLNEF6w2X5CiCRw9Cw9dKRtpaY3kGhOzBiXkwJH9CTaw/8w7uEmQI//NWrvP\n' +
	'9S8YW2ECgYEA9GadWhRLZQYF0R7e3zIr3GyL9FQoVNLpba4Mpf68QO0yrmAZU5gt\n' +
	'ibUWVO/tDGD7tQCaFax+kwF/paGemvsBoiGFeJOSqj/3D5/89sSyd45p44AyjKWU\n' +
	'a8bLhaEm1W9pfYBwYrMxkQxz877s7V1hD3baVf0j8DHGQa0A9PgH+dkCgYEA0ed4\n' +
	'UU5+bfW4SCwr2XbAm2X1K/x17rU7fdSe9M/zdWCjzdgRMJ7nVvbyYP7rmo97SxYI\n' +
	'co/5xhwv+NXH/hPHHkQJLkfbSyCYL3fQMt18VuUZ4uZTWC+pMvjh1Zfn+JT0v7Mm\n' +
	'N9gJ6cXFYp954M8ZzxhviYeWUVPUmsS45OdsUBUCgYEAp0BF9GwpAFRzzJ1Upede\n' +
	'rrS1vhmNlCbVydIvI7XEvKXWZhCrpFJi73c2dh/O2AbSmhZ0W9q0sAN5iC6nLKYT\n' +
	'gxFvlole+BVYDKBO68zF2R1jh2Wmsitp+6uKgcM7oRpiVZl8z36TsBCWlTqWRwX9\n' +
	'MykB15CpdGmLpEwxeHL4elkCgYBK3pU76xONhSfGFntNhd4Nj8BzgAlQq7QcncpU\n' +
	'6Beetmm28mqvPP6nNk4d6s9+wc7oaWN5+YDN+R/jUd2T8toDIaFksJy3n1ipFcNd\n' +
	'YUMIe49QL3dq7RUc6UkkNpq3P+pMtknbgWOHztMo6lk+pqA+Dik6lPI47/3VdnW8\n' +
	'sA8iQQKBgQCfH5+366HCY6uz/JQwaw4SPQTe87ZcnoGBbsAva9qJETJKhaWl1/nZ\n' +
	'9bjw9KrARxlYGfYajarKa2Tkt6/KFBzTAOmp1rg3Q45vohMoY0BmtQDz9sdGGv/k\n' +
	'rVbcyNIUocjTUJgVr2PK9jFBYssEQRpPMRHlwoyC7WTeiwQTcDgO1g==\n' +
	'-----END RSA PRIVATE KEY-----\n';
var SSH_PRIVATE_2048 = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIZMHsQA' +
	'PX8wIMU2ZBrpbJsQmTNYXWOzCshxnUg35Pfrce/X6q0WGOJjUlwh4nE4QQSGRKVGKIe' +
	'cWzpDbldnzSZdaIp4sQTUgXmc5Vw2DG1IxGvrWq3QMP39zXFbMeRCOfDpDpK8tXOSRw' +
	'ukMmd8tzUyxMYHORJbXN219Lyl/quVmlr+XRNzTMjvbLA370uKjakN5domU0x+yJXvx' +
	'vjvMPO3UBmEdtrmlXxdAwC52GIgkjqMqM3Ud9TFXrbAPk+utT3G0MZSFUtLCGE64G33' +
	'K/FxPJG91ZXAo3x33WyFj5cKzilUOMbUjOgG+I29Y9PkbBbH6vBvW8MV139K8NR07N ' +
	'mark@bluesnoop.local';

var SSH_4096 = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAgEAsWUdvcKBBjW4GJ8Uyo0S8U' +
	'FFZbg5bqeRWPHcR2eIbo/k7M54PmWFqNL3YCIR8cRsvsFuYObnVaY01p1p/9+tpN4ezaHS5' +
	'9glhADTSva3uLrYuWA1FCKFi6/rXn9WkM5diSVrrTXzaQE8ZsVRA5QG6AeWhC3x/HNbiJOG' +
	'd9u0xrzYnyjrhO6x7eCnSz/AtNURLyWHbZ9Q0VEY5UVQsfAmmAAownMTth1m7KRG/KgM1Oz' +
	'9Dc+IUHYf0pjxFLQVQgqPnOLsj8OIJEt9SbZR33n66UJezbsbm0uJ+ophA3W/OacvHzCmoL' +
	'm9PaCwYEZ2pIlYlhkGGu6CFpfXhYUne61WAV8xR8pDXaIL7BqLRJZKlxPzrg9Iu278V9XeL' +
	'CnandXIGpaKwC5p7N/K6JoLB+nI1xd4X1NIftaBouxmYTXJy1VK2DKkD+KyvUPtN7EXnC4G' +
	'E4eDn9nibIj35GjfiDXrxcPPaJhSVzqvIIt55XcAnUEEVtiKtxICKwTSbvsojML5hL/gdeu' +
	'MWnMxj1nsZzTgSurD2OFaQ22k5HGu9aC+duNvvgjXWou7BsS/vH1QbP8GbIvYKlO5xNIj9z' +
	'kjINP3nCX4K1+IpW3PDkgS/DleUhUlvhxb10kc4af+9xViAGkV71WqNcoY+PAETvEbDbYpg' +
	'VEBd4mwFJLl/DT2Nlbj9q0= mark@bluesnoop.local';
var PEM_4096 = '-----BEGIN PUBLIC KEY-----\n' +
	'MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAsWUdvcKBBjW4GJ8Uyo0S\n' +
	'8UFFZbg5bqeRWPHcR2eIbo/k7M54PmWFqNL3YCIR8cRsvsFuYObnVaY01p1p/9+t\n' +
	'pN4ezaHS59glhADTSva3uLrYuWA1FCKFi6/rXn9WkM5diSVrrTXzaQE8ZsVRA5QG\n' +
	'6AeWhC3x/HNbiJOGd9u0xrzYnyjrhO6x7eCnSz/AtNURLyWHbZ9Q0VEY5UVQsfAm\n' +
	'mAAownMTth1m7KRG/KgM1Oz9Dc+IUHYf0pjxFLQVQgqPnOLsj8OIJEt9SbZR33n6\n' +
	'6UJezbsbm0uJ+ophA3W/OacvHzCmoLm9PaCwYEZ2pIlYlhkGGu6CFpfXhYUne61W\n' +
	'AV8xR8pDXaIL7BqLRJZKlxPzrg9Iu278V9XeLCnandXIGpaKwC5p7N/K6JoLB+nI\n' +
	'1xd4X1NIftaBouxmYTXJy1VK2DKkD+KyvUPtN7EXnC4GE4eDn9nibIj35GjfiDXr\n' +
	'xcPPaJhSVzqvIIt55XcAnUEEVtiKtxICKwTSbvsojML5hL/gdeuMWnMxj1nsZzTg\n' +
	'SurD2OFaQ22k5HGu9aC+duNvvgjXWou7BsS/vH1QbP8GbIvYKlO5xNIj9zkjINP3\n' +
	'nCX4K1+IpW3PDkgS/DleUhUlvhxb10kc4af+9xViAGkV71WqNcoY+PAETvEbDbYp\n' +
	'gVEBd4mwFJLl/DT2Nlbj9q0CASM=\n' +
	'-----END PUBLIC KEY-----\n';

var DSA_1024 = 'ssh-dss AAAAB3NzaC1kc3MAAACBAKK5sckoM05sOPajUcTWG0zPTvyRmj6' +
	'YQ1g2IgezUUrXgY+2PPy07+JrQi8SN9qr/CBP+0q0Ec48qVFf9LlkUBwu9Jf5HTUVNiKNj3c' +
	'SRPFH8HqZn+nxhVsOLhnHWxgDQ8OOm48Ma61NcYVo2B0Ne8cUs8xSqLqba2EG9ze87FQZAAA' +
	'AFQCVP/xpiAofZRD8L4QFwxOW9krikQAAAIACNv0EmKr+nIA13fjhpiqbYYyVXYOiWM4cmOD' +
	'G/d1J8/vR4YhWHWPbAEw7LD0DEwDIHLlRZr/1jsHbFcwt4tzRs95fyHzpucpGhocmjWx43qt' +
	'xEhDeJrxPlkIXHakciAEhoo+5YeRSSgRse5PrZDosdr5fA+DADs8tnto5Glf5owAAAIBHcEF' +
	'5ytvCRiKbsWKOgeMZ7JT/XGX+hMhS7aaJ2IspKj7YsWada1yBwoM6yYHtlpnGsq/PoPaZU8K' +
	'40f47psV6OhSh+/O/jgqLS/Ur2c0mQQqIb7vvkc7he/SPOQAqyDmyYFBuazuSf2s9Uy2hfvj' +
	'Wgb6X+vN9W8SOb2668IL7Vg== mark@bluesnoop.local';
var DSA_1024_PEM = '-----BEGIN PUBLIC KEY-----\n' +
	'MIIBtjCCASsGByqGSM44BAEwggEeAoGBAKK5sckoM05sOPajUcTWG0zPTvyRmj6Y\n' +
	'Q1g2IgezUUrXgY+2PPy07+JrQi8SN9qr/CBP+0q0Ec48qVFf9LlkUBwu9Jf5HTUV\n' +
	'NiKNj3cSRPFH8HqZn+nxhVsOLhnHWxgDQ8OOm48Ma61NcYVo2B0Ne8cUs8xSqLqb\n' +
	'a2EG9ze87FQZAhUAlT/8aYgKH2UQ/C+EBcMTlvZK4pECgYACNv0EmKr+nIA13fjh\n' +
	'piqbYYyVXYOiWM4cmODG/d1J8/vR4YhWHWPbAEw7LD0DEwDIHLlRZr/1jsHbFcwt\n' +
	'4tzRs95fyHzpucpGhocmjWx43qtxEhDeJrxPlkIXHakciAEhoo+5YeRSSgRse5Pr\n' +
	'ZDosdr5fA+DADs8tnto5Glf5owOBhAACgYBHcEF5ytvCRiKbsWKOgeMZ7JT/XGX+\n' +
	'hMhS7aaJ2IspKj7YsWada1yBwoM6yYHtlpnGsq/PoPaZU8K40f47psV6OhSh+/O/\n' +
	'jgqLS/Ur2c0mQQqIb7vvkc7he/SPOQAqyDmyYFBuazuSf2s9Uy2hfvjWgb6X+vN9\n' +
	'W8SOb2668IL7Vg==\n' +
	'-----END PUBLIC KEY-----\n';

var ENC_PRIVATE = '-----BEGIN RSA PRIVATE KEY-----\n' +
	'Proc-Type: 4,ENCRYPTED\n' +
	'DEK-Info: AES-128-CBC,B3095F1FAF29BE6554540D24F17D14DB\n\n' +
	'1OJdgfzsXazrhPZ7pO9Q27Pr97+OsU8FUxiCrDrEP71piJMJrmifue9KfOoAmC1L\n' +
	'FhaKXGSmRnP1/odgG7KBJ8ybIkZ5gVMz/dU4hR0SyA3zLMx+sV68oqYYw4s0EjrA\n' +
	'KYzQmMc78ouC6yQA4r+psgJ2sgK5VwwB48c0J5lO60HUeyEsno6iGY7VW/Kmt76O\n' +
	'Kl8/LwA9qE2U/1u6pRsoaD34CD2E+m/IwCUIyLeri04tiMfyE0RKTL9EacvxExCu\n' +
	'ucwBlvtGIcQcChw1JJqGxTXBeCrz8Kb3uWNrZ+MME3OEh4qWFPgT6XqeE/gociym\n' +
	'rhyKffZKsnJts0TqxqSuxtpLM5+WaYAGbkEHzuC/chOsynFRKxZomV65ddufmO3N\n' +
	'Kb8B3H+2+Fo9x5iucEBhj4MBLHlZ7ZkQ8yEP+E0d0PuPRIFZ3aRcKPuaoZIc/AiQ\n' +
	'8w1GGAU1TZWWHs1L4pF7OWyWwuq3NkzWLzL7MkNx++zmxXpIPMKDnFTLuBu24nCk\n' +
	'gBx85sgirfSJBwx1mpQzsD1PSE7krAzlA4DRfgPChAWJnlUn89aPJ52uokHneJIK\n' +
	'z8/ApT6HCd3EnH9VHEtXp116ZVk4PhRiiOMY/ek2uhFK57wgMxOrRM3OgODrd+5A\n' +
	'-----END RSA PRIVATE KEY-----\n';

///--- Tests

test('1024b pem to rsa ssh key', function(t) {
	var k = sshpk.parseKey(PEM_1024, 'pem');
	k.comment = 'mark@foo.local';
	t.equal(k.toString('ssh'), SSH_1024);
	t.end();
});

test('2048b pem to rsa ssh key', function(t) {
	var k = sshpk.parseKey(PEM_2048, 'pem');
	k.comment = 'mark@bluesnoop.local';
	t.equal(k.toString('ssh'), SSH_2048);
	t.end();
});

test('2048b pem private to rsa ssh key', function(t) {
	var k = sshpk.parseKey(PEM_PRIVATE_2048, 'pem');
	k.comment = 'mark@bluesnoop.local';
	t.equal(k.toString('ssh'), SSH_PRIVATE_2048);
	t.end();
});

test('4096b pem to rsa ssh key', function(t) {
	var k = sshpk.parseKey(PEM_4096, 'pem');
	k.comment = 'mark@bluesnoop.local';
	t.equal(k.toString('ssh'), SSH_4096);
	t.end();
});

test('1024b rsa ssh key', function(t) {
	var k = sshpk.parseKey(SSH_1024, 'ssh');
	t.equal(k.toString('pem'), PEM_1024);
	t.end();
});

test('2048b rsa ssh key', function(t) {
	var k = sshpk.parseKey(SSH_2048, 'ssh');
	t.equal(k.toString('pem'), PEM_2048);
	t.end();
});

test('4096b rsa ssh key', function(t) {
	var k = sshpk.parseKey(SSH_4096, 'ssh');
	t.equal(k.toString('pem'), PEM_4096);
	t.end();
});

test('1024b dsa ssh key', function(t) {
	var k = sshpk.parseKey(DSA_1024, 'ssh');
	t.equal(k.toString('pem'), DSA_1024_PEM);
	t.end();
});

test('encrypted private key', function(t) {
	t.throws(function () {
		var k = sshpk.parseKey(ENC_PRIVATE, 'pem');
	});
	t.end();
});
