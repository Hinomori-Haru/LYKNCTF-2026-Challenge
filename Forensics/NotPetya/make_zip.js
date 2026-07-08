'use strict';
const fs = require('fs'),
	zlib = require('zlib'),
	crypto = require('crypto'),
	path = require('path');

const serialHex = (process.argv[2] || '').replace(/[^0-9a-fA-F]/g, '');
if (serialHex.length !== 16) {
	console.error(
		'ERR: volSerialHex requires 16 hex characters (8 bytes). Ex: node make_zip.js 3A172CB4442CB428',
	);
	process.exit(1);
}
const VOL_SERIAL = Buffer.from(serialHex, 'hex');

const SEED = 956377,
	SALT = Buffer.from('yuneko_dev_', 'ascii');
const MBIG = 2147483647,
	MSEED = 161803398;
class NetRandom {
	constructor(s) {
		this.s = new Array(56).fill(0);
		let sub = s === -2147483648 ? MBIG : Math.abs(s);
		let mj = MSEED - sub;
		this.s[55] = mj;
		let mk = 1;
		for (let i = 1; i < 55; i++) {
			let ii = (21 * i) % 55;
			this.s[ii] = mk;
			mk = mj - mk;
			if (mk < 0) mk += MBIG;
			mj = this.s[ii];
		}
		for (let k = 0; k < 4; k++)
			for (let i = 1; i < 56; i++) {
				this.s[i] -= this.s[1 + ((i + 30) % 55)];
				if (this.s[i] < 0) this.s[i] += MBIG;
			}
		this.inext = 0;
		this.inextp = 21;
	}
	samp() {
		this.inext = this.inext + 1 >= 56 ? 1 : this.inext + 1;
		this.inextp = this.inextp + 1 >= 56 ? 1 : this.inextp + 1;
		let r = this.s[this.inext] - this.s[this.inextp];
		if (r === MBIG) r--;
		if (r < 0) r += MBIG;
		this.s[this.inext] = r;
		return r;
	}
	nextBytes(n) {
		return Buffer.from(Array.from({ length: n }, () => this.samp() % 256));
	}
}
const aesKey = crypto
	.createHash('sha256')
	.update(
		Buffer.concat([new NetRandom(SEED).nextBytes(32), SALT, VOL_SERIAL]),
	)
	.digest();
const PASSWORD = aesKey.toString('hex').toUpperCase();

const CRCTAB = (() => {
	const t = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++)
			c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		t[n] = c >>> 0;
	}
	return t;
})();
const crcUpd = (crc, b) => (CRCTAB[(crc ^ b) & 0xff] ^ (crc >>> 8)) >>> 0;
class ZipCrypto {
	constructor(pw) {
		this.k0 = 0x12345678;
		this.k1 = 0x23456789;
		this.k2 = 0x34567890;
		for (const c of Buffer.from(pw, 'latin1')) this.upd(c);
	}
	upd(b) {
		this.k0 = crcUpd(this.k0, b);
		this.k1 = (this.k1 + (this.k0 & 0xff)) >>> 0;
		this.k1 = (Math.imul(this.k1, 134775813) + 1) >>> 0;
		this.k2 = crcUpd(this.k2, (this.k1 >>> 24) & 0xff);
	}
	decByte() {
		const t = (this.k2 | 2) >>> 0;
		return (Math.imul(t, t ^ 1) >>> 8) & 0xff;
	}
	encrypt(buf) {
		const out = Buffer.alloc(buf.length);
		for (let i = 0; i < buf.length; i++) {
			const t = this.decByte();
			out[i] = buf[i] ^ t;
			this.upd(buf[i]);
		}
		return out;
	}
}
function encryptEntry(pw, comp, crc) {
	const zc = new ZipCrypto(pw);
	const hdr = Buffer.alloc(12);
	crypto.randomFillSync(hdr.subarray(0, 11));
	hdr[11] = (crc >>> 24) & 0xff;
	return Buffer.concat([zc.encrypt(hdr), zc.encrypt(comp)]);
}

const DIR = 'flag';
if (!fs.existsSync(DIR)) {
	console.error(
		"ERR: missing 'flag/' directory. Run 'node gen_flag.js' first.",
	);
	process.exit(1);
}
const entries = fs
	.readdirSync(DIR)
	.filter((n) => fs.statSync(path.join(DIR, n)).isFile())
	.map((n) => ({ name: n, raw: fs.readFileSync(path.join(DIR, n)) }));
if (!entries.some((e) => e.name === 'part4.txt')) {
	console.error('ERR: flag/part4.txt does not exist.');
	process.exit(1);
}

const GP_ENCRYPTED = 0x0001;
const locals = [],
	centrals = [];
let off = 0;
for (const e of entries) {
	const crc = zlib.crc32(e.raw) >>> 0;
	const comp = zlib.deflateRawSync(e.raw, { level: 9 });
	const enc = encryptEntry(PASSWORD, comp, crc);
	const nameBuf = Buffer.from(e.name, 'latin1');

	const lfh = Buffer.alloc(30);
	lfh.writeUInt32LE(0x04034b50, 0);
	lfh.writeUInt16LE(20, 4);
	lfh.writeUInt16LE(GP_ENCRYPTED, 6);
	lfh.writeUInt16LE(8, 8);
	lfh.writeUInt16LE(0, 10);
	lfh.writeUInt16LE(0, 12);
	lfh.writeUInt32LE(crc, 14);
	lfh.writeUInt32LE(enc.length, 18);
	lfh.writeUInt32LE(e.raw.length, 22);
	lfh.writeUInt16LE(nameBuf.length, 26);
	lfh.writeUInt16LE(0, 28);
	locals.push(lfh, nameBuf, enc);

	const cdh = Buffer.alloc(46);
	cdh.writeUInt32LE(0x02014b50, 0);
	cdh.writeUInt16LE(20, 4);
	cdh.writeUInt16LE(20, 6);
	cdh.writeUInt16LE(GP_ENCRYPTED, 8);
	cdh.writeUInt16LE(8, 10);
	cdh.writeUInt16LE(0, 12);
	cdh.writeUInt16LE(0, 14);
	cdh.writeUInt32LE(crc, 16);
	cdh.writeUInt32LE(enc.length, 20);
	cdh.writeUInt32LE(e.raw.length, 24);
	cdh.writeUInt16LE(nameBuf.length, 28);
	cdh.writeUInt32LE(off, 42);
	centrals.push(cdh, nameBuf);

	off += lfh.length + nameBuf.length + enc.length;
}
const localBuf = Buffer.concat(locals),
	cdBuf = Buffer.concat(centrals);
const eocd = Buffer.alloc(22);
eocd.writeUInt32LE(0x06054b50, 0);
eocd.writeUInt16LE(entries.length, 8);
eocd.writeUInt16LE(entries.length, 10);
eocd.writeUInt32LE(cdBuf.length, 12);
eocd.writeUInt32LE(localBuf.length, 16);

const out = Buffer.concat([localBuf, cdBuf, eocd]);
fs.writeFileSync('flag.zip', out);

const p4 = fs.readFileSync(path.join(DIR, 'part4.txt'));
console.log('flag.zip written', out.length, 'bytes | ZipCrypto, encrypted');
console.log('password (= [P3] KEY) =', PASSWORD);
console.log(
	'piece 4 plaintext on disk:',
	out.indexOf(p4) < 0 ? 'no (safe)' : 'EXISTS (!!)',
);
console.log('extract with: 7z x -p' + PASSWORD + ' flag.zip   (or unzip -P)');
for (const e of entries) console.log(' -', e.name, '(' + e.raw.length + 'B)');
