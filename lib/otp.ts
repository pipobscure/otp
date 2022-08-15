import sha1 from 'sha1';
import * as Base32 from './base32';

interface OTPOptions {
	name: string;
	keySize: number;
	codeLength: number;
	secret: string;
	epoch: number;
	timeSlice: number;
}

export default class OTP {
	constructor(options: string | Partial<OTPOptions> = {}) {
		if ('string' === typeof options) return OTP.parse(options);
		options = Object.assign({}, options);
		options.name = `${options.name || 'OTP-Authentication'}`.split(/[^\w|_|-|@]/).join('');
		options.keySize = options.keySize === 128 ? 128 : 64;
		options.codeLength = isNaN(options.codeLength) ? 6 : options.codeLength;
		options.secret = options.secret || generateKey(options.keySize);
		options.epoch = isNaN(options.epoch) ? 0 : options.epoch;
		options.timeSlice = isNaN(options.timeSlice) ? 30 : options.timeSlice;
		this.options = options as OTPOptions;
		this.hotp = hotp.bind(null, options);
		this.totp = totp.bind(null, options);
	}
	private readonly options: OTPOptions;
	public readonly hotp: (counter: number) => string;
	public readonly totp: (now: number) => string;

	get name() {
		return this.options.name;
	}
	get secret() {
		return this.options.secret;
	}
	get totpURL() {
		return `otpauth://totp/${encodeURIComponent(this.name)}?secret=${encodeURIComponent(this.secret)}`;
	}
	get hotpURL() {
		return `otpauth://hotp/${encodeURIComponent(this.name)}?secret=${encodeURIComponent(this.secret)}`;
	}

	toString() {
		return '[object OTP]';
	}
	toJSON() {
		return Object.assign({ class: OTP.classID }, this.options);
	}
	static reviveJSON(_: string, val: any) {
		if ('object' !== typeof val || null === val || val['class'] !== OTP.classID) return val;
		const { name, keySize, codeLength, secret, epoch, timeSlice } = val;
		return new OTP({ name, keySize, codeLength, secret, epoch, timeSlice });
	}
	static readonly classID = 'OTP{@pipobscure}';
	static parse(urlstr: string = '', options: Partial<OTPOptions> = {}) {
		options = Object.assign({}, options);
		try {
			const url = new URL(urlstr);
			const name = decodeURIComponent(url.pathname.slice(1)).trim();
			const rawsecret = Base32.decode(decodeURIComponent(url.searchParams.get('secret')));
			const keySize = rawsecret.byteLength;
			const secret = Base32.encode(rawsecret);
			if (name) options = Object.assign(options, name ? { name, keySize, secret } : { keySize, secret });
		} catch {
			const rawsecret = Base32.decode(urlstr);
			const keySize = rawsecret.byteLength;
			const secret = Base32.encode(rawsecret);
			options = Object.assign(options, { keySize, secret });
		}
		return new OTP(options);
	}
}

function hotp(options: OTPOptions, counter: number): string {
	const digest = new Hmac(options.keySize, Base32.decode(options.secret)).update(UInt64Buffer(counter)).digest();
	const offset = digest[19] & 0xf;
	const code = String(
		((digest[offset] & 0x7f) << 24) |
			((digest[offset + 1] & 0xff) << 16) |
			((digest[offset + 2] & 0xff) << 8) |
			(digest[offset + 3] & 0xff),
	);
	return `${new Array(options.codeLength).fill('0')}${code}`.slice(-1 * options.codeLength);
}
function totp(options: OTPOptions, now: number = Date.now()): string {
	const counter = Math.floor((now - options.epoch * 1000) / (options.timeSlice * 1000));
	return hotp(options, counter);
}

function generateKey(length: number) {
	const key = new Uint8Array(new Array(length).fill(0).map(() => Math.floor(Math.random() * 256)));
	return Base32.encode(key);
}
function UInt64Buffer(num: number) {
	const res = Buffer.alloc(8);
	res.writeBigUInt64BE(BigInt(num));
	return res;
}

class Hmac {
	constructor(blocksize: number, key: Uint8Array) {
		if (blocksize !== 128 && blocksize !== 64) {
			throw new Error('blocksize must be either 64 for or 128 , but was:' + blocksize);
		}
		this.key = rekey(key, blocksize);
		this.opad = new Uint8Array(new Array(blocksize).fill(0));
		this.ipad = new Uint8Array(new Array(blocksize).fill(0));

		for (var i = 0; i < blocksize; i++) {
			this.ipad[i] = this.key[i] ^ 0x36;
			this.opad[i] = this.key[i] ^ 0x5c;
		}

		this.hash = new Hash();
		this.hash.update(this.ipad);
	}
	private key: Uint8Array;
	private ipad: Uint8Array;
	private opad: Uint8Array;
	private hash: Hash;

	update(data: Uint8Array) {
		this.hash.update(data);
		return this;
	}
	digest() {
		const hash = this.hash.digest();
		return new Hash().update(this.opad).update(hash).digest();
	}
}

function rekey(key: Uint8Array, blocksize: number): Uint8Array {
	if (key.length > blocksize) {
		return Hash.hash(key);
	}
	if (key.length < blocksize) {
		const res = new Uint8Array(blocksize);
		res.set(key);
		res.fill(0, key.length);
		return res;
	}
	return key;
}

class Hash {
	constructor() {}
	private data: number[] = [];
	update(data: Uint8Array) {
		this.data.push(...data.values());
		return this;
	}
	digest() {
		return sha1(this.data, { asBytes: true });
	}
	static hash(data: Uint8Array) {
		return new Hash().update(data).digest();
	}
}
