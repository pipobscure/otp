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

function generateKey(length: number): string {
	const bytes = new Uint8Array(length);
	globalThis.crypto.getRandomValues(bytes);
	return Base32.encode(bytes);
}

function UInt64Buffer(num: number): Uint8Array {
	const buffer = new ArrayBuffer(8);
	new DataView(buffer).setBigUint64(0, BigInt(num));
	return new Uint8Array(buffer);
}

class Hmac {
	private key: Uint8Array;
	private ipad: Uint8Array;
	private opad: Uint8Array;
	private hash: Hash;

	constructor(blockSize: number, key: Uint8Array) {
		if (blockSize !== 64 && blockSize !== 128) {
			throw new Error(`Invalid blockSize: ${blockSize}. Must be 64 or 128.`);
		}
		this.key = rekey(key, blockSize);
		this.ipad = new Uint8Array(blockSize).fill(0x36).map((b, i) => b ^ this.key[i]);
		this.opad = new Uint8Array(blockSize).fill(0x5c).map((b, i) => b ^ this.key[i]);

		this.hash = new Hash();
		this.hash.update(this.ipad);
	}

	update(data: Uint8Array): Hmac {
		this.hash.update(data);
		return this;
	}

	digest(): Uint8Array {
		const innerHash = this.hash.digest();
		return new Hash().update(this.opad).update(innerHash).digest();
	}
}

function rekey(key: Uint8Array, blockSize: number): Uint8Array {
	if (key.length > blockSize) {
		return Hash.hash(key);
	} else if (key.length < blockSize) {
		const extendedKey = new Uint8Array(blockSize);
		extendedKey.set(key);
		return extendedKey;
	}
	return key;
}

class Hash {
	private data: number[] = [];

	update(data: Uint8Array): Hash {
		this.data.push(...data);
		return this;
	}

	digest(): Uint8Array {
		return new Uint8Array(sha1(this.data, { asBytes: true }));
	}

	static hash(data: Uint8Array): Uint8Array {
		return new Hash().update(data).digest();
	}
}

export default class OTP {
	private readonly options: OTPOptions;
	public readonly hotp: (counter: number) => string;
	public readonly totp: (now: number) => string;

	constructor(options: string | Partial<OTPOptions> = {}) {
		if (typeof options === 'string') {
			return OTP.parse(options);
		}

		const defaultOptions = {
			name: 'OTP-Authentication',
			keySize: 64,
			codeLength: 6,
			secret: generateKey(64),
			epoch: 0,
			timeSlice: 30,
		};

		this.options = {
			...defaultOptions,
			...options,
			name: `${options.name || defaultOptions.name}`.replace(/[^\w|_|-|@]/g, ''),
			keySize: options.keySize === 128 ? 128 : 64,
			codeLength: isNaN(options.codeLength) ? 6 : options.codeLength,
			secret: options.secret || generateKey(options.keySize),
			epoch: isNaN(options.epoch) ? 0 : options.epoch,
			timeSlice: isNaN(options.timeSlice) ? 30 : options.timeSlice,
		} as OTPOptions;

		this.hotp = this.generateHotp.bind(this);
		this.totp = this.generateTotp.bind(this);
	}

	get name(): string {
		return this.options.name;
	}

	get secret(): string {
		return this.options.secret;
	}

	get totpURL(): string {
		return `otpauth://totp/${encodeURIComponent(this.name)}?secret=${encodeURIComponent(this.secret)}`;
	}

	get hotpURL(): string {
		return `otpauth://hotp/${encodeURIComponent(this.name)}?secret=${encodeURIComponent(this.secret)}`;
	}

	toString(): string {
		return '[object OTP]';
	}

	toJSON() {
		return {
			class: OTP.classID,
			...this.options,
		};
	}

	static reviveJSON(_: string, val: any): OTP | any {
		if (typeof val !== 'object' || val === null || val['class'] !== OTP.classID) {
			return val;
		}
		const { name, keySize, codeLength, secret, epoch, timeSlice } = val;
		return new OTP({ name, keySize, codeLength, secret, epoch, timeSlice });
	}

	static readonly classID = 'OTP{@pipobscure}';

	static parse(urlstr: string = '', options: Partial<OTPOptions> = {}): OTP {
		const newOptions = { ...options };

		try {
			const url = new URL(urlstr);
			const name = decodeURIComponent(url.pathname.slice(1)).trim();
			const rawSecret = Base32.decode(decodeURIComponent(url.searchParams.get('secret')));
			const keySize = rawSecret.byteLength;
			const secret = Base32.encode(rawSecret);

			if (name) {
				Object.assign(newOptions, { name, keySize, secret });
			}
		} catch {
			const rawSecret = Base32.decode(urlstr);
			const keySize = rawSecret.byteLength;
			const secret = Base32.encode(rawSecret);
			Object.assign(newOptions, { keySize, secret });
		}

		return new OTP(newOptions);
	}

	private generateHotp(counter: number): string {
		const { keySize, secret, codeLength } = this.options;
		const hmac = new Hmac(keySize, Base32.decode(secret));
		const digest = hmac.update(UInt64Buffer(counter)).digest();
		const offset = digest[digest.length - 1] & 0xf;
		const code = (
			((digest[offset] & 0x7f) << 24) |
			((digest[offset + 1] & 0xff) << 16) |
			((digest[offset + 2] & 0xff) << 8) |
			(digest[offset + 3] & 0xff)
		).toString();

		return code.padStart(codeLength, '0').slice(-codeLength);
	}

	private generateTotp(now: number = Date.now()): string {
		const { epoch, timeSlice } = this.options;
		const counter = Math.floor((now - epoch * 1000) / (timeSlice * 1000));
		return this.generateHotp(counter);
	}
}
