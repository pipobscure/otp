interface OTPOptions {
	name: string;
	keySize: number;
	codeLength: number;
	secret: string;
	epoch: number;
	timeSlice: number;
}

export class OTP {
	constructor(options: Partial<OTPOptions> = {}) {
		options = Object.assign({}, options);
		options.name = `${options.name || 'OTP-Authentication'}`.split(/[^\w|_|-|@]/).join('');
		options.keySize = options.keySize === 128 ? 128 : 64;
		options.codeLength = Number.isNaN(options.codeLength ?? Number.NaN) ? 6 : (options.codeLength as number);
		options.secret = options.secret || generateKey(options.keySize);
		options.epoch = Number.isNaN(options.epoch ?? Number.NaN) ? 0 : (options.epoch as number);
		options.timeSlice = Number.isNaN(options.timeSlice ?? Number.NaN) ? 30 : (options.timeSlice as number);
		this.#options = options as OTPOptions;
		this.hotp = hotp.bind(null, options as OTPOptions);
		this.totp = totp.bind(null, options as OTPOptions);
	}
	readonly #options: OTPOptions;
	public readonly hotp: (counter: number) => Promise<string>;
	public readonly totp: (now: number) => Promise<string>;

	get name() {
		return this.#options.name;
	}
	get secret() {
		return this.#options.secret;
	}
	get totpURL() {
		return `otpauth://totp/${encodeURIComponent(this.name)}?secret=${encodeURIComponent(this.secret)}`;
	}
	get hotpURL() {
		return `otpauth://hotp/${encodeURIComponent(this.name)}?secret=${encodeURIComponent(this.secret)}`;
	}

	[Symbol.toStringTag]() {
		return 'OTP';
	}
	toJSON() {
		return Object.assign({ class: OTP.classID }, this.#options);
	}
	static reviveJSON(_: string, val: any) {
		if ('object' !== typeof val || null === val || (val as any).class !== OTP.classID) return val;
		const { name, keySize, codeLength, secret, epoch, timeSlice } = val;
		return new OTP({ name, keySize, codeLength, secret, epoch, timeSlice });
	}
	static readonly classID = 'OTP{@pipobscure}';
	static parse(urlstr: string = '', options: Partial<OTPOptions> = {}) {
		options = Object.assign({}, options);
		try {
			const url = new URL(urlstr);
			const name = decodeURIComponent(url.pathname.slice(1)).trim();
			const rawsecret = decode(decodeURIComponent(url.searchParams.get('secret') ?? ''));
			const keySize = rawsecret.byteLength;
			const secret = encode(rawsecret);
			if (name) options = Object.assign(options, name ? { name, keySize, secret } : { keySize, secret });
		} catch {
			const rawsecret = decode(urlstr);
			const keySize = rawsecret.byteLength;
			const secret = encode(rawsecret);
			options = Object.assign(options, { keySize, secret });
		}
		return new OTP(options);
	}
}
export default OTP;

async function hotp(options: OTPOptions, counter: number): Promise<string> {
	const key = await crypto.subtle.importKey('raw', decode(options.secret), { name: 'HMAC', hash: 'sha-1' }, false, ['sign']);
	const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, UInt64Buffer(counter)));
	const offset = (digest[19] ?? 0) & 0xf;
	const code = String((((digest[offset] ?? 0) & 0x7f) << 24) | (((digest[offset + 1] ?? 0) & 0xff) << 16) | (((digest[offset + 2] ?? 0) & 0xff) << 8) | ((digest[offset + 3] ?? 0) & 0xff));
	return `${new Array(options.codeLength).fill('0')}${code}`.slice(-1 * options.codeLength);
}
async function totp(options: OTPOptions, now: number = Date.now()): Promise<string> {
	const counter = Math.floor((now - options.epoch * 1000) / (options.timeSlice * 1000));
	return await hotp(options, counter);
}

function generateKey(length: number) {
	const bytes = new Uint8Array(length);
	globalThis.crypto.getRandomValues(bytes);
	return encode(bytes);
}
function UInt64Buffer(num: number) {
	const buffer = new ArrayBuffer(8);
	new DataView(buffer).setBigUint64(0, BigInt(num));
	return new Uint8Array(buffer);
}

const VOCAB = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789='.split('');
const PAD = ['=', '=', '=', '=', '=', '=', '=', '='];

export function encodeChunk(data: Uint8Array) {
	const b1 = data.length > 0 ? data[0] : 0;
	assertNumber(b1);
	const b2 = data.length > 1 ? data[1] : 0;
	assertNumber(b2);
	const b3 = data.length > 2 ? data[2] : 0;
	assertNumber(b3);
	const b4 = data.length > 3 ? data[3] : 0;
	assertNumber(b4);
	const b5 = data.length > 4 ? data[4] : 0;
	assertNumber(b5);

	const chars = [
		map(mask(b1 >> 3)), // [12345]678 >> 12345
		map(mask((b1 << 2) | (b2 >> 6))), // 12345678 << 67800 | 12345678 >> 00012
		map(mask(b2 >> 1)), // 12345678 >> 34567
		map(mask((b2 << 4) | (b3 >> 4))), // 12345678 << 80000 | 12345678 >> 01234
		map(mask((b3 << 1) | (b4 >> 7))), // 12345678 << 56780 | 12345678 >> 00001
		map(mask(b4 >> 2)), // 12345678 >> 23456
		map(mask((b4 << 3) | (b5 >> 5))), // 12345678 << 78000 | 12345678 >> 00123
		map(mask(b5)), // 12345678 >> 45678
	];

	switch (data.length) {
		case 0:
			return '';
		case 1:
			return chars.slice(0, 2).concat(PAD).slice(0, 8).join('');
		case 2:
			return chars.slice(0, 4).concat(PAD).slice(0, 8).join('');
		case 3:
			return chars.slice(0, 5).concat(PAD).slice(0, 8).join('');
		case 4:
			return chars.slice(0, 7).concat(PAD).slice(0, 8).join('');
		case 5:
			return chars.slice(0, 8).concat(PAD).slice(0, 8).join('');
		default:
			return chars.join('');
	}
}

function mask(n: number): number {
	return n & 0b00011111;
}
function map(n: number): string {
	return n > -1 && n < VOCAB.length ? (VOCAB[n] as string) : '=';
}

export function encode(data: Uint8Array) {
	let offset = 0;
	const chunks: string[] = [];
	while (offset < data.length) {
		const subset = data.subarray(offset, offset + 5);
		chunks.push(encodeChunk(subset));
		offset += subset.length;
	}
	return chunks.join('');
}

function decodeChar(data: string): number {
	const index = VOCAB.indexOf(data);
	if (index < 0) throw new Error(`invalid character: ${data}`);
	if (index === VOCAB.length - 1) return 0;
	return Math.max(index, 0);
}
export function decodeChunk(data: string[], dest: Uint8Array) {
	const c1 = decodeChar(data[0] ?? ' ');
	const c2 = decodeChar(data[1] ?? ' ');
	const c3 = data[2] ? decodeChar(data[2]) : undefined;
	const c4 = data[3] ? decodeChar(data[3]) : undefined;
	const c5 = data[4] ? decodeChar(data[4]) : undefined;
	const c6 = data[5] ? decodeChar(data[5]) : undefined;
	const c7 = data[6] ? decodeChar(data[6]) : undefined;
	const c8 = data[7] ? decodeChar(data[7]) : undefined;

	dest[0] = byte((c1 << 3) | (c2 >> 2));
	if (isNumber(c3) && isNumber(c4)) dest[1] = byte((c2 << 6) | (c3 << 1) | (c4 >> 4)); // xxx12 34567 8xxxx
	if (isNumber(c4) && isNumber(c5)) dest[2] = byte((c4 << 4) | (c5 >> 1)); // x1234 1234x
	if (isNumber(c5) && isNumber(c6) && isNumber(c7)) dest[3] = byte((c5 << 7) | (c6 << 2) | (c7 >> 3)); // xxxx1 23456 78xxx
	if (isNumber(c7) && isNumber(c8)) dest[4] = byte((c7 << 5) | c8); // xx123 45678
}

function isNumber(arg: number | undefined): arg is number {
	return arg !== undefined && Number.isFinite(arg);
}
function assertNumber(arg: any): asserts arg is number {
	if ('number' !== typeof arg || !isNumber(arg)) throw new TypeError('argument is not a number');
}
function byte(n: number) {
	return n & 0xff;
}

export function decode(data: string) {
	data = data
		.split(/\s+/)
		.map((s) => s.trim())
		.join('');
	const dest = new Uint8Array((data.length * 5) / 8);
	const chars = data.split('');
	let coff = 0;
	let boff = 0;
	let fin = 5;
	while (fin === 5 && coff < chars.length && boff < dest.length) {
		const chunk = chars.slice(coff, coff + 8);
		if (chunk.indexOf('=') > -1) {
			chunk.splice(chunk.indexOf('='), 8);
			switch (chunk.length) {
				case 2:
					fin = 1;
					break;
				case 4:
					fin = 2;
					break;
				case 5:
					fin = 3;
					break;
				case 7:
					fin = 4;
					break;
				default:
					throw new Error('invalid padding');
			}
		}
		decodeChunk(chunk, dest.subarray(boff, boff + 5));
		coff += 8;
		boff += 5;
	}
	return dest.subarray(0, dest.length - 5 + fin);
}
