const VOCAB = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789='.split('');
const PAD = ['=', '=', '=', '=', '=', '=', '=', '='];

export function encodeChunk(data: Uint8Array) {
	const b1 = data.length > 0 ? data[0] : 0;
	const b2 = data.length > 1 ? data[1] : 0;
	const b3 = data.length > 2 ? data[2] : 0;
	const b4 = data.length > 3 ? data[3] : 0;
	const b5 = data.length > 4 ? data[4] : 0;

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
	return n > -1 && n < VOCAB.length ? VOCAB[n] : '=';
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
	if (index < 0) throw new Error('invalid character: ' + data);
	if (index === VOCAB.length - 1) return 0;
	return Math.max(index, 0);
}
export function decodeChunk(data: string[], dest: Uint8Array) {
	const c1 = decodeChar(data[0]);
	const c2 = decodeChar(data[1]);
	const c3 = data[2] ? decodeChar(data[2]) : undefined;
	const c4 = data[3] ? decodeChar(data[3]) : undefined;
	const c5 = data[4] ? decodeChar(data[4]) : undefined;
	const c6 = data[5] ? decodeChar(data[5]) : undefined;
	const c7 = data[6] ? decodeChar(data[6]) : undefined;
	const c8 = data[7] ? decodeChar(data[7]) : undefined;

	dest[0] = byte((c1 << 3) | (c2 >> 2));
	if (defined(c3, c4)) dest[1] = byte((c2 << 6) | (c3 << 1) | (c4 >> 4)); // xxx12 34567 8xxxx
	if (defined(c4, c5)) dest[2] = byte((c4 << 4) | (c5 >> 1)); // x1234 1234x
	if (defined(c5, c6, c7)) dest[3] = byte((c5 << 7) | (c6 << 2) | (c7 >> 3)); // xxxx1 23456 78xxx
	if (defined(c7, c8)) dest[4] = byte((c7 << 5) | c8); // xx123 45678
}

function defined(...args: (number | undefined)[]) {
	for (const arg of args) if (arg === undefined) return false;
	return true;
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
	while (fin == 5 && coff < chars.length && boff < dest.length) {
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
