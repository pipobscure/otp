import { describe, it } from 'node:test';
import { strictEqual } from 'node:assert';

import { randomBytes } from 'node:crypto';
import { encode, decode, encodeChunk, decodeChunk } from './otp.ts';

describe('base32', () => {
	describe('chunk', () => {
		const data = Buffer.from('8479efe183', 'hex');
		const encd = 'QR467YMD';
		it('encode', () => {
			const actual = encodeChunk(data);
			strictEqual(actual, encd);
		});
		it('decode', () => {
			const actual = Buffer.alloc(5);
			decodeChunk(encd.split(''), actual);
			strictEqual(actual.toString('hex'), data.toString('hex'));
		});
	});
	describe('whole', () => {
		const data = Buffer.from('4373acf0d34e7c15', 'hex');
		const encd = 'INZ2Z4GTJZ6BK===';
		it('encode', () => {
			const actual = encode(data);
			strictEqual(actual, encd);
		});
		it('decode', () => {
			const actual = Buffer.from(decode(encd));
			strictEqual(actual.toString('hex'), data.toString('hex'));
		});
	});
	describe('64', () => {
		const data = Buffer.from('0b17fcff5b73f9b5141cbfa33da655d3c243295127d91c92d291ab0c2698bf9067a5840ebc30fb83804f4df0b4f343368dd671d9cb6be1e1950fc6250615e86d', 'hex');
		const encd = 'BML7Z723OP43KFA4X6RT3JSV2PBEGKKRE7MRZEWSSGVQYJUYX6IGPJMEB26DB64DQBHU34FU6NBTNDOWOHM4W27B4GKQ7RRFAYK6Q3I=';
		it('encode', () => {
			const actual = encode(data);
			strictEqual(actual, encd);
		});
		it('decode', () => {
			const actual = Buffer.from(decode(encd));
			strictEqual(actual.toString('hex'), data.toString('hex'));
		});
	});
	it('encodes(64)', () => {
		const data = randomBytes(64);
		const encoded = encode(data);
		const decoded = Buffer.from(decode(encoded));
		strictEqual(decoded.toString('hex'), data.toString('hex'));
	});
	it('encodes(128)', () => {
		const data = randomBytes(64);
		const encoded = encode(data);
		const decoded = Buffer.from(decode(encoded));
		strictEqual(decoded.toString('hex'), data.toString('hex'));
	});
	it('decodes(64)', () => {
		const data = '7E3WMHGCDN45PYLUCVAJ7FDST3WGXLF7AB6CRDXBRGQGWS3OR4HA====';
		const decoded = decode(data);
		const reen = encode(decoded);
		strictEqual(reen, data);
	});
});
