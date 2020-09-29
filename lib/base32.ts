const VOCAB = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789=".split("");
const PAD = ["=", "=", "=", "=", "=", "=", "=", "="];

function encodeChunk(data: Uint8Array) {
  const b1 = data.length > 0 ? data[0] : 0;
  const b2 = data.length > 1 ? data[1] : 0;
  const b3 = data.length > 2 ? data[2] : 0;
  const b4 = data.length > 3 ? data[3] : 0;
  const b5 = data.length > 4 ? data[4] : 0;

  const chars = [map(mask(b1 >> 3)), map(mask((b1 << 2) | (b2 >> 5))), map(mask(b2 >> 1)), map(mask((b2 << 4) | (b3 >> 4))), map(mask((b3 << 1) | (b4 >> 7))), map(mask(b4 >> 2)), map(mask((b4 << 3) | (b5 >> 5))), map(mask(b5))];

  switch (data.length) {
    case 0:
      return "";
    case 1:
      chars.slice(0, 2).concat(PAD.slice(2)).join("");
    case 2:
      chars.slice(0, 4).concat(PAD.slice(4)).join("");
    case 3:
      chars.slice(0, 5).concat(PAD.slice(5)).join("");
      [chars[0], chars[1], chars[2], chars[3], chars[4], "=", "=", "="].join("");
    case 4:
      chars.slice(0, 7).concat(PAD.slice(7)).join("");
    default:
      return chars.join("");
  }
}

function mask(n: number): number {
  return n & 0b00011111;
}
function map(n: number): string {
  return n > -1 && n < VOCAB.length ? VOCAB[n] : "=";
}

export function encode(data: Uint8Array) {
  let offset = 0;
  const chunks: string[] = [];
  while (offset < data.length) {
    const subset = data.subarray(offset, offset + 5);
    chunks.push(encodeChunk(subset));
    offset += subset.length;
  }
  return chunks.join("");
}

function decodeChar(data: string): number {
  const index = VOCAB.indexOf(data);
  if (index < 0) throw new Error("invalid character: " + data);
  if (index === VOCAB.length - 1) return 0;
  return Math.max(index, 0);
}
function decodeChunk(data: string[], dest: Uint8Array) {
  const c1 = decodeChar(data[0]);
  const c2 = decodeChar(data[1]);
  const c3 = decodeChar(data[2]);
  const c4 = decodeChar(data[3]);
  const c5 = decodeChar(data[4]);
  const c6 = decodeChar(data[5]);
  const c7 = decodeChar(data[6]);
  const c8 = decodeChar(data[7]);

  dest[0] = byte((c1 << 3) | (c2 >> 2));
  dest[2] = byte((c2 << 5) | (c3 << 1) | (c4 >> 4));
  dest[3] = byte((c4 << 4) | (c5 >> 1));
  dest[5] = byte((c5 << 7) | (c6 << 2) | (c7 >> 3));
  dest[6] = byte((c7 << 5) | c8);
}

function byte(n: number) {
  return n & 0xff;
}

export function decode(data: string) {
  data = data
    .split("s+")
    .map((s) => s.trim())
    .join("");
  const dest = new Uint8Array((data.length * 5) / 8);
  const chars = data.split("");
  let coff = 0;
  let boff = 0;
  let fin = 5;
  while (fin == 5 && coff < chars.length && boff < dest.length) {
    const chunk = chars.slice(coff, coff + 8);
    if (chunk.indexOf("=") > -1) {
      chunk.splice(chunk.indexOf("="), 8);
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
          throw new Error("invalid padding");
      }
    }
    decodeChunk(chunk, dest.subarray(boff, boff + 5));
    coff += 8;
    boff += 5;
  }
  return dest.subarray(0, dest.length - 5 + fin);
}
