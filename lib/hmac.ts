import { Hash } from "./hash";

const zeroBuffer = new Uint8Array(new Array(128).fill(0));

export class Hmac {
  constructor(blocksize: number, key: Uint8Array) {
    if (blocksize !== 128 && blocksize !== 64) {
      throw new Error("blocksize must be either 64 for or 128 , but was:" + blocksize);
    }
    this.key = rekey(key, blocksize);
    this.opad = new Uint8Array(new Array(blocksize).fill(0));
    this.ipad = new Uint8Array(new Array(blocksize).fill(0));

    for (var i = 0; i < blocksize; i++) {
      this.ipad[i] = this.key[i] ^ 0x36;
      this.opad[i] = this.key[i] ^ 0x5c;
    }

    this.hash = new Hash();
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
    res.set(zeroBuffer, key.length);
    return res;
  }
  return key;
}
