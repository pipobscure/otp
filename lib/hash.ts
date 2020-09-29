import sha1 from "sha1";

export class Hash {
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
