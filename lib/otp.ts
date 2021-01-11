import * as Base32 from "./base32";
import { Hmac } from "./hmac";

export interface OTPOptions {
  name: string;
  keySize: number;
  codeLength: number;
  secret: string;
  epoch: number;
  timeSlice: number;
}

export default class OTP {
  constructor(options: string | Partial<OTPOptions> = {}) {
    if ("string" === typeof options) return OTP.parse(options);
    options = Object.assign({}, options);
    options.name = `${options.name || "OTP-Authentication"}`.split(/[^\w|_|-|@]/).join("");
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
    return ["otpauth://totp/", this.name, "?secret=", encodeURIComponent(this.secret)].join("");
  }
  get hotpURL() {
    return ["otpauth://hotp/", this.name, "?secret=", encodeURIComponent(this.secret)].join("");
  }

  toString() {
    return "[object OTP]";
  }
  toJSON() {
    return Object.assign({ class: OTP.classID }, this.options);
  }
  static reviveJSON(_: string, val: any) {
    if ("object" !== typeof val || null === val || val["class"] !== OTP.classID) return val;
    const { name, keySize, codeLength, secret, epoch, timeSlice } = val;
    return new OTP({ name, keySize, codeLength, secret, epoch, timeSlice });
  }
  static readonly classID = "OTP{@pipobscure}";
  static parse(urlstr: string = "", options: Partial<OTPOptions> = {}) {
    options = Object.assign({}, options);
    const urlbits = /^otpauth:\/\/[t|h]otp\/([\s|\S]+?)\?secret=([\s|\S]+)$/.exec(urlstr);
    if (urlbits) {
      options.name = urlbits[1];
      options.secret = Base32.encode(Base32.decode(urlbits[2]));
    } else {
      options.secret = Base32.encode(Base32.decode(urlstr));
    }
    return new OTP(options);
  }
}

function hotp(options: OTPOptions, counter: number): string {
  const digest = new Hmac(options.keySize, Base32.decode(options.secret)).update(UInt64Buffer(counter)).digest();
  const offset = digest[19] & 0xf;
  const code = String(((digest[offset] & 0x7f) << 24) | ((digest[offset + 1] & 0xff) << 16) | ((digest[offset + 2] & 0xff) << 8) | (digest[offset + 3] & 0xff));
  return `${new Array(options.codeLength).fill("0")}${code}`.slice(-1 * options.codeLength);
}
function totp(options: OTPOptions, now: number = Date.now()): string {
  const counter = Math.floor((now - options.epoch * 1000) / (options.timeSlice * 1000));
  return hotp(options, counter);
}

function generateKey(length: number) {
  const key = new Uint8Array(new Array(length).fill(0).map(() => Math.floor(Math.random() * 256)));
  return Base32.encode(key).replace(/=/g, "");
}
function UInt64Buffer(num: number) {
  const res = Buffer.alloc(8);
  res.writeBigUInt64BE(BigInt(num));
  return res;
}
