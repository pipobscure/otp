export interface OTPOptions {
  name: string;
  keySize: number;
  codeLength: number;
  secret: string;
  epoch: number;
  timeSlice: number;
}
export default class OTP {
  constructor(options?: string | Partial<OTPOptions>);
  private readonly options;
  readonly hotp: (counter: number) => string;
  readonly totp: (now: number) => string;
  get name(): string;
  get secret(): string;
  get totpURL(): string;
  get hotpURL(): string;
  toString(): string;
  toJSON(): {
    class: string;
  } & OTPOptions;
  static reviveJSON(_: string, val: any): any;
  static readonly classID = "OTP{@pipobscure}";
  static parse(urlstr?: string, options?: Partial<OTPOptions>): OTP;
}
