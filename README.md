# OTP [![NPM](https://nodei.co/npm/otp.png)](https://nodei.co/npm/otp/)

This is a utility to work with Google-Authenticator and compatible OTP-Mechanisms.

- HOTP (HMAC-Based One-Time Password Algorithm): [RFC 4226](http://tools.ietf.org/html/rfc4226)
- TOTP (Time-Based One-Time Password Algorithm): [RFC 6238](http://tools.ietf.org/html/rfc6238)

## Main Function

    var otp = new OTP(options);
    otp.hotp(counter); // Generates an OTP using HTOP method
    otp.totp(); // Generates an OTP using TOTP method
    otp.secret; // Base32 encoded secret
    otp.totpURL; // A TOTP-URL that can be used with Google-Authenticator
    otp.hotpURL; // A HOTP-URL that can be used with Google-Authenticator

Options can have the following properties:

- **name**: A name used in generating URLs
- **keySize**: The size of the OTP-Key (default 64) (possible values: 64 & 128)
- **codeLength**: The length of the code generated (default 6)
- **secret**: The secret (either a Buffer of Base32-encoded String)
- **epoch**: The seconds since Unix-Epoch to use as a base for calculating the TOTP (default 0)
- **timeSlice**: The timeslice to use for calculating counter from time in seconds (default 30)

## OTP.parse(string)

Parses an OTP-URL or Base32-Encoded Secret.

## OTP.reviveJSON

A JSON-reviver to revive stringified OTP objects

## License (MIT)

Copyright (C) 2013-2020 Philipp Dunkel

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
