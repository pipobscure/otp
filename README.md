# OTP [![NPM](https://nodei.co/npm/otp.png)](https://nodei.co/npm/otp/)

This is a utility to work with Google-Authenticator and compatible OTP-Mechanisms.

- HOTP (HMAC-Based One-Time Password Algorithm): [RFC 4226](http://tools.ietf.org/html/rfc4226)
- TOTP (Time-Based One-Time Password Algorithm): [RFC 6238](http://tools.ietf.org/html/rfc6238)

## Main Function

    var otp = new OTP(options);
    otp.hotp(counter); // Generates an OTP using HTOP method (Promise)
    otp.totp(); // Generates an OTP using TOTP method (Promise)
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

## License

© 2025 Philipp Dunkel <pip@pipobscure.com> [EUPL v1.2](https://eupl.eu/1.2/en)
