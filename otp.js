/*
** © 2013 by Philipp Dunkel <p.dunkel@me.com>. Licensed unde MIT-License
*/

module.exports = OTP;

var Crypto = require('crypto');
var Base32 = require('thirty-two');

function OTP(options) {
  if ('string' === typeof options) return OTP.parse(options);
  if (!(this instanceof OTP)) return new OTP(options);
  options = clone(options || {});
  options.name = String(options.name || 'OTP-Authentication').split(/[^\w|_|-|@]/).join('');
  options.keySize =  isNaN(options.keySize) ? 32 : options.keySize;
  options.codeLength = isNaN(options.codeLength) ? 6 : options.codeLength;
  options.secret = options.secret || generateKey(options.keySize);
  options.epoch = (isNaN(options.epoch) ? 0 : options.epoch) * 1000;
  options.timeSlice = (isNaN(options.timeSlice) ? 30 : options.timeSlice) * 1000;
  Object.keys(OTP.prototype).forEach(function(method) {
    if ('function' !== typeof OTP.prototype[method]) return;
    Object.defineProperty(this, method, {
      value: OTP.prototype[method].bind(this, options)
    });
  }.bind(this));

  Object.defineProperty(this, 'secret', {
    value:options.secret,
    enumerable:true
  });
  Object.defineProperty(this, 'totpURL', {
    value:['otpauth://totp/', options.name, '?secret=', encodeURIComponent(this.secret) ].join(''),
    enumerable:true
  });
  Object.defineProperty(this, 'hotpURL', {
    value:['otpauth://hotp/', options.name, '?secret=', encodeURIComponent(this.secret) ].join(''),
    enumerable:true
  });
}

function generateKey(length) {
  var set = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz!@#$%^&*()<>?/[]{},.:;';
  var res = '';
  while(res.length < length) {
    res += set[Math.floor(Math.random() * set.length)];
  }
  return Base32.encode(res).replace(/=/g, '');;
}

OTP.parse = function(str, options) {
  options = clone(options || {});
  str = String(str || '');
  var url = /^otpauth:\/\/[t|h]opt\/([\s|\S]+?)\?secret=([\s|\S]+)$/.exec(str);
  if (url) {
    options.name = url[1];
    options.secret = url[2];
  } else {
    options.secret = str;
  }
  return new OTP(options);
};

OTP.prototype.hotp = function(options, counter) {
  var hmac = Crypto.createHmac('sha1', new Buffer(Base32.decode(options.secret)));
  hmac = new Buffer(hmac.update(UInt64Buffer(counter)).digest('hex'), 'hex');
  var offset = hmac[19] & 0xf;
  var code = String((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 | (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff));
  code = ((new Array(options.codeLength + 1)).join('0')+code).slice(-1 * options.codeLength);
  return code;
};

function UInt64Buffer(num) {
  var res = [];
  while (res.length < 8) {
    res.unshift(num & 0xFF);
    num = num >> 8;
  }
  return new Buffer(res);
}

OTP.prototype.totp = function(options) {
  var now = isNaN(options.now) ? Date.now() : options.now;
  var counter = Math.floor((now - options.epoch) / options.timeSlice);
  return this.hotp(counter);
};
OTP.prototype.toString = function() {
  return '[object OTP]';
};
OTP.classID = 'OTP{@phidelta}';
OTP.prototype.toJSON = function(options) {
  var res = {
    'class':OTP.classID,
    name:options.name,
    keySize:options.keySize,
    codeLength:options.codeLength,
    secret:this.secret,
    epoch:options.epoch / 1000,
    timeSlice:options.timeSlice / 1000
  };
  return res;
};
OTP.reviveJSON = function(key, val) {
  if (('object' !== typeof val) || (null === val) || (val['class'] !== OTP.classID)) return val;
  return OTP(val);
};

function clone(obj) {
  if ('object' !== typeof obj) {
    return obj;
  } else if (Array.isArray(obj)) {
    return obj.map(clone);
  } else if (obj instanceof Date) {
    return new Date(obj.getTime());
  }

  var res = {};
  Object.keys(obj).forEach(function(key) {
    res[key] = clone(obj[key]);
  });
  return res;
}
