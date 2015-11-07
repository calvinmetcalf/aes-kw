var aes = require('browserify-aes');
var xor = require('buffer-xor/inplace');
var bufferEq = require('buffer-equal-constant-time');

var IV = new Buffer('A6A6A6A6A6A6A6A6', 'hex');
var EMPTY_BUF = new Buffer('');
function Encrypter(key, decipher) {
  if (decipher) {
    this.cipher = aes.createDecipheriv(getCipherName(key), key, EMPTY_BUF);
  } else {
    this.cipher = aes.createCipheriv(getCipherName(key), key, EMPTY_BUF);
  }
  this.cipher.setAutoPadding(false);
}
Encrypter.prototype.encrypt = function (iv, buf) {
  if (iv.length !== 8) {
    throw new Error('invalid iv length');
  }
  if (buf.length !== 8) {
    throw new Error('invalid data length');
  }
  this.cipher.update(iv);
  return this.cipher.update(buf);
}
Encrypter.prototype.done = function () {
  this.cipher.final();
}
function getCipherName(key) {
  switch (key.length) {
    case 16: return 'aes-128-ecb';
    case 24: return 'aes-192-ecb';
    case 32: return 'aes-256-ecb';
  }
}
function msb(b) {
  return b.slice(0, 8);
}
function lsb(b) {
  return b.slice(-8);
}
exports.encrypt = encrypt;
function encrypt(key, plaintext) {
  if (plaintext.length % 8) {
    throw new Error('must be 64 bit incriment');
  }
  var enc = new Encrypter(key);
  var j = -1;
  var i, b;
  var t = new Buffer(8);
  var a = IV;
  var n = plaintext.length / 8;
  var r = createR(plaintext);
  while (++j <= 5) {
    i = -1;
    while (++i < n) {
      b = enc.encrypt(a, r[i]);
      t.writeUIntBE((n * j) + i + 1, 0, 8);
      a = xor(msb(b), t);
      r[i] = lsb(b);
    }
  }
  enc.done();
  return Buffer.concat([a].concat(r));
}
exports.decrypt = decrypt;
function decrypt(key, ciphertext) {
  if (ciphertext.length % 8) {
    throw new Error('must be 64 bit incriment');
  }
  var enc = new Encrypter(key, true);
  var j = 6;
  var i, b;
  var t = new Buffer(8);
  var n = ciphertext.length / 8;
  var r = createR(ciphertext);
  var a = r[0];
  while (--j >= 0) {
    i = n;
    while (--i) {
      t.writeUIntBE(((n - 1)* j) + i, 0, 8);
      a = xor(a, t);
      b = enc.encrypt(a, r[i]);
      a = msb(b);
      r[i] = lsb(b);
    }
  }
  enc.done();
  if (!bufferEq(a, IV)) {
    throw new Error('unable to decrypt');
  }
  return Buffer.concat(r.slice(1));
}
function createR(buf) {
  var n = buf.length / 8;
  var out = new Array(n);
  var i = -1;
  while (++i < n) {
    out[i] = buf.slice(i * 8, (i + 1) * 8);
  }
  return out;
}
