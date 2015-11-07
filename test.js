'use strict';
var test = require('tape');
var kw = require('./');
var vectors = [
  {
    plaintext: '00112233445566778899AABBCCDDEEFF',
    key: '000102030405060708090A0B0C0D0E0F',
    ciphertext: '1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5'
  },
  {
    plaintext: '00112233445566778899AABBCCDDEEFF',
    key: '000102030405060708090A0B0C0D0E0F1011121314151617',
    ciphertext: '96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D'
  },
  {
    plaintext: '00112233445566778899AABBCCDDEEFF',
    key: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    ciphertext: '64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7'
  },
  {
    plaintext: '00112233445566778899AABBCCDDEEFF0001020304050607',
    key: '000102030405060708090A0B0C0D0E0F1011121314151617',
    ciphertext: '031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2'
  },
  {
    plaintext: '00112233445566778899AABBCCDDEEFF0001020304050607',
    key: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    ciphertext: 'A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1'
  },
  {
    plaintext: '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F',
    key: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    ciphertext: '28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21'
  }
];
test('it works', function (t) {
  var i = -1;
  while (++i < vectors.length) {
    testIt(t, i);
  }
});
function testIt(t, i) {
  t.test('vector:' + i, function (t) {
    t.plan(2);
    var key = new Buffer(vectors[i].key.replace(/\s/g, ''), 'hex');
    var plaintext = new Buffer(vectors[i].plaintext.replace(/\s/g, ''), 'hex');
    var ciphertext = new Buffer(vectors[i].ciphertext.replace(/\s/g, ''), 'hex');
    var encrypted = kw.encrypt(key, plaintext);
    t.equals(encrypted.toString('hex'), ciphertext.toString('hex'), 'encrypts');
    var decrypted = kw.decrypt(key, ciphertext);
    t.equals(decrypted.toString('hex'), plaintext.toString('hex'), 'decrypts');
  });
}
