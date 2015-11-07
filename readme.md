AES-KW
===

```
npm install --save aes-kw
```

Implementation of AES-KW algorithm as per
[RFC 3394](http://www.ietf.org/rfc/rfc3394.txt).


```js
var kw = require('aes-kw');

var encrypted = kw.encrypt(key, keyMaterial);
var decrypted = kw.decrypt(key, encrypted);
assert(keyMaterial === decrypted);
```

The encryption key, the key material to encrypt and the encrypted data must all
be buffers.  The key must be 16, 24, or 32 bytes long and the keyMaterial and
encrypted data must be a multiple of 8 bytes.
