# SalCha20
Pure JavaScript Salsa20, Chacha20 and Chacha20-Poly1305 implementations

### Implementation derived from 
- https://cr.yp.to/snuffle/salsa20/ref/salsa20.c
- [The Salsa20 family of stream ciphers](https://cr.yp.to/snuffle/salsafamily-20071225.pdf)
- [Salsa20 specification](https://cr.yp.to/snuffle/spec.pdf)
- [Salsa20 design](https://cr.yp.to/snuffle/design.pdf)
- [Chacha20 and Poly1305 Spec](https://tools.ietf.org/html/rfc7539)
- [Poly1305 and AEAD implementation](https://github.com/devi/chacha20poly1305/blob/master/chacha20poly1305.js)

### Usage
Encrypt message with key and nonce
```javascript
import JSSalsa20 from "js-salsa20";

const key = Uint8Array([...]); // 32 bytes key
const nonce = Uint8Array([...]); // 8 bytes nonce
const message = Uint8Array([...]); // some data as bytes array

// Encrypt //
const encrypt = new JSSalsa20(key, nonce).encrypt(message);

// now encrypt contains bytes array of encrypted message
```

Decrypt encrypted message with key and nonce
```javascript
import JSSalsa20 from "js-salsa20";

const key = Uint8Array([...]); // 32 bytes key
const nonce = Uint8Array([...]); // 8 bytes nonce
const encrypt = Uint8Array([...]); // some data as bytes array

// Encrypt //
const message = new JSSalsa20(key, nonce).decrypt(encrypt);

// now message contains bytes array of original message
```

That all. If something happens, Error will be thrown.
More examples you can find in tests files.
