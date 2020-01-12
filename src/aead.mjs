// https://github.com/devi/chacha20poly1305/blob/master/chacha20poly1305.js
// Written in 2014 by Devi Mandiri. Public domain.

function store64(dst, num) {
    var hi = 0, lo = num >>> 0;
    if ((+(Math.abs(num))) >= 1) {
      if (num > 0) {
        hi = ((Math.min((+(Math.floor(num/4294967296))), 4294967295))|0) >>> 0;
      } else {
        hi = (~~((+(Math.ceil((num - +(((~~(num)))>>>0))/4294967296))))) >>> 0;
      }
    }
    dst.push(lo & 0xff); lo >>>= 8;
    dst.push(lo & 0xff); lo >>>= 8;
    dst.push(lo & 0xff); lo >>>= 8;
    dst.push(lo & 0xff);
    dst.push(hi & 0xff); hi >>>= 8;
    dst.push(hi & 0xff); hi >>>= 8;
    dst.push(hi & 0xff); hi >>>= 8;
    dst.push(hi & 0xff);
  }
  
  function aead_mac(polykey, data, ciphertext) {
    var dlen = data.length,
        clen = ciphertext.length,
        dpad = dlen % 16,
        cpad = clen % 16,
        m = [], i;
  
    for (i = 0; i < dlen; i++) m.push(data[i]);
  
    if (dpad !== 0) {
      for (i = (16 - dpad); i--;) m.push(0);
    }
  
    for (i = 0; i < clen; i++) m.push(ciphertext[i]);
  
    if (cpad !== 0) {
      for (i = (16 - cpad); i--;) m.push(0);
    }
  
    store64(m, dlen);
    store64(m, clen);
  
    return poly1305_auth(m, m.length, polykey);
  }
  
  function aead_encrypt(key, nonce, plaintext, data) {
    var plen = plaintext.length,
        buf = new Uint8Array(plen),
        ciphertext = new Uint8Array(plen),
        polykey = new Uint8Array(64),
        ctx = new Chacha20(key, nonce, 0);
  
    ctx.keystream(polykey, 64);
  
    ctx.keystream(buf, plen);
  
    for (var i = 0; i < plen; i++) {
      ciphertext[i] = buf[i] ^ plaintext[i];
    }
  
    return [ciphertext, aead_mac(polykey, data, ciphertext)];
  }
  
  function aead_decrypt(key, nonce, ciphertext, data, mac) {
    var plen = ciphertext.length,
        buf = new Uint8Array(plen),
        plaintext = new Uint8Array(plen),
        polykey = new Uint8Array(64),
        ctx = new Chacha20(key, nonce, 0);
  
    ctx.keystream(polykey, 64);
  
    var tag = aead_mac(polykey, data, ciphertext);
  
    if (poly1305_verify(tag, mac) !== 1) return false;
  
    ctx.keystream(buf, plen);
  
    for (var i = 0; i < plen; i++) {
      plaintext[i] = buf[i] ^ ciphertext[i];
    }
  
    return plaintext;
  }
  