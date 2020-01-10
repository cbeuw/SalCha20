'use strict'
/**
 * Created by Mykola Bubelich
 * 2017-01-25
 */

import test from 'tape'
import JSChacha20 from '../src/jschacha20.mjs'

/**
 * Encrypt / Decrypt
 */
test('Encrypt and decrypt for 256 byte should be same', tape => {
  const crypto = require('crypto')

  const key = new Uint8Array(crypto.randomBytes(32))
  const nonce = new Uint8Array(crypto.randomBytes(8))
  const data = new Uint8Array(crypto.randomBytes(4096))

  const encoder = new JSChacha20(key, nonce)
  const decoder = new JSChacha20(key, nonce)

  const encr = encoder.encrypt(data)
  const decr = decoder.decrypt(encr)

  tape.deepEqual(encoder.param, decoder.param, 'Parameters should be equivalent')
  tape.deepEqual(data, decr, 'Decrypted data should be the same as input')
  tape.deepEqual([64, 64], [encoder.param[12], decoder.param[12]], 'Counter should be equal 64')

  tape.end()
})

// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
test('Key stream should be equal to the reference', tape => {
  const nullBlock = new Uint8Array(Array(64).fill(0))

  const key = new Uint8Array(Array(32).fill(0))

  const nonce = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0])

  const cipher = new JSChacha20(key, nonce)

  const expStream = new Uint8Array([
    0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
    0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7, 
    0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 
    0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
  ])

  tape.deepEqual(cipher.encrypt(nullBlock), expStream, 'Key stream should be equal to the reference')

  tape.end()
})

