'use strict'

/**
 * Dependencies
 * @ignore
 */
const base64url = require('base64url')
const crypto = require('@trust/webcrypto')
const TextEncoder = require('../text-encoder')

/**
 * AES-GCM
 */
class AES_GCM {

  /**
   * constructor
   *
   * @param {string} bitlength
   */
  constructor (params) {
    this.params = params
  }

  /**
   * encrypt
   *
   * @description
   * Encrypt data and associated additional authentication data using AES-GCM.
   *
   * @param {CryptoKey} key
   * @param {BufferSource} data
   * @param {BufferSource} aad
   *
   * @returns {Promise}
   */
  encrypt (key, data, aad) {
    let algorithm = Object.assign({}, this.params)
    // ensure each encryption has a new iv
    Object.defineProperty(algorithm, 'iv', {
      enumerable: false,
      configurable: true,
      value: crypto.getRandomValues(new Uint8Array(16))
    })
    Object.defineProperty(algorithm, 'aad', {
      enumerable: false,
      configurable: true,
      value: aad
    })

    data = new TextEncoder().encode(data)

    return crypto.subtle
      .encrypt(algorithm, key, data)
      .then(result => {
        // split the result into ciphertext and tag
        let tagLength = (algorithm.tagLength / 8) || 16
        let tag = result.slice(result.byteLength - tagLength)
        let ciphertext = result.slice(0, -tagLength)

        return {
          iv: base64url(Buffer.from(algorithm.iv)),
          ciphertext: base64url(Buffer.from(ciphertext)),
          tag: base64url(Buffer.from(tag))
        }
      })
  }

  /**
   * decrypt
   *
   * @description
   * Decrypt the given data (authenticated with the aad) encrypted with iv,
   * checking for integrity using the tag provided.
   *
   * @param {CryptoKey} key
   * @param {string} ciphertext
   * @param {string} iv
   * @param {string} tag
   * @param {string} aad
   *
   * @return {Promise}
   */
  decrypt (key, ciphertext, iv, tag, aad) {
    let algorithm = this.params
    Object.defineProperty(algorithm, 'iv', {
      enumerable: false,
      configurable: true,
      value: Uint8Array.from(base64url.toBuffer(iv))
    })
    Object.defineProperty(algorithm, 'aad', {
      enumerable: false,
      configurable: true,
      value: aad
    })

    // Decode ciphertext and tag from base64
    ciphertext = base64url.toBuffer(ciphertext)
    tag = base64url.toBuffer(tag)

    // Concatenate the two buffers
    let data = new Uint8Array(ciphertext.length + tag.length)
    data.set(new Uint8Array(ciphertext), 0)
    data.set(new Uint8Array(tag), ciphertext.length)
    data = data.buffer

    return crypto.subtle
      .decrypt(algorithm, key, data)
      .then(plaintext => Buffer.from(plaintext).toString())
  }

  /**
   * encryptKey
   *
   * @description
   * Wrap key using AES-GCM.
   *
   * @param {CryptoKey} key
   * @param {CryptoKey} wrappingKey
   *
   * @returns {Promise}
   */
  encryptKey (key, wrappingKey) {
    let algorithm = this.params
    return Promise.resolve()
    // return crypto.subtle
      // .wrapKey('jwk', key, wrappingKey, algorithm)
  }

  /**
   * decryptKey
   *
   * @description
   * Unwrap key using AES-GCM.
   *
   * @param {string|Buffer} wrappedKey
   * @param {CryptoKey} unwrappingKey
   * @param {string} unwrappedKeyAlg
   *
   * @returns {Promise}
   */
  decryptKey (wrappedKey, unwrappingKey, unwrappedKeyAlg) {
    let algorithm = this.params
    return Promise.resolve()
    // return crypto.subtle
      // .unwrapKey('jwk', wrappedKey, unwrappingKey, algorithm, unwrappedKeyAlgorithm, true, keyUsages)
  }


  /**
   * Generate Key
   *
   * @description
   * Generate key for AES-GCM.
   *
   * @param {boolean} extractable
   * @param {Array} key_ops
   * @param {Object} options
   *
   * @return {Promise}
   */
  generateKey (extractable, key_ops, options = {}) {
    let algorithm = this.params
    return crypto.subtle
      .generateKey(algorithm, extractable, key_ops)
  }

  /**
   * Import
   *
   * @description
   * Import a key in JWK format.
   *
   * @param {CryptoKey} key
   *
   * @return {Promise}
   */
  importKey (key) {
    let jwk = Object.assign({}, key)
    let algorithm = this.params
    let usages = key['key_ops'] || ['encrypt', 'decrypt']

    return crypto.subtle
      .importKey('jwk', jwk, algorithm, true, usages)
      .then(cryptoKey => {
        Object.defineProperty(jwk, 'cryptoKey', {
          enumerable: false,
          value: cryptoKey
        })

        return jwk
      })
  }

}
/**
 * Export
 */
module.exports = AES_GCM
