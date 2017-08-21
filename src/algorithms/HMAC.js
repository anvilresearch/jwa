'use strict'

/**
 * Dependencies
 * @ignore
 */
const base64url = require('base64url')
const crypto = require('@trust/webcrypto')
const TextEncoder = require('../text-encoder')

/**
 * HMAC with SHA-2 Functions
 */
class HMAC {

  /**
   * Constructor
   *
   * @param {string} bitlength
   */
  constructor (params) {
    this.params = params
  }

  /**
   * Sign
   *
   * @description
   * Generate a hash-based message authentication code for a
   * given input and key. Enforce the key length is equal to
   * or greater than the bitlength.
   *
   * @param {CryptoKey} key
   * @param {(BufferSource|String)} data
   *
   * @returns {string}
   */
  sign (key, data) {
    let algorithm = this.params

    // TODO: validate key length

    // String input
    if (typeof data === 'string') {
      data = new TextEncoder().encode(data)
    }

    return crypto.subtle
      .sign(algorithm, key, data)
      .then(signature => base64url(Buffer.from(signature)))
  }

  /**
   * Verify
   *
   * @description
   * Verify a digital signature for a given input and private key.
   *
   * @param {CryptoKey} key
   * @param {(BufferSource|String)} signature - Base64URL encoded signature.
   * @param {(BufferSource|String)} data
   *
   * @returns {Boolean}
   */
  verify (key, signature, data) {
    let algorithm = this.params

    if (typeof signature === 'string') {
      signature = Uint8Array.from(base64url.toBuffer(signature))
    }

    if (typeof data === 'string') {
      data = new TextEncoder().encode(data)
    }

    return crypto.subtle.verify(algorithm, key, signature, data)
  }

  /**
   * Generate Key
   *
   * @description
   * Generate key for HMAC.
   *
   * @param {boolean} extractable
   * @param {Array} key_ops
   * @param {Object} options
   *
   * @return {Promise}
   */
  generateKey (extractable, key_ops, options = {}) {
    let params = this.params
    return crypto.subtle
      .generateKey(params, extractable, key_ops)
  }


  /**
   * importKey
   *
   * @param {JWK} key
   * @returns {Promise}
   */
  importKey (key) {
    let jwk = Object.assign({}, key)
    let algorithm = this.params
    let usages = key['key_ops'] || []
    // duplicate key operation values MUST NOT be present
    if (!(usages.length === new Set(usages).size)) {
      return Promise.reject(new Error('Invalid key operations key parameter'))
    }

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

  /**
   * Assert Sufficient Key Length
   *
   * @description Assert that the key length is sufficient
   * @param {string} key
   */
  // assertSufficientKeyLength (key) {
  //   if (key.length < this.bitlength) {
  //     throw new Error('The key is too short.')
  //   }
  // }
}

/**
 * Export
 */
module.exports = HMAC
