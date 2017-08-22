'use strict'

/**
 * Dependencies
 * @ignore
 */
const base64url = require('base64url')
const crypto = require('@trust/webcrypto')
const TextEncoder = require('../text-encoder')

/**
 * ECDSA
 */
class ECDSA {

  /**
   * constructor
   *
   * @param {string} bitlength
   */
  constructor (params) {
    this.params = params
  }

  /**
   * sign
   *
   * @description
   * Generate a digital signature for a given input and private key.
   *
   * @param {CryptoKey} key
   * @param {(BufferSource|String)} data
   *
   * @returns {Promise}
   */
  sign (key, data) {
    let algorithm = this.params

    // Normalize data input
    if (typeof data === 'string') {
      data = new TextEncoder().encode(data)
    }

    return crypto.subtle
      .sign(algorithm, key, data)
      .then(signature => base64url(Buffer.from(signature)))
  }

  /**
   * verify
   *
   * @description
   * Verify a digital signature for a given input and private key.
   *
   * @param {CryptoKey} key
   * @param {(BufferSource|String)} signature - Base64URL encoded signature.
   * @param {(BufferSource|String)} data
   *
   * @returns {Promise}
   */
  verify (key, signature, data) {
    let algorithm = this.params

    // Normalize signature
    if (typeof signature === 'string') {
      signature = Uint8Array.from(base64url.toBuffer(signature))
    }

    // Normalize data to be verified
    if (typeof data === 'string') {
      data = new TextEncoder().encode(data)
    }

    return crypto.subtle
      .verify(algorithm, key, signature, data)
  }

  /**
   * Generate Key
   *
   * @description
   * Generate key pair for ECDSA.
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
    // handle use parameter for public keys
    if (key.use === 'sig') {
      usages.push('verify')
    }
    if (key.use === 'enc') {
      return Promise.reject(new Error('Invalid use key parameter'))
    }

    // Elliptic Curve is used
    // if d parameter is present, this is a private key
    if (jwk.d) {
      if (!usages.includes('sign')) {
        usages.push('sign')
      }
    } else if (!usages.includes('verify')) {
      usages.push('verify')
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
}

/**
 * Export
 */
module.exports = ECDSA
