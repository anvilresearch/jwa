'use strict'

/**
 * Dependencies
 * @ignore
 */
const base64url = require('base64url')
const crypto = require('@trust/webcrypto')
const TextEncoder = require('../text-encoder')

/**
 * RSASSA-PKCS1-v1_5
 */
class RSASSA_PKCS1_v1_5 {

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
   * @param {BufferSource} data
   *
   * @returns {Promise}
   */
  sign (key, data) {
    let algorithm = this.params

    // TODO
    //if (!this.sufficientKeySize()) {
    //  return Promise.reject(
    //    new Error(
    //      'A key size of 2048 bits or larger must be used with RSASSA-PKCS1-v1_5'
    //    )
    //  )
    //}

    data = new TextEncoder().encode(data)

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
   * @param {BufferSource} signature
   * @param {BufferSource} data
   *
   * @returns {Promise}
   */
  verify (key, signature, data) {
    let algorithm = this.params

    if (typeof signature === 'string') {
      signature = Uint8Array.from(base64url.toBuffer(signature))
    }

    if (typeof data === 'string') {
      data = new TextEncoder().encode(data)
    }
    // ...

    return crypto.subtle.verify(algorithm, key, signature, data)
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

    if (key.use === 'sig' || !key.d) {
      usages.push('verify')
    }

    if (key.use === 'enc') {
      // TODO: handle encryption keys
      return Promise.resolve(key)
    }

    if (key.key_ops) {
      usages = key.key_ops
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

      /* / construct the key operations array from key_ops and use fields
      let usages = key['key_ops'] || []
      // duplicate key operation values MUST NOT be present
      if (!(usages.length === new Set(usages).size)) {
        throw new Error('Invalid key operations key parameter')
      }
      // handle use parameter for public keys
      if (key.use === 'sig') {
        usages.push('verify')
      }
      if (key.use === 'enc') {
        usages.push('encrypt')
      }
      // infer usages from kty
      if (jwk.kty === 'EC') {
        // Elliptic Curve is used
        // if d parameter is present, this is a private key
        if (jwk.d) {
          usages.push('sign')
        } else {
          usages.push('verify')
        }
      } else if(jwk.kty === 'RSA') {
        // RSA is used
        if (jwk.d) {
          if (!usages.includes('sign')) {
            usages.push('sign')
          }
        } else if (!usages.includes('verify')) {
          usages.push('verify')
        }
      } else if(jwk.kty === 'oct') {
        // if it was none of the previous two store
        // the JWA name from the alg field of the key
        algorithm = key.alg
      }*/
  }
}

/**
 * Export
 */
module.exports = RSASSA_PKCS1_v1_5
