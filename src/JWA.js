/**
 * Dependencies
 *
 * TODO
 * - switch between Node.js webcrypto package and browser implementation
 */
const base64url = require('base64url')
const supportedAlgorithms = require('./algorithms')
const {NotSupportedError} = require('./errors')
const crypto = require('@trust/webcrypto')

/**
 * JWA
 * https://tools.ietf.org/html/rfc7518
 */
class JWA {

  /**
   * Sign
   *
   * @description
   * Create a digital signature.
   *
   * @param {string} alg
   * @param {CryptoKey} key
   * @param {string|Buffer} data
   *
   * @return {Promise}
   */
  static sign (alg, key, data) {
    // normalize the algorithm
    let normalizedAlgorithm = supportedAlgorithms.normalize('sign', alg)

    // validate algorithm is supported
    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(new NotSupportedError(alg))
    }

    // validate type of key
    // TODO
    //  - is the key suitable for the algorithm?
    //  - does that get validated in webcrypto?
    //if (key instanceof CryptoKey) {
    //  return Promise.reject(new InvalidKeyError())
    //}

    // sign the data
    return normalizedAlgorithm.sign(key, data)
  }

  /**
   * Verify
   *
   * @description
   * Verify a digital signature.
   *
   * @param {string} alg
   * @param {CryptoKey} privateKey
   * @param {string|Buffer} signature
   * @param {string|Buffer} data
   *
   * @return {Promise}
   */
  static verify (alg, key, signature, data) {
    let normalizedAlgorithm = supportedAlgorithms.normalize('verify', alg)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(new NotSupportedError(alg))
    }

    // TODO
    // validate publicKey

    // verify the signature
    return normalizedAlgorithm.verify(key, signature, data)
  }

  /**
   * Encrypt
   */

  /**
   * Decrypt
   */

  /**
   * Import
   */
  static importKey (key) {
    let { alg } = key
    let normalizedAlgorithm = supportedAlgorithms.normalize('importKey', alg)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(new NotSupportedError(alg))
    }

    return normalizedAlgorithm.importKey(key)
  }

  /**
   * Export
   */
  static exportKey (format, key) {
    return crypto.subtle.exportKey(format, key)
  }

  /**
   * Generate
   */
  static generateKey (alg, descriptor) {
    let { key_ops, modulusLength, extractable = true } = descriptor
    let normalizedAlgorithm = supportedAlgorithms.normalize('generateKey', alg)

    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(new NotSupportedError(alg))
    }

    if (!key_ops) {
      return Promise.reject(new DataError('Invalid key_ops'))
    }

    // RSA
    if (modulusLength) {
      normalizedAlgorithm.params.modulusLength = modulusLength
    }

    return normalizedAlgorithm.generateKey(extractable, key_ops)
  }
}

/**
 * Export
 */
module.exports = JWA
