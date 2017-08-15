/**
 * Dependencies
 *
 * TODO
 * - switch between Node.js webcrypto package and browser implementation
 */
const base64url = require('base64url')
const supportedAlgorithms = require('./algorithms')
const { NotSupportedError } = require('./errors')
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
    // normalize the algorithm
    let normalizedAlgorithm = supportedAlgorithms.normalize('verify', alg)

    // validate algorithm is supported
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
   *
   * @description
   * Encrypt data and associated additional authentication data.
   *
   * @param {string} alg
   * @param {CryptoKey} key
   * @param {string\Buffer} data
   * @param {string|Buffer} aad
   *
   * @return {Promise}
   */
   static encrypt (alg, key, data, aad) {
     // normalize the algorithm
    let normalizedAlgorithm = supportedAlgorithms.normalize('encrypt', alg)

    // validate algorithm is supported
    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(new NotSupportedError(alg))
    }

    // encrypt the data
    return normalizedAlgorithm.encrypt(key, data, aad)
  }

  /**
   * Decrypt
   *
   * @description
   * Decrypt the given data (authenticated with the aad) encrypted with iv,
   * checking for integrity using the tag provided.
   *
   * @param {string} alg
   * @param {CryptoKey} key
   * @param {string\Buffer} data
   * @param {string|Buffer} iv
   * @param {string|Buffer} tag
   * @param {string|Buffer} aad
   *
   * @return {Promise}
   */
   static decrypt (alg, key, data, iv, tag, aad) {
     // normalize the algorithm
    let normalizedAlgorithm = supportedAlgorithms.normalize('decrypt', alg)

    // validate algorithm is supported
    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(new NotSupportedError(alg))
    }

    // decrypt the data and recover the contents
    return normalizedAlgorithm.decrypt(key, data, iv, tag, aad)
  }

  /**
   * wrapKey
   *
   * @description
   *
   * @param {KeyFormat} format
   * @param {CryptoKey} key
   * @param {CryptoKey} wrappingKey
   * @param {AlgorithmIdentifier} wrapAlgorithm
   *
   * @returns {Promise}
   */
  static wrapKey () {}

  /**
   * unwrapKey
   *
   * @description
   *
   * @param {KeyFormat} format
   * @param {BufferSource} wrappedKey
   * @param {CryptoKey} unwrappingKey
   * @param {AlgorithmIdentifier} unwrapAlgorithm
   * @param {AlgorithmIdentifier} unwrappedKeyAlgorithm
   * @param {Boolean} extractable
   * @param {Array} keyUsages
   *
   * @returns {Promise}
   */
  static unwrapKey () {}

  /**
   * Generate Key
   *
   * @description
   * Generate key / key pair based on the specified attributes.
   *
   * @param {string} alg
   * @param {Object} options
   *
   * @return {Promise}
   */
  static generateKey (alg, options = {}) {
    // normalize the algorithm
    let normalizedAlgorithm = supportedAlgorithms.normalize('generateKey', alg)

    // validate algorithm is supported
    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(new NotSupportedError(alg))
    }

    let { key_ops, extractable = true } = options

    if (!key_ops) {
      return Promise.reject(new DataError('Invalid key_ops'))
    }

    return normalizedAlgorithm.generateKey(extractable, key_ops, options)
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
  static importKey (key) {
    // map the JWA alg name to the corresponding object
    let normalizedAlgorithm = supportedAlgorithms.normalize('importKey', key.alg)

    // validate algorithm is supported
    if (normalizedAlgorithm instanceof Error) {
      return Promise.reject(new NotSupportedError(alg))
    }

    return normalizedAlgorithm.importKey(key)
  }
  
  /**
   * Export key
   *
   * @description
   * Export the key in the specified format.
   *
   * @param {string} format
   * @param {CryptoKey} key
   *
   * @return {Promise}
   */
  static exportKey (format, key) {
    return crypto.subtle.exportKey(format, key)
  }
}

/**
 * Export
 */
module.exports = JWA
