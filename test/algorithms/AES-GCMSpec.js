'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')

/**
 * Assertions
 */
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const crypto = require('@trust/webcrypto')
const base64url = require('base64url')
const AES_GCM = require('../../src/algorithms/AES-GCM')

/**
 * Tests
 */
describe('AES-GCM', () => {

  let alg, ec, encryptedData
  const A256GCMKey = {
    kty: "oct",
    k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
    alg: "A256GCM",
    ext: true,
  }

  before(() => {
    alg = { name: 'AES-GCM', length: 128, tagLength: 128 }
    ec = new AES_GCM(alg)
  })

  /**
   * constructor
   */
  describe('constructor', () => {
    it('should set params', () => {
      ec.params.should.equal(alg)
    })
  })

  /**
   * encrypt
   */
  describe('encrypt', () => {
    let data, key

    before(() => {
      let promise = crypto.subtle.importKey(
                    "jwk",
                    A256GCMKey,
                    {   // algorithm
                      name: "AES-GCM",
                    },
                    false, // extractable
                    ["encrypt", "decrypt"] // usages
                  )
      data = 'encrypted with Chrome webcrypto'
      promise.then(result => {
        key = result
      })
    })

    it('should return a promise', () => {
      ec.encrypt(key, data).should.be.instanceof(Promise)
    })

    it('should perform encryption', () => {
      return ec.encrypt(key, data)
        .then(result => {
          encryptedData = result
          result.should.not.eql(Buffer.from(data))
        })
    })

    it('should contain ciphertext, iv and tag', () => {
      return ec.encrypt(key, data)
        .then(result => {
          result.should.have.property('ciphertext')
          result.should.have.property('iv')
          result.should.have.property('tag')
      })
    })
  })

  /**
   * decrypt
   */
  describe('decrypt', () => {
    let key, data

    before(() => {
      let promise = crypto.subtle.importKey(
                   "jwk",
                   A256GCMKey,
                   {   // algorithm
                     name: "AES-GCM",
                   },
                   false, // extractable
                   ["encrypt", "decrypt"] // usages
                 )
      data = 'encrypted with Chrome webcrypto'
      promise.then(result => { key = result })
    })

    it('should return a promise', () => {
      ec.decrypt(key, encryptedData.ciphertext,
        encryptedData.iv, encryptedData.tag)
      .should.be.instanceof(Promise)
    })

    it('should recover plaintext', () => {
      return ec.decrypt(key, encryptedData.ciphertext,
        encryptedData.iv, encryptedData.tag)
        .then(result => {
          result.should.eql(data)
        })
    })

  })

  /**
   * encryptKey
   */
  describe('encryptKey', () => {

  })

  /**
   * decryptKey
   */
  describe('decryptKey', () => {

  })

  /**
   * generateKey
   */
  describe('generateKey', () => {
    let promise, result

    before(() => {
      promise = ec.generateKey(true, ["encrypt", "decrypt"])
      promise.then(jwk => {
        result = jwk
      })
    })

    it('should return a promise', () => {
      promise.should.be.instanceof(Promise)
    })

    it('should create a CryptoKey', () => {
      result.algorithm.should.eql(ec.params)
    })
  })

  /**
   * importKey
   */
  describe('importKey', () => {
    let promise, result

    before(() => {
      promise = ec.importKey(A256GCMKey).then(jwk => result = jwk)
    })

    it('should return a promise', () => {
      promise.should.be.instanceof(Promise)
    })

    it('should resolve a JWK', () => {
      result.should.eql(A256GCMKey)
    })

    it('should resolve a JWK with CryptoKey property', () => {
      result.cryptoKey.constructor.name.should.equal('CryptoKey')
    })
  })
})
