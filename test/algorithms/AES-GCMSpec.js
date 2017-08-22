'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const TextEncoder = require('../../src/text-encoder')

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
 * Test Data from browser
 */
const encryptedWithAad = {
  data: 'encrypted with Chrome webcrypto',
  aad: base64url(new TextEncoder().encode('additional metadata')),
  tag: base64url(Buffer.from([183,165,187,15,18,138,110,42,90,65,41,68,144,168,192,211])),
  ciphertext: base64url(Buffer.from([219,150,7,111,57,171,225,186,91,234,198,237,236,103,238,65,139,236,225,39,29,81,221,32,99,53,244,187,49,202,30])),
  iv: base64url(Buffer.from([89,209,108,248,129,144,123,205,136,161,187,142,128,11,17,154])),
}
const encryptedWithoutAad = {
  data: 'encrypted with Chrome webcrypto',
  tag: base64url(Buffer.from([195,62,147,6,74,41,247,155,159,147,64,182,114,1,221,124])),
  ciphertext: base64url(Buffer.from([219,150,7,111,57,171,225,186,91,234,198,237,236,103,238,65,139,236,225,39,29,81,221,32,99,53,244,187,49,202,30])),
  iv: base64url(Buffer.from([89,209,108,248,129,144,123,205,136,161,187,142,128,11,17,154])),
}

/**
 * Tests
 */
describe('AES-GCM', () => {

  let alg, ec
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
    let data, key, aad

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
      aad = 'additional metadata'
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
          result.should.not.eql(Buffer.from(data))
        })
    })

    it('should perform encryption', () => {
      return ec.encrypt(key, Buffer.from(data))
        .then(result => {
          result.should.not.eql(Buffer.from(data))
        })
    })

    it('should contain ciphertext, iv and tag', () => {
      return ec.encrypt(key, data)
        .then(result => {
          result.should.have.property('ciphertext')
          result.should.have.property('iv')
          result.should.have.property('tag')
          result.should.not.have.property('aad')
        })
    })

    describe('with aad', () => {
      it('should encrypt with aad', () => {
        return ec.encrypt(key, data, aad)
          .then(result => {
            result.should.have.property('ciphertext')
            result.should.have.property('iv')
            result.should.have.property('tag')
            result.should.have.property('aad')
          })
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
      ec.decrypt(key, encryptedWithoutAad.ciphertext,
        encryptedWithoutAad.iv, encryptedWithoutAad.tag)
      .should.be.instanceof(Promise)
    })

    it('should recover plaintext', () => {
      return ec.decrypt(key, encryptedWithoutAad.ciphertext,
        encryptedWithoutAad.iv, encryptedWithoutAad.tag)
        .then(result => {
          result.should.eql(encryptedWithoutAad.data)
        })
    })

    it('should recover plaintext with buffer input', () => {
      return ec.decrypt(key, base64url.toBuffer(encryptedWithoutAad.ciphertext),
        base64url.toBuffer(encryptedWithoutAad.iv),
        base64url.toBuffer(encryptedWithoutAad.tag))
        .then(result => {
          result.should.eql(encryptedWithoutAad.data)
        })
    })

    describe('with aad', () => {

      it('should reject if the aad is omitted', () => {
        return ec.decrypt(key, encryptedWithAad.ciphertext,
          encryptedWithAad.iv, encryptedWithAad.tag)
          .should.be.rejected
      })

      it('should decrypt with aad', () => {
        return ec.decrypt(key, encryptedWithAad.ciphertext,
          encryptedWithAad.iv, encryptedWithAad.tag, encryptedWithAad.aad)
          .should.eventually.equal(data)
      })

      it('should decrypt with buffer aad', () => {
        return ec.decrypt(key, encryptedWithAad.ciphertext,
          encryptedWithAad.iv, encryptedWithAad.tag,
          base64url.toBuffer(encryptedWithAad.aad))
          .should.eventually.equal(data)
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
