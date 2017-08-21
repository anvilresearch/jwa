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
const RSASSA_PKCS1_v1_5 = require('../../src/algorithms/RSASSA-PKCS1-v1_5')
const { RsaPrivateCryptoKey, RsaPublicCryptoKey, RsaPrivateJwk, RsaPublicJwk } = require('../keys')

/**
 * Tests
 */
describe('RSASSA_PKCS1_v1_5', () => {

  /**
   * constructor
   */
  describe('constructor', () => {
    it('should set params', () => {
      let alg = { name: 'RSASSA-PKCS1-v1_5' }
      let rsa = new RSASSA_PKCS1_v1_5(alg)
      rsa.params.should.equal(alg)
    })
  })

  /**
   * sign
   */
  describe('sign', () => {
    let alg, rsa, data, chromeRsaSignature

    before(() => {
      alg = { name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-256' } }
      rsa = new RSASSA_PKCS1_v1_5(alg)

      data = 'signed with Chrome webcrypto'

      chromeRsaSignature = new Uint8Array([
        84, 181, 186, 121, 235, 76, 199, 102, 174, 125, 176, 216, 94, 190,
        243, 201, 219, 114, 227, 61, 54, 194, 237, 14, 248, 204, 120, 109,
        249, 220, 229, 80, 44, 48, 86, 133, 96, 129, 85, 213, 70, 19, 126,
        0, 160, 91, 18, 185, 200, 102, 180, 181, 69, 27, 162, 181, 189, 110,
        188, 112, 124, 93, 57, 208, 91, 142, 182, 192, 87, 167, 193, 111,
        88, 5, 244, 108, 200, 150, 133, 68, 144, 208, 27, 155, 222, 213, 189,
        224, 156, 226, 124, 65, 178, 69, 71, 63, 243, 141, 3, 126, 209, 237,
        45, 179, 240, 255, 194, 245, 43, 148, 123, 97, 172, 239, 168, 221,
        44, 186, 72, 194, 29, 9, 171, 103, 125, 182, 39, 95, 163, 80, 3, 208,
        184, 184, 48, 114, 135, 7, 111, 114, 38, 25, 28, 234, 82, 18, 49, 113,
        20, 251, 59, 147, 206, 7, 134, 15, 189, 201, 253, 241, 120, 236, 58,
        235, 148, 27, 204, 233, 165, 31, 27, 223, 28, 10, 214, 159, 109, 186,
        239, 71, 126, 18, 63, 111, 198, 115, 226, 237, 145, 26, 12, 120, 56,
        166, 13, 195, 65, 11, 114, 149, 145, 255, 242, 97, 190, 255, 202, 219,
        144, 83, 238, 240, 182, 82, 165, 229, 118, 146, 29, 95, 127, 76, 188,
        247, 138, 254, 72, 18, 251, 42, 118, 156, 229, 66, 8, 106, 55, 106,
        83, 232, 234, 23, 195, 160, 167, 133, 14, 181, 126, 5, 36, 157, 2, 81,
        144, 83
      ])
    })

    it('should return a promise', () => {
      rsa.sign(RsaPrivateCryptoKey, data).should.be.instanceof(Promise)
    })

    it('should reject an insufficient key length')

    it('should resolve a base64url encoded value for string input', () => {
      return rsa.sign(RsaPrivateCryptoKey, data)
        .then(signature => {
          base64url.toBuffer(signature)
            .should.eql(Buffer.from(chromeRsaSignature))
        })
    })

    it('should resolve a base64url encoded value for buffer input', () => {
      return rsa.sign(RsaPrivateCryptoKey, Buffer.from(data))
        .then(signature => {
          base64url.toBuffer(signature)
            .should.eql(Buffer.from(chromeRsaSignature))
        })
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
    let alg, rsa, data, signature

    before(() => {
      alg = { name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-256' } }

      rsa = new RSASSA_PKCS1_v1_5(alg)

      data ='signed with Chrome webcrypto'

      signature = 'VLW6eetMx2aufbDYXr7zydty4z02wu0O-Mx4bfnc5VAsMFaFYIFV1UY' +
                  'TfgCgWxK5yGa0tUUborW9brxwfF050FuOtsBXp8FvWAX0bMiWhUSQ0B' +
                  'ub3tW94JzifEGyRUc_840DftHtLbPw_8L1K5R7YazvqN0sukjCHQmrZ' +
                  '322J1-jUAPQuLgwcocHb3ImGRzqUhIxcRT7O5POB4YPvcn98XjsOuuU' +
                  'G8zppR8b3xwK1p9tuu9HfhI_b8Zz4u2RGgx4OKYNw0ELcpWR__Jhvv_' +
                  'K25BT7vC2UqXldpIdX39MvPeK_kgS-yp2nOVCCGo3alPo6hfDoKeFDr' +
                  'V-BSSdAlGQUw'
    })

    it('should return a promise', () => {
      rsa.verify(RsaPublicCryptoKey, signature, data)
        .should.be.instanceof(Promise)
    })

    it('should resolve a boolean', () => {
      return rsa.verify(RsaPublicCryptoKey, signature, data)
        .then(verified => {
          verified.should.equal(true)
        })
    })

    it('should resolve a boolean', () => {
      let sigBuffer = base64url.toBuffer(signature)
      let dataBuffer = Buffer.from(data)
      return rsa.verify(RsaPublicCryptoKey, sigBuffer, dataBuffer)
        .then(verified => {
          verified.should.equal(true)
        })
    })
  })

  /**
   * generateKey
   */
  describe('generateKey', () => {
    let promise, result, alg, rsa, modulusLength

    before(() => {
      alg = { name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-256' } }

      rsa = new RSASSA_PKCS1_v1_5(alg)
      modulusLength = 1024

      promise = rsa.generateKey(true, ["sign"])
      promise.then(jwk => {
        result = jwk
      })
    })

    it('should return a promise', () => {
      promise.should.be.instanceof(Promise)
    })

    it('should create a CryptoKeyPair', () => {
      result.should.have.property('publicKey')
      result.should.have.property('privateKey')
      result.publicKey.algorithm.should.eql(alg)
      result.privateKey.algorithm.should.eql(alg)
    })

    it('should create a CryptoKeyPair', () => {
      rsa.generateKey(true, [], {modulusLength})
      .then(result => {
        result.should.have.property('publicKey')
        result.should.have.property('privateKey')
        result.publicKey.algorithm.should.eql(alg)
        result.publicKey.algorithm.modulusLength.should.eql(1024)
        result.privateKey.algorithm.should.eql(alg)
        result.privateKey.algorithm.modulusLength.should.eql(1024)
      })
    })
  })

  /**
   * importKey
   */
  describe('importKey', () => {
    let publicPromise, privatePromise, publicResult, privateResult, alg, rsa
    before(() => {
      alg = { name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-256' } }

      rsa = new RSASSA_PKCS1_v1_5(alg)

      publicPromise = rsa.importKey(RsaPublicJwk)
      publicPromise.then(jwk => {
        publicResult = jwk
      })
      privatePromise = rsa.importKey(RsaPrivateJwk)
      privatePromise.then(jwk => {
        privateResult = jwk
      })
    })

    it('should reject duplicate key use', () => {
      let wrongKey = Object.assign({}, RsaPublicJwk)
      wrongKey.key_ops = ["verify", "verify"]
      return rsa.importKey(wrongKey)
        .should.be.rejectedWith('Invalid key operations key parameter')
    })

    it('should not duplicate existent key use', () => {
      let key = Object.assign({}, RsaPrivateJwk)
      key.key_ops = ["sign"]
      return rsa.importKey(key)
        .should.be.fullfilled
    })

    it('should return a promise', () => {
      privatePromise.should.be.instanceof(Promise)
      publicPromise.should.be.instanceof(Promise)
    })

    it('should reject "enc" use', () => {
      let wrongKey = Object.assign({}, RsaPublicJwk)
      wrongKey.use = "enc"
      return rsa.importKey(wrongKey)
        .should.be.rejectedWith('Invalid use key parameter')
    })

    it('should resolve a JWK', () => {
      privateResult.should.eql(RsaPrivateJwk)
      publicResult.should.eql(RsaPublicJwk)
    })

    it('should resolve a JWK with CryptoKey property', () => {
      privateResult.cryptoKey.constructor.name.should.equal('CryptoKey')
      publicResult.cryptoKey.constructor.name.should.equal('CryptoKey')
    })
  })
})
