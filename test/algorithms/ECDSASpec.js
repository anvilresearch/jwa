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
const ECDSA = require('../../src/algorithms/ECDSA')
const { ECPublicJwk, ECPrivateJwk } = require('../keys')

/**
 * Tests
 */
describe('ECDSA', () => {
  let publicKey, privateKey, alg, ec

  before(() => {
    alg = { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } }
    ec = new ECDSA(alg)
    crypto.subtle.importKey(
                  "jwk",
                  ECPublicJwk,
                  alg,
                  false, // extractable
                  ["verify"] // usages
    ).then(result => {
      publicKey = result
    })
    crypto.subtle.importKey(
                  "jwk",
                  ECPrivateJwk,
                  alg,
                  false, // extractable
                  ["sign"] // usages
    ).then(result => {
      privateKey = result
    })
  })

  /**
   * constructor
   */
  describe('constructor', () => {
    it('should set params', () => {
      return ec.params.should.equal(alg)
    })
  })

  /**
   * sign
   */
  describe('sign', () => {
    let data

    before(() => {
      data = 'signed with Chrome webcrypto'
    })

    it('should return a promise', () => {
      ec.sign(privateKey, data).should.be.instanceof(Promise)
    })

    it('should reject an insufficient key length')

    it('should resolve a base64url encoded value', () => {
      return ec.sign(privateKey, data).should.be.fulfilled
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
    let data, signature

    before(() => {
      data ='signed with Chrome webcrypto'

      ec.sign(privateKey, data)
      .then(result => {
        signature = result
      })
    })

    it('should return a promise', () => {
      ec.verify(publicKey, signature, data)
        .should.be.instanceof(Promise)
    })

    it('should resolve a boolean', () => {
      return ec.verify(publicKey, signature, data)
        .then(verified => {
          verified.should.equal(true)
        })
    })
  })

  /**
   * generateKey
   */
  describe('generateKey', () => {
    let promise, result

    before(() => {
      promise = ec.generateKey(true, ["sign"])
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
      result.publicKey.algorithm.should.eql(ec.params)
      result.privateKey.algorithm.should.eql(ec.params)
    })
  })

  /**
   * importKey
   */
  describe('importKey', () => {
    let publicPromise, privatePromise, publicResult, privateResult

    before(() => {
      publicPromise = ec.importKey(ECPublicJwk)
      publicPromise.then(jwk => {
        publicResult = jwk
      })
      privatePromise = ec.importKey(ECPrivateJwk)
      privatePromise.then(jwk => {
        privateResult = jwk
      })
    })

    it('should return a promise', () => {
      privatePromise.should.be.instanceof(Promise)
      publicPromise.should.be.instanceof(Promise)
    })

    it('should reject "enc" use', () => {
      let wrongKey = Object.assign({}, ECPublicJwk)
      wrongKey.use = "enc"
      return ec.importKey(wrongKey).should.be.rejectedWith(Error)
    })

    it('should resolve a JWK', () => {
      privateResult.should.eql(ECPrivateJwk)
      publicResult.should.eql(ECPublicJwk)
    })

    it('should resolve a JWK with CryptoKey property', () => {
      privateResult.cryptoKey.constructor.name.should.equal('CryptoKey')
      publicResult.cryptoKey.constructor.name.should.equal('CryptoKey')
    })
  })
})
