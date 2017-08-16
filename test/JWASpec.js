'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')

/**
 * Assertions
 */
chai.should()
chai.use(chaiAsPromised)
let expect = chai.expect

/**
 * Code under test
 */
const crypto = require('@trust/webcrypto')
const { NotSupportedError } = require('../src/errors')
const JWA = require('../src/JWA')
const { RsaPrivateCryptoKey, RsaPublicCryptoKey,
  RsaPublicJwk, RsaPrivateJwk } = require('./keys')

/**
 * Tests
 */
describe('JWA', () => {
  let alg, signature, data, enc, key
  let A256GCMKey = {
    kty: "oct",
    k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
    alg: "A256GCM",
    ext: true,
  }

  before(() => {
    alg = { name: 'RSASSA-PKCS1-v1_5' }
    enc = { name: 'A128GCM' }
    data ='signed with Chrome webcrypto'
    signature = "VLW6eetMx2aufbDYXr7zydty4z02wu0O-Mx4bfnc5VAsMFaFYIFV1UYTfgC" +
                "gWxK5yGa0tUUborW9brxwfF050FuOtsBXp8FvWAX0bMiWhUSQ0Bub3tW94J" +
                "zifEGyRUc_840DftHtLbPw_8L1K5R7YazvqN0sukjCHQmrZ322J1-jUAPQu" +
                "LgwcocHb3ImGRzqUhIxcRT7O5POB4YPvcn98XjsOuuUG8zppR8b3xwK1p9t" +
                "uu9HfhI_b8Zz4u2RGgx4OKYNw0ELcpWR__Jhvv_K25BT7vC2UqXldpIdX39" +
                "MvPeK_kgS-yp2nOVCCGo3alPo6hfDoKeFDrV-BSSdAlGQUw"

    crypto.subtle.importKey(
                  "jwk",
                  A256GCMKey,
                  {   // algorithm
                    name: "AES-GCM",
                  },
                  false, // extractable
                  ["encrypt", "decrypt"] // usages
    ).then(result => { key = result })
  })

  describe('sign', () => {
    it('should return a promise', () => {
      return JWA.sign('RS256', RsaPrivateCryptoKey, 'data')
        .should.be.fulfilled
    })

    it('should reject unsupported algorithm', () => {
      return JWA.sign('RS257', RsaPrivateCryptoKey, 'data')
        .should.be.rejectedWith(NotSupportedError)
    })

    it('should reject mismatching key', () => {
      return JWA.sign('ES256', RsaPrivateCryptoKey, 'data')
        .should.be.rejected
    })

    it('should resolve a signature', () => {
      return JWA.sign('RS256', RsaPrivateCryptoKey, data)
        .should.eventually.equal(signature)
    })
  })

  describe('verify', () => {
    it('should return a promise', () => {
      return JWA.verify('RS256', RsaPublicCryptoKey, signature, data)
        .should.be.fulfilled
    })

    it('should reject unsupported algorithm', () => {
      return JWA.verify('RS257', RsaPrivateCryptoKey, signature, data)
        .should.be.rejectedWith(NotSupportedError)
    })

    it('should reject mismatching key', () => {
      return JWA.sign('ES256', RsaPrivateCryptoKey, 'data')
        .should.be.rejected
    })

    it('should resolve a boolean', () => {
      return JWA.verify('RS256', RsaPublicCryptoKey, signature, data)
        .should.eventually.equal(true)
    })
  })

  describe('encrypt', () => {
    it('should return a promise', () => {
      return JWA.encrypt('A128GCM', key, data)
        .should.be.fulfilled
    })

    it('should reject unsupported algorithm', () => {
      return JWA.encrypt('RS257', key, data)
        .should.be.rejectedWith(NotSupportedError)
    })

    it('should reject mismatching key', () => {
      return JWA.encrypt('A128CBC-HS256', key, data)
        .should.be.rejected
    })

    it('should contain ciphertext, iv and tag', () => {
      return JWA.encrypt('A128GCM', key, data)
        .then(result => {
          result.should.have.property('ciphertext')
          result.should.have.property('iv')
          result.should.have.property('tag')
      })
    })
  })

  describe('decrypt', () => {
    let result

    before(() => {
      JWA.encrypt('A128GCM', key, data)
      .then(object => result = object)
    })

    it('should return a promise', () => {
      return JWA.decrypt('A128GCM', key, result.ciphertext, result.iv, result.tag)
        .should.be.fulfilled
    })

    it('should reject unsupported algorithm', () => {
      return JWA.decrypt('RS257', key, result.ciphertext, result.iv, result.tag)
        .should.be.rejectedWith(NotSupportedError)
    })

    it('should reject mismatching key', () => {
      return JWA.decrypt('A128CBC-HS256', key, result)
        .should.be.rejected
    })

    it('should return plaintext as a string', () => {
      return JWA.decrypt('A128GCM', key, result.ciphertext, result.iv, result.tag)
        .then(result => {
          expect(typeof result === "string")
      })
    })
  })

  describe('encryptKey', () => {
  })

  describe('decryptKey', () => {
  })

  describe('agreeKey', () => {
  })

  describe('generateKey', () => {
    it('should return a promise', () => {
      return JWA.generateKey("A128GCM", {key_ops: ["encrypt", "decrypt"]})
        .should.be.fulfilled
    })

    it('should reject unsupported algorithm', () => {
      return JWA.generateKey("A257GCM", {key_ops: ["encrypt", "decrypt"]})
        .should.be.rejectedWith(NotSupportedError)
    })
  })

  describe('importKey', () => {
    it('should return a promise', () => {
      return JWA.importKey(A256GCMKey).should.be.fulfilled
    })

    it('should reject unsupported algorithm', () => {
      key.alg = 'RS257'
      return JWA.importKey(key)
        .should.be.rejectedWith(NotSupportedError)
    })

    it('should resolve a public key', () => {
      RsaPublicJwk.alg = 'RS256'
      return JWA.importKey(RsaPublicJwk).should.be.fulfilled
    })

    it('should resolve a private key', () => {
      RsaPrivateJwk.alg = 'RS256'
      return JWA.importKey(RsaPrivateJwk).should.be.fulfilled
    })

    it('should accept same key with different algorithms', () => {
      RsaPublicJwk.alg = "RS256"
      return Promise.resolve()
      .then(() => {
        return JWA.importKey(RsaPublicJwk).should.be.fulfilled
      })
      .then(result => {
        RsaPublicJwk.alg = "RS384"
        return JWA.importKey(RsaPublicJwk).should.be.fulfilled
      })
    })
  })

  describe('exportKey', () => {
  })

})
