'use strict'

const NodeRSA = require('node-rsa')
const crypto = require('crypto')
const sinon = require('sinon')

exports.getModulus = (privateKey) => {
  const key = new NodeRSA(privateKey)
  const modulus = key.exportKey('components-public').n

  if (modulus[0] === 0) return modulus.slice(1)
  else return modulus
}

exports.sign = (message, privateKeyString, salt) => {
  const privateKey = new NodeRSA(privateKeyString, {
    signingScheme: 'pss-sha256',
    signingSchemeOptions: {
      hash: 'sha256',
      saltLength: 32
    }
  })

  // Workaround for node-rsa bug where signingSchemeOptions.saltLength is ignored
  privateKey.$options.signingSchemeOptions.saltLength = 32
  privateKey.keyPair.setOptions(privateKey.$options)

  const randomBytes = sinon.stub(crypto, 'randomBytes', (len) => {
    if (len !== salt.length) {
      throw new Error('Unexpected salt length ' + len + ', expected: ' + salt.length)
    }
    return salt
  })

  const signature = privateKey.sign(message)

  randomBytes.restore()

  return signature
}
