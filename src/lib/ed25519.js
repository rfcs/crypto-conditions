'use strict'

const ed25519 = require('ed25519')

exports.getPublicKey = (privateKey) => {
  return ed25519.MakeKeypair(privateKey).publicKey
}

exports.sign = (message, privateKey) => {
  return ed25519.Sign(message, privateKey)
}
