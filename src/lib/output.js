'use strict'

const base64url = require('base64url')

const input = require('./input')

const generateFulfillmentDefinitionJson = (testCaseDefinition) => {
  if (testCaseDefinition.type === 'preimage-sha-256') {
    return {
      type: 'preimage-sha-256',
      preimage: base64url(testCaseDefinition.preimage)
    }
  } else if (testCaseDefinition.type === 'prefix-sha-256') {
    return {
      type: 'prefix-sha-256',
      maxMessageLength: testCaseDefinition.maxMessageLength,
      prefix: base64url(testCaseDefinition.prefix),
      subfulfillment: input.getJsonForCase(testCaseDefinition.subcondition)
    }
  } else if (testCaseDefinition.type === 'threshold-sha-256') {
    return {
      type: 'threshold-sha-256',
      threshold: testCaseDefinition.threshold,
      subfulfillments: testCaseDefinition.subconditionsAll.map(input.getJsonForCase)
    }
  } else if (testCaseDefinition.type === 'rsa-sha-256') {
    return {
      type: 'rsa-sha-256',
      modulus: base64url(testCaseDefinition.modulus),
      signature: base64url(testCaseDefinition.signature)
    }
  } else if (testCaseDefinition.type === 'ed25519-sha-256') {
    return {
      type: 'ed25519-sha-256',
      publicKey: base64url(testCaseDefinition.publicKey),
      signature: base64url(testCaseDefinition.signature)
    }
  }
}
const generateTestVectorJson = (testCaseDefinition) => {
  return {
    json: generateFulfillmentDefinitionJson(testCaseDefinition),
    cost: testCaseDefinition.cost,
    subtypes: testCaseDefinition.subtypes,
    fingerprintContents: testCaseDefinition.serial.fingerprint.der.toString('hex').toUpperCase(),
    fulfillment: testCaseDefinition.serial.fulfillment.der.toString('hex').toUpperCase(),
    conditionBinary: testCaseDefinition.serial.condition.der.toString('hex').toUpperCase(),
    conditionUri: testCaseDefinition.serial.condition.uri
  }
}

module.exports = {
  generateFulfillmentDefinitionJson,
  generateTestVectorJson
}
