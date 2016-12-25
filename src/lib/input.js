'use strict'

const uniq = require('lodash/uniq')
const flatten = require('lodash/flatten')

const ed25519 = require('./ed25519')
const rsa = require('./rsa')
const serializer = require('./serializer')
const output = require('./output')

const sum = arr => arr.reduce((a, b) => a + b, 0)
const square = a => a * a
const getNLargest = (n, arr) => arr.sort((a, b) => b - a).slice(0, n)

const hydrateWithMessage = (message) => {
  return (testCaseDefinitionJson) => hydrateTestCaseDefinition(
    testCaseDefinitionJson,
    message
  )
}

const hydrateTestCaseDefinition = (testCaseDefinitionJson, message = null) => {
  // Test Case Definition
  const tcd = Object.assign({}, testCaseDefinitionJson)

  tcd.subtypes = []
  if (message) {
    tcd.message = message
  } else if (tcd.message) {
    tcd.message = Buffer.from(testCaseDefinitionJson.message, 'base64')
  } else {
    tcd.message = Buffer.alloc(0)
  }

  if (testCaseDefinitionJson.type === 'preimage-sha-256') {
    tcd.preimage = Buffer.from(testCaseDefinitionJson.preimage, 'base64')
    tcd.cost = tcd.preimage.length
  } else if (testCaseDefinitionJson.type === 'prefix-sha-256') {
    tcd.prefix = Buffer.from(testCaseDefinitionJson.prefix, 'base64')
    const hydrate = hydrateWithMessage(Buffer.concat([tcd.prefix, tcd.message]))
    tcd.subcondition = hydrate(tcd.subcondition)
    tcd.cost =
      tcd.prefix.length +
      tcd.maxMessageLength +
      getCostForCase(tcd.subcondition) +
      1024
    tcd.subtypes = getSubtypesForCase(tcd.subcondition)
  } else if (testCaseDefinitionJson.type === 'threshold-sha-256') {
    const hydrate = hydrateWithMessage(tcd.message)
    tcd.threshold = testCaseDefinitionJson.subfulfillments.length
    tcd.subfulfillments = tcd.subfulfillments.map(hydrate)
    if (testCaseDefinitionJson.subconditions) {
      tcd.subconditions = tcd.subconditions.map(hydrate)
    } else {
      tcd.subconditions = []
    }
    tcd.subconditionsAll = tcd.subconditions.concat(tcd.subfulfillments)
    tcd.cost =
      sum(getNLargest(tcd.threshold, tcd.subconditionsAll.map(getCostForCase))) +
      tcd.subconditionsAll.length * 1024
    tcd.subtypes = uniq(flatten(tcd.subconditionsAll.map(getSubtypesForCase))).sort()
  } else if (testCaseDefinitionJson.type === 'rsa-sha-256') {
    tcd.modulus = rsa.getModulus(tcd.privateKey)
    tcd.salt = Buffer.from(testCaseDefinitionJson.salt, 'base64')
    tcd.signature = rsa.sign(
      tcd.message,
      tcd.privateKey,
      tcd.salt
    )
    tcd.cost = square(tcd.modulus.length)
  } else if (testCaseDefinitionJson.type === 'ed25519-sha-256') {
    tcd.privateKey = Buffer.from(testCaseDefinitionJson.privateKey, 'base64')
    tcd.publicKey = ed25519.getPublicKey(tcd.privateKey)
    tcd.signature = ed25519.sign(tcd.message, tcd.privateKey)
    tcd.cost = 131072
  }

  tcd.serial = serializer.getAll(tcd)

  return tcd
}

const getDataForCase = (testCase) => {
  const tcd = hydrateTestCaseDefinition(testCase)
  return output.generateTestVectorJson(tcd)
}

const getJsonForCase =
exports.getJsonForCase = testCase => getDataForCase(testCase).json
const getCostForCase = testCase => getDataForCase(testCase).cost
const getSubtypesForCase = testCase => {
  const testData = getDataForCase(testCase)
  const subtypes = uniq(testData.subtypes.concat([testData.json.type]))
  return subtypes.sort()
}

module.exports = {
  hydrateTestCaseDefinition,
  getDataForCase,
  getJsonForCase,
  getCostForCase,
  getSubtypesForCase
}
