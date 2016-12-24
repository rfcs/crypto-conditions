'use strict'

const path = require('path')

const uniq = require('lodash/uniq')
const flatten = require('lodash/flatten')

const ed25519 = require('./ed25519')
const rsa = require('./rsa')

const outputPath = path.resolve(__dirname, '../../test-vectors')

const sum = arr => arr.reduce((a, b) => a + b, 0)
const square = a => a * a
const getNLargest = (n, arr) => arr.sort((a, b) => b - a).slice(0, n)

const hydrateTestCaseDefinition = (testCaseDefinitionJson) => {
  const testCaseDefinition = Object.assign({}, testCaseDefinitionJson)

  testCaseDefinition.subtypes = []

  if (testCaseDefinitionJson.type === 'preimage-sha-256') {
    testCaseDefinition.preimage = Buffer.from(testCaseDefinitionJson.preimage, 'base64')
    testCaseDefinition.cost = testCaseDefinition.preimage.length
  } else if (testCaseDefinitionJson.type === 'prefix-sha-256') {
    testCaseDefinition.prefix = Buffer.from(testCaseDefinitionJson.prefix, 'base64')
    testCaseDefinition.cost =
      testCaseDefinition.prefix.length +
      testCaseDefinition.maxMessageLength +
      getCostForCase(testCaseDefinition.subcondition) +
      1024
    testCaseDefinition.subtypes = getSubtypesForCase(testCaseDefinition.subcondition)
  } else if (testCaseDefinitionJson.type === 'threshold-sha-256') {
    testCaseDefinition.threshold = testCaseDefinitionJson.subfulfillments.length
    testCaseDefinition.subconditions = testCaseDefinitionJson.subconditions || []
    testCaseDefinition.subconditionsAll = testCaseDefinition.subconditions
      .concat(testCaseDefinition.subfulfillments)
    testCaseDefinition.cost =
      sum(getNLargest(testCaseDefinition.threshold, testCaseDefinition.subconditionsAll.map(getCostForCase))) +
      testCaseDefinition.subconditionsAll.length * 1024
    testCaseDefinition.subtypes = uniq(flatten(testCaseDefinition.subconditionsAll.map(getSubtypesForCase))).sort()
  } else if (testCaseDefinitionJson.type === 'rsa-sha-256') {
    testCaseDefinition.modulus = rsa.getModulus(testCaseDefinition.privateKey)
    testCaseDefinition.message = Buffer.from(testCaseDefinitionJson.message, 'base64')
    testCaseDefinition.salt = Buffer.from(testCaseDefinitionJson.salt, 'base64')
    testCaseDefinition.signature = rsa.sign(
      testCaseDefinition.message,
      testCaseDefinition.privateKey,
      testCaseDefinition.salt
    )
    testCaseDefinition.cost = square(testCaseDefinition.modulus.length)
  } else if (testCaseDefinitionJson.type === 'ed25519-sha-256') {
    testCaseDefinition.privateKey = Buffer.from(testCaseDefinitionJson.privateKey, 'base64')
    testCaseDefinition.publicKey = ed25519.getPublicKey(testCaseDefinition.privateKey)
    testCaseDefinition.message = Buffer.from(testCaseDefinitionJson.message, 'base64')
    testCaseDefinition.signature = ed25519.sign(testCaseDefinition.message, testCaseDefinition.privateKey)
    testCaseDefinition.cost = 131072
  }

  return testCaseDefinition
}

const getDataForCase = (testCase) => {
  const outputJsonPath = path.resolve(outputPath, `valid/${testCase}.json`)
  const outputJson = require(outputJsonPath)
  return outputJson
}

const getJsonForCase = testCase => getDataForCase(testCase).json
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
