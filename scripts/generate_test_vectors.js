'use strict'

const fs = require('fs')
const path = require('path')

const base64url = require('base64url')
const uniq = require('lodash/uniq')
const flatten = require('lodash/flatten')

const ed25519 = require('../src/lib/ed25519')
const rsa = require('../src/lib/rsa')
const serializer = require('../src/lib/serializer')

const jsonPath = path.resolve(__dirname, '../src/json')

const distPath = path.resolve(__dirname, '../dist')
const outputPath = path.resolve(__dirname, '../test-vectors')

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

const getTestData = (testCaseDefinition) => {
  if (testCaseDefinition.type === 'preimage-sha-256') {
    return {
      json: {
        type: 'preimage-sha-256',
        preimage: base64url(testCaseDefinition.preimage)
      },
      cost: testCaseDefinition.cost,
      subtypes: testCaseDefinition.subtypes
    }
  } else if (testCaseDefinition.type === 'prefix-sha-256') {
    return {
      json: {
        type: 'prefix-sha-256',
        maxMessageLength: testCaseDefinition.maxMessageLength,
        prefix: base64url(testCaseDefinition.prefix),
        subfulfillment: getJsonForCase(testCaseDefinition.subcondition)
      },
      cost: testCaseDefinition.cost,
      subtypes: testCaseDefinition.subtypes
    }
  } else if (testCaseDefinition.type === 'threshold-sha-256') {
    return {
      json: {
        type: 'threshold-sha-256',
        threshold: testCaseDefinition.threshold,
        subfulfillments: testCaseDefinition.subconditionsAll.map(getJsonForCase)
      },
      cost: testCaseDefinition.cost,
      subtypes: testCaseDefinition.subtypes
    }
  } else if (testCaseDefinition.type === 'rsa-sha-256') {
    return {
      json: {
        type: 'rsa-sha-256',
        modulus: base64url(testCaseDefinition.modulus),
        signature: base64url(testCaseDefinition.signature)
      },
      cost: testCaseDefinition.cost,
      subtypes: testCaseDefinition.subtypes
    }
  } else if (testCaseDefinition.type === 'ed25519-sha-256') {
    return {
      json: {
        type: 'ed25519-sha-256',
        publicKey: base64url(testCaseDefinition.publicKey),
        signature: base64url(testCaseDefinition.signature)
      },
      cost: testCaseDefinition.cost,
      subtypes: testCaseDefinition.subtypes
    }
  }
}

const suite = 'valid'
const suitePath = path.resolve(jsonPath, suite)

for (let testCase of fs.readdirSync(suitePath)) {
  const testName = testCase.replace(/\.json$/, '')
  const testPath = path.resolve(suitePath, testCase)
  const testOutputPath = path.resolve(outputPath, `${suite}/${testCase}`)
  const testCaseDefinition = hydrateTestCaseDefinition(require(testPath))

  const testData = getTestData(testCaseDefinition)

  const xmlFingerprintPath = path.resolve(distPath, `${suite}_${testName}_fingerprint.xml`)
  const derFingerprintPath = path.resolve(distPath, `${suite}_${testName}_fingerprint.der`)
  const xmlFulfillmentPath = path.resolve(distPath, `${suite}_${testName}_fulfillment.xml`)
  const derFulfillmentPath = path.resolve(distPath, `${suite}_${testName}_fulfillment.der`)
  const xmlConditionPath = path.resolve(distPath, `${suite}_${testName}_condition.xml`)
  const derConditionPath = path.resolve(distPath, `${suite}_${testName}_condition.der`)

  const serial = serializer.getAll(testCaseDefinition)

  // preimage-sha-256 has no fingerprint, so we may end up skipping this
  if (serial.fingerprint.xml) {
    fs.writeFileSync(xmlFingerprintPath, serial.fingerprint.xml)
  }
  fs.writeFileSync(derFingerprintPath, serial.fingerprint.der)
  fs.writeFileSync(xmlFulfillmentPath, serial.fulfillment.xml)
  fs.writeFileSync(derFulfillmentPath, serial.fulfillment.der)
  fs.writeFileSync(xmlConditionPath, serial.condition.xml)
  fs.writeFileSync(derConditionPath, serial.condition.der)

  testData.fingerprintContents = serial.fingerprint.der.toString('hex').toUpperCase()
  testData.fulfillment = serial.fulfillment.der.toString('hex').toUpperCase()
  testData.conditionBinary = serial.condition.der.toString('hex').toUpperCase()
  testData.conditionUri = serial.condition.uri

  fs.writeFileSync(testOutputPath, JSON.stringify(testData, null, 2))
}
