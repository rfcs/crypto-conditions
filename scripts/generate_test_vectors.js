'use strict'

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const execSync = require('child_process').execSync

const Mustache = require('mustache')
Mustache.escape = a => a
const xmldoc = require('xmldoc')
const base64url = require('base64url')
const uniq = require('lodash/uniq')
const flatten = require('lodash/flatten')

const ed25519 = require('../src/lib/ed25519')
const rsa = require('../src/lib/rsa')

const jsonPath = path.resolve(__dirname, '../src/json')
const jsonSuites = fs.readdirSync(jsonPath)

const xmlPath = path.resolve(__dirname, '../src/xer')
const uriPath = path.resolve(__dirname, '../src/uri')
const distPath = path.resolve(__dirname, '../dist')
const asnPath = path.resolve(__dirname, '../src/asn1/CryptoConditions.asn')
const outputPath = path.resolve(__dirname, '../test-vectors')

const FINGERPRINT_ASN_TYPES = {
  // Preimage doesn't have an ASN-encoded fingerprint. The fingerprint contents
  // are just the preimage
  "preimage-sha-256": false,
  "prefix-sha-256": "PrefixFingerprintContents",
  "threshold-sha-256": "ThresholdFingerprintContents",
  "rsa-sha-256": "RsaFingerprintContents",
  "ed25519-sha-256": "Ed25519FingerprintContents"
}

const SUBTYPES_BITS = {
  "preimage-sha-256": 0,
  "prefix-sha-256": 1,
  "threshold-sha-256": 2,
  "rsa-sha-256": 3,
  "ed25519-sha-256": 4
}

const formattedHex = (buffer) => {
  return (buffer
    .toString('hex')
    .toUpperCase()
    .match(/.{1,8}/g) || [])
    .join(' ')
}

const sum = arr => arr.reduce((a, b) => a + b, 0)
const square = a => a*a
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
    testCaseDefinition.threshold = testCaseDefinitionJson.threshold
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

const getXml = (testCase, type) => {
  const fulfillmentXmlPath = path.resolve(distPath, `valid_${testCase}_${type}.xml`)
  const fulfillmentXml = fs.readFileSync(fulfillmentXmlPath, 'utf-8')
  const fulfillmentXmlDoc = new xmldoc.XmlDocument(fulfillmentXml)

  return fulfillmentXmlDoc.firstChild.toString()
}

const getTemplateProps = (testCaseDefinition) => {
  if (testCaseDefinition.type === 'preimage-sha-256') {
    return {
      preimage: formattedHex(testCaseDefinition.preimage),
      cost: testCaseDefinition.cost
    }
  } else if (testCaseDefinition.type === 'prefix-sha-256') {
    return {
      prefix: formattedHex(testCaseDefinition.prefix),
      maxMessageLength: testCaseDefinition.maxMessageLength,
      subcondition: getXml(testCaseDefinition.subcondition, 'condition'),
      subfulfillment: getXml(testCaseDefinition.subcondition, 'fulfillment'),
      cost: testCaseDefinition.cost
    }
  } else if (testCaseDefinition.type === 'threshold-sha-256') {
    return {
      threshold: testCaseDefinition.threshold,
      subconditionsAll: testCaseDefinition.subconditionsAll.map(x => getXml(x, 'condition')),
      subconditions: testCaseDefinition.subconditions.map(x => getXml(x, 'condition')),
      subfulfillments: testCaseDefinition.subfulfillments.map(x => getXml(x, 'fulfillment')),
      cost: testCaseDefinition.cost
    }
  } else if (testCaseDefinition.type === 'rsa-sha-256') {
    return {
      modulus: formattedHex(testCaseDefinition.modulus),
      signature: formattedHex(testCaseDefinition.signature),
      cost: testCaseDefinition.cost
    }
  } else if (testCaseDefinition.type === 'ed25519-sha-256') {
    return {
      publicKey: formattedHex(testCaseDefinition.publicKey),
      signature: formattedHex(testCaseDefinition.signature),
      cost: testCaseDefinition.cost
    }
  }
}

const XML_PREAMBLE = '<?xml version="1.0" encoding="UTF-8"?>\n'
const normalizeXml = xml => XML_PREAMBLE + new xmldoc.XmlDocument(xml).toString()

const suite = 'valid'
const suitePath = path.resolve(jsonPath, suite)

for (let testCase of fs.readdirSync(suitePath)) {
  const testName = testCase.replace(/\.json$/, '')
  const testPath = path.resolve(suitePath, testCase)
  const testOutputPath = path.resolve(outputPath, `${suite}/${testCase}`)
  const testCaseDefinition = hydrateTestCaseDefinition(require(testPath))
  const type = testCase.split('_')[1]

  const testData = getTestData(testCaseDefinition)
  const templateProps = getTemplateProps(testCaseDefinition)

  // Generate fingerprint
  if (type === 'preimage-sha-256') {
    testData.fingerprintContents = testCaseDefinition.preimage.toString('hex').toUpperCase()
  } else {
    const xmlFingerprintPath = path.resolve(distPath, `${suite}_${testName}_fingerprint.xml`)
    const derFingerprintPath = path.resolve(distPath, `${suite}_${testName}_fingerprint.der`)
    const xmlFingerprintTemplate = fs.readFileSync(path.resolve(xmlPath, `fingerprint_${type}.xml`), 'utf-8')
    const xmlFingerprint = Mustache.render(xmlFingerprintTemplate, templateProps)

    fs.writeFileSync(xmlFingerprintPath, normalizeXml(xmlFingerprint))

    const fingerprintAsnType = FINGERPRINT_ASN_TYPES[type]
    execSync(
      `ffasn1dump -I xer -O der ${asnPath} ${fingerprintAsnType} ` +
      `${xmlFingerprintPath} ${derFingerprintPath}`
    )

    const fingerprintData = fs.readFileSync(derFingerprintPath)
    testData.fingerprintContents = fingerprintData.toString('hex').toUpperCase()
  }

  // Generate fulfillment
  const xmlFulfillmentPath = path.resolve(distPath, `${suite}_${testName}_fulfillment.xml`)
  const derFulfillmentPath = path.resolve(distPath, `${suite}_${testName}_fulfillment.der`)
  const xmlFulfillmentTemplate = fs.readFileSync(path.resolve(xmlPath, `fulfillment_${type}.xml`), 'utf-8')
  const xmlFulfillment = Mustache.render(xmlFulfillmentTemplate, templateProps)

  fs.writeFileSync(xmlFulfillmentPath, normalizeXml(xmlFulfillment))

  execSync(
    `ffasn1dump -I xer -O der ${asnPath} Fulfillment ` +
    `${xmlFulfillmentPath} ${derFulfillmentPath}`
  )

  const fulfillmentData = fs.readFileSync(derFulfillmentPath)
  testData.fulfillment = fulfillmentData.toString('hex').toUpperCase()

  // Generate condition
  const uriConditionPath = path.resolve(uriPath, `condition_${type}.txt`)
  const xmlSrcConditionPath = path.resolve(xmlPath, `condition_${type}.xml`)
  const xmlDstConditionPath = path.resolve(distPath, `${suite}_${testName}_condition.xml`)
  const derConditionPath = path.resolve(distPath, `${suite}_${testName}_condition.der`)
  const fingerprint = crypto
    .createHash('sha256')
    .update(Buffer.from(testData.fingerprintContents, 'hex'))
    .digest()

  const fingerprintHex = formattedHex(fingerprint)

  let subtypesBitarrayString = ''
  if (testCaseDefinition.subtypes) {
    const subtypeBits = testCaseDefinition.subtypes.map(x => SUBTYPES_BITS[x])
    const largestBit = subtypeBits.reduce((a, b) => Math.max(a, b), 0)
    const subtypesBitarray = new Array(largestBit).fill(0)
    for (let subtypeBit of subtypeBits) {
      subtypesBitarray[subtypeBit] = 1
    }
    subtypesBitarrayString = subtypesBitarray.join('')
  }

  templateProps.fingerprint = formattedHex(fingerprint)
  templateProps.subtypes = subtypesBitarrayString

  const srcConditionXmlData = fs.readFileSync(xmlSrcConditionPath, 'utf-8')
  const dstConditionXmlData = Mustache.render(srcConditionXmlData, templateProps)

  const srcConditionUriData = fs.readFileSync(uriConditionPath, 'utf-8')
  const dstConditionUriData = srcConditionUriData
    .replace('{{fingerprint}}', base64url(fingerprint))
    .replace('{{cost}}', testCaseDefinition.cost)
    .replace('{{subtypes}}', (testCaseDefinition.subtypes || []).join(','))
    .replace(/\n$/, '')

  fs.writeFileSync(xmlDstConditionPath, dstConditionXmlData)

  execSync(
    `ffasn1dump -I xer -O der ${asnPath} Condition ` +
    `${xmlDstConditionPath} ${derConditionPath}`
  )

  const conditionData = fs.readFileSync(derConditionPath)
  testData.conditionBinary = conditionData.toString('hex').toUpperCase()
  testData.conditionUri = dstConditionUriData

  fs.writeFileSync(testOutputPath, JSON.stringify(testData, null, 2))
}
