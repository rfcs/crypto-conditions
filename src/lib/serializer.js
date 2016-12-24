'use strict'

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const base64url = require('base64url')
const Mustache = require('mustache')
Mustache.escape = a => a
const xmldoc = require('xmldoc')
const ffasn1dump = require('../lib/ffasn1dump')

const xmlPath = path.resolve(__dirname, '../xer')
const uriPath = path.resolve(__dirname, '../uri')
const distPath = path.resolve(__dirname, '../../dist')

const FINGERPRINT_ASN_TYPES = {
  // Preimage doesn't have an ASN-encoded fingerprint. The fingerprint contents
  // are just the preimage
  'preimage-sha-256': false,
  'prefix-sha-256': 'PrefixFingerprintContents',
  'threshold-sha-256': 'ThresholdFingerprintContents',
  'rsa-sha-256': 'RsaFingerprintContents',
  'ed25519-sha-256': 'Ed25519FingerprintContents'
}

const SUBTYPES_BITS = {
  'preimage-sha-256': 0,
  'prefix-sha-256': 1,
  'threshold-sha-256': 2,
  'rsa-sha-256': 3,
  'ed25519-sha-256': 4
}

const XML_PREAMBLE = '<?xml version="1.0" encoding="UTF-8"?>\n'
const normalizeXml = xml => XML_PREAMBLE + new xmldoc.XmlDocument(xml).toString()

const formattedHex = (buffer) => {
  return (buffer
    .toString('hex')
    .toUpperCase()
    .match(/.{1,8}/g) || [])
    .join(' ')
}

const getXml = (testCase, type) => {
  const xmlPath = path.resolve(distPath, `valid_${testCase}_${type}.xml`)
  const xml = fs.readFileSync(xmlPath, 'utf-8')
  const xmlDoc = new xmldoc.XmlDocument(xml)

  return xmlDoc.firstChild.toString()
}

const getTemplateProps = (test) => {
  if (test.type === 'preimage-sha-256') {
    return {
      preimage: formattedHex(test.preimage),
      cost: test.cost
    }
  } else if (test.type === 'prefix-sha-256') {
    return {
      prefix: formattedHex(test.prefix),
      maxMessageLength: test.maxMessageLength,
      subcondition: getXml(test.subcondition, 'condition'),
      subfulfillment: getXml(test.subcondition, 'fulfillment'),
      cost: test.cost
    }
  } else if (test.type === 'threshold-sha-256') {
    return {
      threshold: test.threshold,
      subconditionsAll: test.subconditionsAll.map(x => getXml(x, 'condition')),
      subconditions: test.subconditions.map(x => getXml(x, 'condition')),
      subfulfillments: test.subfulfillments.map(x => getXml(x, 'fulfillment')),
      cost: test.cost
    }
  } else if (test.type === 'rsa-sha-256') {
    return {
      modulus: formattedHex(test.modulus),
      signature: formattedHex(test.signature),
      cost: test.cost
    }
  } else if (test.type === 'ed25519-sha-256') {
    return {
      publicKey: formattedHex(test.publicKey),
      signature: formattedHex(test.signature),
      cost: test.cost
    }
  }
}

const getFingerprint = (type, templateProps, preimage) => {
  if (type === 'preimage-sha-256') {
    return {
      der: preimage,
      xml: ''
    }
  } else {
    const xmlFingerprintTemplate = fs.readFileSync(path.resolve(xmlPath, `fingerprint_${type}.xml`), 'utf-8')
    const xmlFingerprint = Mustache.render(xmlFingerprintTemplate, templateProps)

    const fingerprintAsnType = FINGERPRINT_ASN_TYPES[type]
    const fingerprintData = ffasn1dump.xerToDer(xmlFingerprint, fingerprintAsnType)

    return {
      der: fingerprintData,
      xml: normalizeXml(xmlFingerprint)
    }
  }
}

const getFulfillment = (type, templateProps) => {
  const xmlFulfillmentTemplate = fs.readFileSync(path.resolve(xmlPath, `fulfillment_${type}.xml`), 'utf-8')
  const xmlFulfillment = Mustache.render(xmlFulfillmentTemplate, templateProps)

  const fulfillmentData = ffasn1dump.xerToDer(xmlFulfillment, 'Fulfillment')

  return {
    der: fulfillmentData,
    xml: normalizeXml(xmlFulfillment)
  }
}

const getCondition = (type, templateProps, fingerprintContents, subtypes, cost) => {
  const uriConditionPath = path.resolve(uriPath, `condition_${type}.txt`)
  const xmlSrcConditionPath = path.resolve(xmlPath, `condition_${type}.xml`)
  const fingerprint = crypto
    .createHash('sha256')
    .update(fingerprintContents)
    .digest()

  let subtypesBitarrayString = ''
  if (subtypes) {
    const subtypeBits = subtypes.map(x => SUBTYPES_BITS[x])
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
    .replace('{{cost}}', cost)
    .replace('{{subtypes}}', (subtypes || []).join(','))
    .replace(/\n$/, '')

  const conditionData = ffasn1dump.xerToDer(dstConditionXmlData, 'Condition')

  return {
    der: conditionData,
    xml: dstConditionXmlData,
    uri: dstConditionUriData
  }
}

const getAll = (testCaseDefinition) => {
  const templateProps = getTemplateProps(testCaseDefinition)
  const fingerprint = getFingerprint(
    testCaseDefinition.type,
    templateProps,
    testCaseDefinition.preimage
  )
  const fulfillment = getFulfillment(
    testCaseDefinition.type,
    templateProps
  )
  const condition = getCondition(
    testCaseDefinition.type,
    templateProps,
    fingerprint.der,
    testCaseDefinition.subtypes,
    testCaseDefinition.cost
  )

  return {
    fingerprint,
    fulfillment,
    condition
  }
}

module.exports = {
  getTemplateProps,
  getFingerprint,
  getFulfillment,
  getCondition,
  getAll
}
