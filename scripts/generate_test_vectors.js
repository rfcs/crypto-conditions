'use strict'

const fs = require('fs')
const path = require('path')

const serializer = require('../src/lib/serializer')
const input = require('../src/lib/input')
const output = require('../src/lib/output')

const jsonPath = path.resolve(__dirname, '../src/json')

const distPath = path.resolve(__dirname, '../dist')
const outputPath = path.resolve(__dirname, '../test-vectors')

const suite = 'valid'
const suitePath = path.resolve(jsonPath, suite)

for (let testCase of fs.readdirSync(suitePath)) {
  const testName = testCase.replace(/\.json$/, '')
  const testPath = path.resolve(suitePath, testCase)
  const testOutputPath = path.resolve(outputPath, `${suite}/${testCase}`)
  const xmlFingerprintPath = path.resolve(distPath, `${suite}_${testName}_fingerprint.xml`)
  const derFingerprintPath = path.resolve(distPath, `${suite}_${testName}_fingerprint.der`)
  const xmlFulfillmentPath = path.resolve(distPath, `${suite}_${testName}_fulfillment.xml`)
  const derFulfillmentPath = path.resolve(distPath, `${suite}_${testName}_fulfillment.der`)
  const xmlConditionPath = path.resolve(distPath, `${suite}_${testName}_condition.xml`)
  const derConditionPath = path.resolve(distPath, `${suite}_${testName}_condition.der`)

  const testCaseDefinition = input.hydrateTestCaseDefinition(require(testPath))
  const serial = serializer.getAll(testCaseDefinition)
  const testData = output.generateTestVectorJson(testCaseDefinition, serial)

  if (serial.fingerprint.xml) {
    // preimage-sha-256 has no fingerprint, so we'll skip it if it doesn't exist
    fs.writeFileSync(xmlFingerprintPath, serial.fingerprint.xml)
  }
  fs.writeFileSync(derFingerprintPath, serial.fingerprint.der)
  fs.writeFileSync(xmlFulfillmentPath, serial.fulfillment.xml)
  fs.writeFileSync(derFulfillmentPath, serial.fulfillment.der)
  fs.writeFileSync(xmlConditionPath, serial.condition.xml)
  fs.writeFileSync(derConditionPath, serial.condition.der)

  fs.writeFileSync(testOutputPath, JSON.stringify(testData, null, 2))
}
