'use strict'

const fs = require('fs')
const path = require('path')

const map = require('lodash/map')
const flatten = require('lodash/flatten')
const padStart = require('lodash/padStart')

const input = require('../src/lib/input')
const output = require('../src/lib/output')

const distPath = path.resolve(__dirname, '../dist')
const outputPath = path.resolve(__dirname, '../test-vectors')

const flattenTests = (tests, prefix = 'test') => {
  if (tests.type) {
    return {
      name: prefix,
      definition: tests
    }
  } else {
    return flatten(map(tests, (subtest, subprefix) => {
      return flattenTests(subtest, prefix + '-' + subprefix)
    }))
  }
}

const tests = flattenTests(require('../src/tests'))
const suite = 'valid'

tests.forEach((test, i) => {
  const index = padStart(String(i), 4, '0')
  console.log(`generating ${suite} test ${index}_${test.name}`)
  const testOutputPath = path.resolve(outputPath, `${suite}/${index}_${test.name}.json`)
  const xmlFingerprintPath = path.resolve(distPath, `${suite}_${index}_${test.name}_fingerprint.xml`)
  const derFingerprintPath = path.resolve(distPath, `${suite}_${index}_${test.name}_fingerprint.der`)
  const xmlFulfillmentPath = path.resolve(distPath, `${suite}_${index}_${test.name}_fulfillment.xml`)
  const derFulfillmentPath = path.resolve(distPath, `${suite}_${index}_${test.name}_fulfillment.der`)
  const xmlConditionPath = path.resolve(distPath, `${suite}_${index}_${test.name}_condition.xml`)
  const derConditionPath = path.resolve(distPath, `${suite}_${index}_${test.name}_condition.der`)

  const testCaseDefinition = input.hydrateTestCaseDefinition(test.definition)
  const testData = output.generateTestVectorJson(testCaseDefinition)

  if (testCaseDefinition.serial.fingerprint.xml) {
    // preimage-sha-256 has no fingerprint, so we'll skip it if it doesn't exist
    fs.writeFileSync(xmlFingerprintPath, testCaseDefinition.serial.fingerprint.xml)
  }
  fs.writeFileSync(derFingerprintPath, testCaseDefinition.serial.fingerprint.der)
  fs.writeFileSync(xmlFulfillmentPath, testCaseDefinition.serial.fulfillment.xml)
  fs.writeFileSync(derFulfillmentPath, testCaseDefinition.serial.fulfillment.der)
  fs.writeFileSync(xmlConditionPath, testCaseDefinition.serial.condition.xml)
  fs.writeFileSync(derConditionPath, testCaseDefinition.serial.condition.der)

  fs.writeFileSync(testOutputPath, JSON.stringify(testData, null, 2))
})
