'use strict'

const fs = require('fs')
const path = require('path')
const tmp = require('tmp')
const execSync = require('child_process').execSync
const asnPath = path.resolve(__dirname, '../asn1/CryptoConditions.asn')

exports.xerToDer = (inputString, type) => {
  const inputFile = tmp.tmpNameSync()
  const outputFile = tmp.tmpNameSync()
  fs.writeFileSync(inputFile, inputString, 'utf-8')

  execSync(
    `ffasn1dump -I xer -O der ${asnPath} ${type} ` +
    `${inputFile} ${outputFile}`
  )

  const outputString = fs.readFileSync(outputFile)

  fs.unlinkSync(inputFile)
  fs.unlinkSync(outputFile)

  return outputString
}
