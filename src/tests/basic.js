'use strict'

const preimage = {
  type: 'preimage-sha-256',
  preimage: 'YWFh'
}

const rsa = {
  type: 'rsa-sha-256',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA4e+LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdB\nU+Pu89ZmFoQ+DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl/cExIPlnL/f1bPue8gNdA\nxeDwR/PoX8DXWBV3am8/I8XcXnlxOaaILjgzakpfs2E3Yg/zZj264yhHKAGGL3Ly\n+HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04+V99eTgcv\n8s5MZutFIzlzh1J1ljnwJXv1fb1cRD+1FYzOCj02rce6AfM6C7bbsr+YnWBxEvI0\nTZk+d+VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQIDAQABAoIBAAF1UVmYhZpMQt1o\nGJqA19CjMUXZ37bK0rjqk4nV0JlhNTaMkMBg3T73qEsG6XugEwhuG9iNC1NbnXGB\nvVLIW5ie4inc7tSjuWelnrpx8y/RwRa3zPQ6AnMEcQCFNx6bbNzkAO1TLpvxfriX\niZN6y2IpPrriqr/YSILlbRpgPS1V6hLre0wewFyyX6/REtutApRiEe2oiklYvznz\n8Zf4wCvtrv6K1+r0Eeq6VgjcgGgi1xWOI8TXyCwWGAOQ9TKVOSw6/jpo6pELRWYS\npVwsR8U/0L4ZeyYm/w5AGwmQKrlI/uL9vauGKRg55Bj7DjzXOgcRuTuTFZSM/+w/\nz1XpdPECgYEA/ZJGAD61SplbvSsfmI3KxupBnT5c0vxdVpLpc6JXpeHJmnJZvIpN\ndssuTjJlD+LgTb03DSGmVWTpyvAS6L7Xx0OgB0YQbiQHjcLJpbrREv9XAohH1+Al\nW11Cx7ukKpA9tmPM76BBKInhZqfrG0ihfbBBG5i5PNdd97WstjQOdRUCgYEA5BmC\nwVcYdHfIvKj+AE0GNWOM1RGaeJisVF7BQOCBXxmjEUHSqjf+ddDsTODvrSnNTg6P\nLu56Q1fIhx1hY7kYLlnDZBcC192+AvM2QHw8rDJ851ZiruluujhXdZpjRnCO9Mqa\n4d53yXC/Z7G4VSyn15DDylIahyLRueILErr/cxUCgYBVPqdpzasEuSmuHqEwl/pj\nhL0qL5zlERIP2LPCvADbM1yjH24rhBMmrIeUojx3ar4dZE7tizJv4sz1/F9e/0lr\nI8DYsSU04cfoUGOZ44QF7vFBWK9OU3w7is64dsxpwrP8bPCoXieJiVDNQgY31eL0\nbhx1OpKLcZuVeu3lEvsJQQKBgQCAHqAmDtCqopl69oTtEFZ7aHYzO5cDQ+YP4cU0\ntqWUECdayxkUCS2BaZ9As1uMbR1nSaA9ITBFYSo+Uk9gnxeo+TxZnN849tECgS+o\n2t+NbTJhElGNo4pRSNI/OT+n0hNKBf8m/TlVSWIJUXaTSOjhmOuQWbuSygj5GrFT\njPts3QKBgQCnjsKTyZmtRPz0PeJniSsp22njYM7EuE69OtItGxq/N7SA/zxowo3z\nzcAXbOIsnmoLCKGoIB9Cw7wO5OWSkB3fkaT6zUHzxpxBGtlROWtLAsflX0amCp4f\n7CKh5blJ1yGJtNc+Q5qyUbyntoIzFGCibva+xz3UqhJt5Q4TlCy+5Q==\n-----END RSA PRIVATE KEY-----\n',
  message: 'YWFh',
  salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
}

const rsa4096 = {
  type: 'rsa-sha-256',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n',
  message: 'YWFh',
  salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
}

const ed25519 = {
  type: 'ed25519-sha-256',
  privateKey: 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
  message: 'YWFh'
}

const prefix = {
  type: 'prefix-sha-256',
  prefix: 'YWFh',
  maxMessageLength: 0,
  subcondition: ed25519
}

const prefixTwoLevels = {
  type: 'prefix-sha-256',
  prefix: 'YmJi',
  maxMessageLength: 3,
  message: 'enp6',
  subcondition: {
    type: 'prefix-sha-256',
    prefix: 'YWFh',
    maxMessageLength: 6,
    subcondition: ed25519
  }
}

const threshold = {
  type: 'threshold-sha-256',
  subfulfillments: [
    prefix,
    ed25519
  ],
  subconditions: [
    rsa4096
  ],
  message: 'YWFh'
}

const thresholdSameConditionTwice = {
  type: 'threshold-sha-256',
  subfulfillments: [
    preimage
  ],
  subconditions: [
    // Interleaving helps test the implementation's sorting
    prefix,
    rsa4096,
    prefix,
    rsa4096
  ]
}

const thresholdSameFulfillmentTwice = {
  type: 'threshold-sha-256',
  subfulfillments: [
    // Interleaving helps test the implementation's sorting
    prefix,
    ed25519,
    prefix,
    ed25519
  ]
}

const thresholdTwoLevels = {
  type: 'threshold-sha-256',
  subfulfillments: [
    threshold,
    preimage
  ]
}

// Threshold containing a subcondition that is simultaneously fulfilled and
// unfulfilled.
const thresholdSchroedingersFulfillment = {
  type: 'threshold-sha-256',
  subfulfillments: [
    preimage
  ],
  subconditions: [
    preimage
  ]
}

module.exports = {
  preimage,
  prefix,
  'prefix-two-levels-deep': prefixTwoLevels,
  threshold,
  'threshold-same-condition-twice': thresholdSameConditionTwice,
  'threshold-same-fulfillment-twice': thresholdSameFulfillmentTwice,
  'threshold-two-levels-deep': thresholdTwoLevels,
  'threshold-schroedinger': thresholdSchroedingersFulfillment,
  rsa,
  rsa4096,
  ed25519
}
