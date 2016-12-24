'use strict'

const preimage = {
  'type': 'preimage-sha-256',
  'preimage': 'YWFh'
}

const prefix = {
  'type': 'prefix-sha-256',
  'prefix': 'YWFh',
  'maxMessageLength': 0,
  'subcondition': preimage
}

const rsa = {
  'type': 'rsa-sha-256',
  'privateKey': '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA4e+LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdB\nU+Pu89ZmFoQ+DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl/cExIPlnL/f1bPue8gNdA\nxeDwR/PoX8DXWBV3am8/I8XcXnlxOaaILjgzakpfs2E3Yg/zZj264yhHKAGGL3Ly\n+HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04+V99eTgcv\n8s5MZutFIzlzh1J1ljnwJXv1fb1cRD+1FYzOCj02rce6AfM6C7bbsr+YnWBxEvI0\nTZk+d+VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQIDAQABAoIBAAF1UVmYhZpMQt1o\nGJqA19CjMUXZ37bK0rjqk4nV0JlhNTaMkMBg3T73qEsG6XugEwhuG9iNC1NbnXGB\nvVLIW5ie4inc7tSjuWelnrpx8y/RwRa3zPQ6AnMEcQCFNx6bbNzkAO1TLpvxfriX\niZN6y2IpPrriqr/YSILlbRpgPS1V6hLre0wewFyyX6/REtutApRiEe2oiklYvznz\n8Zf4wCvtrv6K1+r0Eeq6VgjcgGgi1xWOI8TXyCwWGAOQ9TKVOSw6/jpo6pELRWYS\npVwsR8U/0L4ZeyYm/w5AGwmQKrlI/uL9vauGKRg55Bj7DjzXOgcRuTuTFZSM/+w/\nz1XpdPECgYEA/ZJGAD61SplbvSsfmI3KxupBnT5c0vxdVpLpc6JXpeHJmnJZvIpN\ndssuTjJlD+LgTb03DSGmVWTpyvAS6L7Xx0OgB0YQbiQHjcLJpbrREv9XAohH1+Al\nW11Cx7ukKpA9tmPM76BBKInhZqfrG0ihfbBBG5i5PNdd97WstjQOdRUCgYEA5BmC\nwVcYdHfIvKj+AE0GNWOM1RGaeJisVF7BQOCBXxmjEUHSqjf+ddDsTODvrSnNTg6P\nLu56Q1fIhx1hY7kYLlnDZBcC192+AvM2QHw8rDJ851ZiruluujhXdZpjRnCO9Mqa\n4d53yXC/Z7G4VSyn15DDylIahyLRueILErr/cxUCgYBVPqdpzasEuSmuHqEwl/pj\nhL0qL5zlERIP2LPCvADbM1yjH24rhBMmrIeUojx3ar4dZE7tizJv4sz1/F9e/0lr\nI8DYsSU04cfoUGOZ44QF7vFBWK9OU3w7is64dsxpwrP8bPCoXieJiVDNQgY31eL0\nbhx1OpKLcZuVeu3lEvsJQQKBgQCAHqAmDtCqopl69oTtEFZ7aHYzO5cDQ+YP4cU0\ntqWUECdayxkUCS2BaZ9As1uMbR1nSaA9ITBFYSo+Uk9gnxeo+TxZnN849tECgS+o\n2t+NbTJhElGNo4pRSNI/OT+n0hNKBf8m/TlVSWIJUXaTSOjhmOuQWbuSygj5GrFT\njPts3QKBgQCnjsKTyZmtRPz0PeJniSsp22njYM7EuE69OtItGxq/N7SA/zxowo3z\nzcAXbOIsnmoLCKGoIB9Cw7wO5OWSkB3fkaT6zUHzxpxBGtlROWtLAsflX0amCp4f\n7CKh5blJ1yGJtNc+Q5qyUbyntoIzFGCibva+xz3UqhJt5Q4TlCy+5Q==\n-----END RSA PRIVATE KEY-----\n',
  'message': 'YWFh',
  'salt': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
}

const ed25519 = {
  'type': 'ed25519-sha-256',
  'privateKey': 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
  'message': 'YWFh'
}

const threshold = {
  'type': 'threshold-sha-256',
  'subfulfillments': [
    prefix,
    ed25519
  ],
  'subconditions': [
    preimage,
    rsa
  ]
}

const thresholdSameMulti = {
  'type': 'threshold-sha-256',
  'subfulfillments': [
    prefix,
    prefix,
    ed25519,
    ed25519
  ],
  'subconditions': [
    rsa,
    rsa
  ]
}

const thresholdTwoLevels = {
  'type': 'threshold-sha-256',
  'subfulfillments': [
    threshold,
    preimage
  ],
  'subconditions': [
    preimage
  ]
}

module.exports = {
  preimage,
  prefix,
  threshold,
  'threshold-same-conditions-multiple-times': thresholdSameMulti,
  'threshold-two-levels-deep': thresholdTwoLevels,
  rsa,
  ed25519
}
