'use strict'

const notarizedReceipt = {
  type: 'threshold-sha-256',
  subfulfillments: [{
    type: 'prefix-sha-256',
    prefix: 'aHR0cHM6Ly9ub3RhcnkuZXhhbXBsZS9jYXNlcy82NTdjMTJkYS04ZGNhLTQzYjAtOTdjYS04ZWU4YzM4YWI5Zjcvc3RhdGUvZXhlY3V0ZWQ',
    maxMessageLength: 0,
    subcondition: {
      type: 'ed25519-sha-256',
      privateKey: 'R1XHG3XPwkreVK4WN4MI1TfS7xFFPyXvu9OuSgqdoQA'
    }
  }, {
    type: 'preimage-sha-256',
    preimage: 'aHR0cHM6Ly9ub3RhcnkuZXhhbXBsZS9jYXNlcy82NTdjMTJkYS04ZGNhLTQzYjAtOTdjYS04ZWU4YzM4YWI5Zjcvc3RhdGUvZXhlY3V0ZWQ'
  }]
}

const notarizedReceiptMulti = {
  type: 'threshold-sha-256',
  subfulfillments: [{
    type: 'prefix-sha-256',
    prefix: 'Y2FzZXMvNjU3YzEyZGEtOGRjYS00M2IwLTk3Y2EtOGVlOGMzOGFiOWY3L3N0YXRlL2V4ZWN1dGVk',
    maxMessageLength: 0,
    subcondition: {
      type: 'threshold-sha-256',
      subfulfillments: [{
        type: 'prefix-sha-256',
        prefix: 'aHR0cHM6Ly9ub3RhcnkxLmV4YW1wbGUv',
        maxMessageLength: 1024,
        subcondition: {
          type: 'ed25519-sha-256',
          privateKey: 'R1XHG3XPwkreVK4WN4MI1TfS7xFFPyXvu9OuSgqdoQA'
        }
      }, {
        type: 'prefix-sha-256',
        prefix: 'aHR0cHM6Ly9ub3RhcnkyLmV4YW1wbGUv',
        maxMessageLength: 1024,
        subcondition: {
          type: 'ed25519-sha-256',
          privateKey: '2bw8IyjNJWLzc82ojgvmklhioZj7aOP4Np4RtxtY3iU'
        }
      }, {
        type: 'prefix-sha-256',
        prefix: 'aHR0cHM6Ly9ub3RhcnkzLmV4YW1wbGUv',
        maxMessageLength: 1024,
        subcondition: {
          type: 'ed25519-sha-256',
          privateKey: 'GYTe22etYCEYLRxkbfDMF2QMBF-JZSihkKaQKOEBl38'
        }
      }],
      subconditions: [{
        type: 'prefix-sha-256',
        prefix: 'aHR0cHM6Ly9ub3Rhcnk0LmV4YW1wbGUv',
        // Using a higher message length for this one. This is a little dirty
        // trick to ensure that implementations will choose this as the
        // unfulfilled condition. Can be removed if/when the testsuite generator
        // is changed to provide unfulfilled conditions as unfulfilled in the
        // JSON output.
        maxMessageLength: 1025,
        subcondition: {
          type: 'ed25519-sha-256',
          privateKey: 'yBDoqIFXfdrmRrRMF9bwKsJ6NRwMpA0iTJNYx7mMilA'
        }
      }]
    }
  }, {
    type: 'preimage-sha-256',
    preimage: 'aHR0cHM6Ly9ub3RhcnkuZXhhbXBsZS9jYXNlcy82NTdjMTJkYS04ZGNhLTQzYjAtOTdjYS04ZWU4YzM4YWI5Zjcvc3RhdGUvZXhlY3V0ZWQ'
  }]
}

module.exports = {
  'notarized-receipt': notarizedReceipt,
  'notarized-receipt-multiple-notaries': notarizedReceiptMulti
}
