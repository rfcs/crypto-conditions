# Crypto-Conditions

## Spec

You can find the spec here: https://tools.ietf.org/html/draft-thomas-crypto-conditions-02

## Implementations

Known implementations of Crypto Conditions:

* JavaScript: https://github.com/interledgerjs/five-bells-condition
* Java: https://github.com/interledger/java-crypto-conditions
* Python: https://github.com/bigchaindb/cryptoconditions
* Go: https://github.com/jtremback/crypto-conditions

(Note that all of the above implementations currently need testing/updating. As soon as we have run a decent sized test suite against the implementations above, we'll provide the results here.)

If you would like to update this list, please feel free to open a pull request against this repository.

## Test Vectors

In order to verify the different implementations, we provide a series of test vectors in JSON format. You can find them in the folder `test-vectors`. Within that folder, they are organized in the following subfolders:

* `valid` - These are examples of valid crypto-conditions and their fulfillments. You should run the following tests against these:

  * Parse `conditionBinary`, serialize as a URI, should match `conditionUri`.
  * Parse `conditionUri`, serialize as binary, should match `conditionBinary`.
  * Parse `fulfillment`, serialize fulfillment, should match `fulfillment`.
  * Parse `fulfillment` and validate, should return true.
  * Parse `fulfillment` and generate the fingerprint contents
  * Parse `fulfillment`, generate the condition, serialize the condition as a URI, should match `conditionUri`.
  * Create fulfillment from `json`, serialize fulfillment, should match `fulfillment`.

  If a `message` field is provided, the condition should be evaluated against the message. Otherwise, an empty message should be passed to the verification function.

* `invalid` - These are examples of intrinsically invalid fulfillments, such as an invalid signature or an encoding error.
  * Parse `fulfillment` and validate, should return error.

Note that we don't provide any test cases for fulfillments that are valid, but don't match the provided condition, because we can just include them in the `valid` set, which provides the exact condition that the fulfillment *should* map to. (Which is stricter than testing one of the nearly infinite possible conditions that it doesn't map to.)

## Test Vectors Source

The test vectors themselves are generated from example data in the `src/test-vectors/` folder. You should never have to worry about that unless you are adding or editing test vectors.

## Generating Tests

The ffasn1dump tool is used to produce DER encodings. It is available from http://bellard.org/ffasn1
